package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	u "github.com/Quiq/webauthn_proxy/user"
	util "github.com/Quiq/webauthn_proxy/util"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"

	yaml "gopkg.in/yaml.v3"
)

var (
	webAuthn             *webauthn.WebAuthn
	webauthnSessionStore *session.Store
	configuration        Configuration
	users                map[string]u.User
	registrations        map[string]u.User
	sessionStoreKey      []byte
	sessionStore         *sessions.CookieStore
)

type Configuration struct {
	CredentialFile string

	EnableFullRegistration bool

	RPDisplayName string // Relying party display name
	RPOrigin      string // Relying party origin

	ServerAddress        string
	ServerPort           string
	SessionLengthSeconds int
	StaticPath           string

	UsernameRegex string
}

type RegistrationSuccess struct {
	Message string
	Data    string
}

type AuthenticationSuccess struct {
	Message string
}

type AuthenticationFailure struct {
	Message string
}

type WebAuthnError struct {
	Message string
}

type Credentials map[string]string
type WebAuthnCredentials map[string]webauthn.Credential

func main() {
	var err error
	var credfile []byte
	var credentials map[string]string

	rand.Seed(time.Now().UnixNano())

	users = make(map[string]u.User)
	registrations = make(map[string]u.User)

	viper.SetDefault("configpath", "/opt/webauthn_proxy")
	viper.SetDefault("enablefullregistration", false)
	viper.SetEnvPrefix("webauthn_proxy")
	viper.BindEnv("configpath")

	viper.SetConfigName("config")
	viper.SetConfigType("yml")

	configpath := viper.GetString("configpath")
	log.Printf("Reading config file, %s/config.yml", configpath)
	viper.AddConfigPath(configpath)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("\nError reading config file %s/config.yml. %s", configpath, err.Error())
	}

	if err = viper.Unmarshal(&configuration); err != nil {
		log.Fatalln("Unable to decode config file into struct.", err)
	}

	// Parse out the origin host to use as Relying party ID
	originUrl, err := url.Parse(configuration.RPOrigin)
	if err != nil {
		log.Fatalln("Failed parsing RP origin: ", err)
	}
	rpID := originUrl.Host
	if strings.Contains(rpID, ":") {
		rpID, _, _ = net.SplitHostPort(rpID)
	}

	fmt.Printf("\nCredential File: %s", configuration.CredentialFile)
	fmt.Printf("\nRelying Party Display Name: %s", configuration.RPDisplayName)
	fmt.Printf("\nRelying Party ID: %s", rpID)
	fmt.Printf("\nRelying Party Origin: %s", configuration.RPOrigin)
	fmt.Printf("\nEnable Full Registration: %v", configuration.EnableFullRegistration)
	fmt.Printf("\nServer Address: %s", configuration.ServerAddress)
	fmt.Printf("\nServer Port: %s", configuration.ServerPort)
	fmt.Printf("\nSession Length: %d", configuration.SessionLengthSeconds)
	fmt.Printf("\nStatic Path: %s", configuration.StaticPath)
	fmt.Printf("\nUsername Regex: %s\n\n", configuration.UsernameRegex)

	if credfile, err = ioutil.ReadFile(configuration.CredentialFile); err != nil {
		log.Fatalf("\nUnable to read credential file %s %v", configuration.CredentialFile, err)
	}

	if err = yaml.Unmarshal(credfile, &credentials); err != nil {
		log.Fatalf("\nUnable to parse YAML credential file %s %v", configuration.CredentialFile, err)
	}

	// Unmarshall credentials map to users
	for username, credential := range credentials {
		unmarshaledUser, err := u.UnmarshalUser(credential)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error unmarshalling user credential %s", username), err)
		}

		users[username] = *unmarshaledUser
	}

	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: configuration.RPDisplayName, // Relying party display name
		RPID:          rpID,                        // Relying party ID
		RPOrigin:      configuration.RPOrigin,      // Relying party origin
	})

	if err != nil {
		log.Fatalln("Failed to create WebAuthn from config:", err)
	}

	webauthnSessionStore, err = session.NewStore()
	if err != nil {
		log.Fatalln("Failed to create Webauthn session store:", err)
	}

	sessionStoreKey = util.RandStringBytesRmndr(32)
	sessionStore = sessions.NewCookieStore(sessionStoreKey)

	// Sessions stored for a configurable length of time
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   configuration.SessionLengthSeconds,
		HttpOnly: true,
	}

	r := http.NewServeMux()

	r.HandleFunc("/webauthn/auth", GetUserAuth)
	r.HandleFunc("/webauthn/login", HandleLogin)
	r.HandleFunc("/webauthn/register", HandleRegister)
	r.HandleFunc("/webauthn/login/get_credential_request_options", GetCredentialRequestOptions)
	r.HandleFunc("/webauthn/login/process_login_assertion", ProcessLoginAssertion)
	r.HandleFunc("/webauthn/register/get_credential_creation_options", GetCredentialCreationOptions)
	r.HandleFunc("/webauthn/register/process_registration_attestation", ProcessRegistrationAttestation)

	// All remaining references to static assets. Add /webauthn_static/ for embedding.
	r.Handle("/webauthn_static/", http.StripPrefix("/webauthn_static/", http.FileServer(http.Dir(configuration.StaticPath))))
	r.Handle("/", http.FileServer(http.Dir(configuration.StaticPath)))

	serverAddress := fmt.Sprintf("%s:%s", configuration.ServerAddress, configuration.ServerPort)
	log.Println("Starting server at", serverAddress)
	log.Fatalln(http.ListenAndServe(serverAddress, r))
}

func GetUserAuth(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "webauthn-proxy-session")

	// Check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		util.JSONResponse(w, AuthenticationFailure{Message: "Unauthenticated"}, http.StatusUnauthorized)
		return
	} else {
		util.JSONResponse(w, AuthenticationSuccess{Message: "OK"}, http.StatusOK)
		return
	}
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "webauthn-proxy-session")
	redirectUrl := util.GetRedirectUrl(r, "/webauthn_static/authenticated.html")

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, redirectUrl, http.StatusFound)
	} else {
		http.ServeFile(w, r, filepath.Join(configuration.StaticPath, "login.html"))
	}

	return
}

func HandleRegister(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(configuration.StaticPath, "register.html"))
	return
}

// Step 1 of the login process, get credential request options for the user
func GetCredentialRequestOptions(w http.ResponseWriter, r *http.Request) {
	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	user, exists := users[username]
	if !exists {
		log.Printf("\nUser %s does not exist", username)
		util.JSONResponse(w, WebAuthnError{Message: fmt.Sprintf("User %s does not exist", username)}, http.StatusBadRequest)
		return
	}

	// Begin the login process
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println("Error beginning the login process", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	// Store session data as marshaled JSON
	err = webauthnSessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println("Error saving Webauthn session during login", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, options, http.StatusOK)
	return
}

// Step 2 of the login process, process the assertion from the client authenticator
func ProcessLoginAssertion(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "webauthn-proxy-session")
	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	user, exists := users[username]
	if !exists {
		log.Printf("\nUser %s does not exist", username)
		util.JSONResponse(w, WebAuthnError{Message: fmt.Sprintf("User %s does not exist", username)}, http.StatusBadRequest)
		return
	}

	// Load the session data
	sessionData, err := webauthnSessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println("Error getting Webauthn session during login", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println("Error finishing Webauthn login", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	// TODO: Perform additional validation of the login assertion

	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Save(r, w)

	successMessage := AuthenticationSuccess{
		Message: "Authentication Successful",
	}
	util.JSONResponse(w, successMessage, http.StatusOK)
	return
}

// Step 1 of the registration process, get credential creation options
func GetCredentialCreationOptions(w http.ResponseWriter, r *http.Request) {
	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	if _, exists := users[username]; exists {
		util.JSONResponse(w, WebAuthnError{Message: fmt.Sprintf("User %s is already registered", username)}, http.StatusBadRequest)
		return
	} else if _, exists = registrations[username]; exists {
		util.JSONResponse(w, WebAuthnError{Message: fmt.Sprintf("User %s has already begun registration", username)}, http.StatusBadRequest)
		return
	}

	user := u.NewUser(username)
	registrations[username] = *user

	// Generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		user,
	)

	if err != nil {
		log.Println("Error beginning Webauthn registration", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	// Store session data as marshaled JSON
	if err = webauthnSessionStore.SaveWebauthnSession("registration", sessionData, r, w); err != nil {
		log.Println("Error saving Webauthn session during registration", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, options, http.StatusOK)
	return
}

// Step 2 of the registration process, process the attestation (new credential) from the client authenticator
func ProcessRegistrationAttestation(w http.ResponseWriter, r *http.Request) {
	var user u.User
	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	if _, exists := users[username]; exists {
		log.Printf("\nUser %s is already registered", username)
		util.JSONResponse(w, WebAuthnError{Message: fmt.Sprintf("User %s is already registered", username)}, http.StatusBadRequest)
		return
	} else if user, exists = registrations[username]; !exists {
		log.Printf("\nUser %s has not begun registration", username)
		util.JSONResponse(w, WebAuthnError{Message: fmt.Sprintf("User %s has not begun registration", username)}, http.StatusBadRequest)
		return
	}

	// Load the session data
	sessionData, err := webauthnSessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Println("Error getting Webauthn session during registration", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		log.Println("Error finishing Webauthn registration", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	// Note: enabling this can be risky as it allows anyone to add themselves to the proxy.
	// Only enable full registration if the registration page is secure (e.g. behind
	// some other form of authentication)
	if configuration.EnableFullRegistration {
		users[username] = user
	}

	marshaledUser, err := u.MarshalUser(user)
	if err != nil {
		log.Println("Error marshalling user object", err)
		util.JSONResponse(w, WebAuthnError{Message: err.Error()}, http.StatusBadRequest)
		return
	}

	// TODO: Perform additional validation of the registration attestation

	successMessage := RegistrationSuccess{
		Message: "Registration Successful. Please share the values below with your system administrator so they can add you to the credential file:",
		Data:    fmt.Sprintf("%s: %s", username, marshaledUser),
	}
	util.JSONResponse(w, successMessage, http.StatusOK)
	return
}
