package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	u "github.com/Quiq/webauthn_proxy/user"
	util "github.com/Quiq/webauthn_proxy/util"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/sessions"

	"github.com/spf13/viper"

	yaml "gopkg.in/yaml.v3"
)

var (
	configuration     Configuration
	loginError        WebAuthnError
	registrationError WebAuthnError
	registrations     map[string]u.User
	users             map[string]u.User
	dynamicOrigins    bool
	webAuthns         map[string]*webauthn.WebAuthn
	sessionStores     map[string]*sessions.CookieStore
)

type Configuration struct {
	CredentialFile string

	TestMode bool

	RPDisplayName string   // Relying party display name
	RPID          string   // Relying party ID
	RPOrigins     []string // Relying party origin

	ServerAddress             string
	ServerPort                string
	SessionSoftTimeoutSeconds int
	SessionHardTimeoutSeconds int
	StaticPath                string

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

const SessionKey = "webauthn-proxy-session"

func main() {
	var err error
	var credfile []byte
	var credentials map[string]string

	loginError = WebAuthnError{Message: "Unable to login"}
	registrationError = WebAuthnError{Message: "Error during registration"}

	rand.Seed(time.Now().UnixNano())

	users = make(map[string]u.User)
	registrations = make(map[string]u.User)
	webAuthns = make(map[string]*webauthn.WebAuthn)
	sessionStores = make(map[string]*sessions.CookieStore)

	viper.SetDefault("configpath", "/opt/webauthn_proxy")
	viper.SetEnvPrefix("webauthn_proxy")
	viper.BindEnv("configpath")
	viper.SetConfigName("config")
	viper.SetConfigType("yml")

	// Set configuration defaults
	viper.SetDefault("credentialfile", "/opt/webauthn_proxy/credentials.yml")
	viper.SetDefault("testmode", false)
	viper.SetDefault("rporigins", []string{})
	viper.SetDefault("serveraddress", "127.0.0.1")
	viper.SetDefault("serverport", "8080")
	viper.SetDefault("sessionsofttimeoutseconds", 28800)
	viper.SetDefault("sessionhardtimeoutseconds", 86400)
	viper.SetDefault("staticpath", "/static/")
	viper.SetDefault("usernameregex", "^.*$")

	// Read in configuration file
	configpath := viper.GetString("configpath")
	log.Printf("Reading config file, %s/config.yml", configpath)
	viper.AddConfigPath(configpath)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file %s/config.yml. %s", configpath, err.Error())
	}

	if err = viper.Unmarshal(&configuration); err != nil {
		log.Fatalln("Unable to decode config file into struct.", err)
	}

	// Ensure that session soft timeout <= hard timeout
	if configuration.SessionSoftTimeoutSeconds < 1 {
		log.Fatalf("Invalid session soft timeout of %d, must be > 0", configuration.SessionSoftTimeoutSeconds)
	} else if configuration.SessionHardTimeoutSeconds < 1 {
		log.Fatalf("Invalid session hard timeout of %d, must be > 0", configuration.SessionHardTimeoutSeconds)
	} else if configuration.SessionHardTimeoutSeconds < configuration.SessionSoftTimeoutSeconds {
		log.Fatalln("Invalid session hard timeout, must be > session soft timeout")
	}

	fmt.Printf("\nCredential File: %s", configuration.CredentialFile)
	fmt.Printf("\nRelying Party Display Name: %s", configuration.RPDisplayName)
	fmt.Printf("\nRelying Party ID: %s", configuration.RPID)
	fmt.Printf("\nRelying Party Origins: %v", configuration.RPOrigins)
	fmt.Printf("\nServer Address: %s", configuration.ServerAddress)
	fmt.Printf("\nServer Port: %s", configuration.ServerPort)
	fmt.Printf("\nSession Soft Timeout: %d", configuration.SessionSoftTimeoutSeconds)
	fmt.Printf("\nSession Hard Tiemout: %d", configuration.SessionHardTimeoutSeconds)
	fmt.Printf("\nStatic Path: %s", configuration.StaticPath)
	fmt.Printf("\nTest Mode: %v", configuration.TestMode)
	fmt.Printf("\nUsername Regex: %s", configuration.UsernameRegex)

	if configuration.TestMode {
		fmt.Printf("\n\nWarning!!! Test Mode enabled! This is not safe for production!\n\n")
	}

	// Read in credentials file
	if credfile, err = ioutil.ReadFile(configuration.CredentialFile); err != nil {
		log.Fatalf("Unable to read credential file %s %v", configuration.CredentialFile, err)
	}

	if err = yaml.Unmarshal(credfile, &credentials); err != nil {
		log.Fatalf("Unable to parse YAML credential file %s %v", configuration.CredentialFile, err)
	}

	// Unmarshall credentials map to users
	for username, credential := range credentials {
		unmarshaledUser, err := u.UnmarshalUser(credential)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error unmarshalling user credential %s", username), err)
		}

		users[username] = *unmarshaledUser
	}

	/*
	  If list of relying party origins has been specified in configuration,
	  create one Webauthn config / Session store per origin, else origins
	  will be dynamic
	*/
	if len(configuration.RPOrigins) > 0 {
		dynamicOrigins = false
		for _, rpOrigin := range configuration.RPOrigins {
			var webAuthn *webauthn.WebAuthn
			webAuthn, err = webauthn.New(&webauthn.Config{
				RPDisplayName: configuration.RPDisplayName,
				RPID:          configuration.RPID,
				RPOrigin:      rpOrigin,
			})

			if err != nil {
				log.Fatalln("Failed to create WebAuthn from config:", err)
			}
			webAuthns[rpOrigin] = webAuthn

			var sessionStoreKey = util.RandStringBytesRmndr(32)
			var sessionStore = sessions.NewCookieStore(sessionStoreKey)
			// Sessions maintained for up to soft timeout limit
			sessionStore.Options = &sessions.Options{
				Path:     "/",
				MaxAge:   configuration.SessionSoftTimeoutSeconds,
				HttpOnly: true,
			}
			sessionStores[rpOrigin] = sessionStore
		}
	} else {
		dynamicOrigins = true
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

// /webauthn/auth - Check if user has an authenticated session
func GetUserAuth(w http.ResponseWriter, r *http.Request) {
	_, sessionStore, err := checkOrigin(r)
	if err != nil {
		log.Println("Error validating origin", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	session, _ := sessionStore.Get(r, SessionKey)
	if err != nil {
		log.Println("Error getting session from session store during user auth handler", err)
		util.JSONResponse(w, AuthenticationFailure{Message: "Unauthenticated"}, http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		util.JSONResponse(w, AuthenticationFailure{Message: "Unauthenticated"}, http.StatusUnauthorized)
		return
	} else if time.Now().Unix()-session.Values["authenticationtime"].(int64) >= int64(configuration.SessionHardTimeoutSeconds) {
		// Invalidate the session, session has exceeded the hard limit
		session.Options = &sessions.Options{
			MaxAge: -1,
		}
		session.Save(r, w)
		util.JSONResponse(w, AuthenticationFailure{Message: "Unauthenticated"}, http.StatusUnauthorized)
		return
	} else {
		// Update the session to reset the soft timeout
		session.Save(r, w)

		util.JSONResponse(w, AuthenticationSuccess{Message: "OK"}, http.StatusOK)
		return
	}
}

// /webauthn/login - Redirect to URL if authenticated, else serve up login page
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	_, sessionStore, err := checkOrigin(r)
	if err != nil {
		log.Println("Error validating origin", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	session, _ := sessionStore.Get(r, SessionKey)
	if err != nil {
		log.Println("Error getting session from session store during login handler", err)
		util.JSONResponse(w, AuthenticationFailure{Message: "Unauthenticated"}, http.StatusInternalServerError)
		return
	}

	redirectUrl := util.GetRedirectUrl(r, "/webauthn_static/authenticated.html")

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, redirectUrl, http.StatusFound)
	} else {
		http.ServeFile(w, r, filepath.Join(configuration.StaticPath, "login.html"))
	}

	return
}

// /webauthn/register - Serve up registration page
func HandleRegister(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(configuration.StaticPath, "register.html"))
	return
}

/*
  /webauthn/login/get_credential_request_options -
  Step 1 of the login process, get credential request options for the user
*/
func GetCredentialRequestOptions(w http.ResponseWriter, r *http.Request) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		log.Println("Error validating origin", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		log.Println("Error getting username", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	user, exists := users[username]
	if !exists {
		log.Printf("User %s does not exist", username)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Begin the login process
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println("Error beginning the login process", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Store Webauthn session data
	session, _ := sessionStore.Get(r, SessionKey)
	if err != nil {
		log.Println("Error getting session from session store during login", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	err = util.SaveWebauthnSession(session, "authentication", sessionData, r, w)
	if err != nil {
		log.Println("Error saving Webauthn session during login", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, options, http.StatusOK)
	return
}

/*
   /webauthn/login/process_login_assertion -
   Step 2 of the login process, process the assertion from the client authenticator
*/
func ProcessLoginAssertion(w http.ResponseWriter, r *http.Request) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		log.Println("Error validating origin", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		log.Println("Error getting username", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	user, exists := users[username]
	if !exists {
		log.Printf("User %s does not exist", username)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Load the session data
	session, _ := sessionStore.Get(r, SessionKey)
	if err != nil {
		log.Println("Error getting session from session store during login", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	sessionData, err := util.FetchWebauthnSession(session, "authentication", r)
	if err != nil {
		log.Println("Error getting Webauthn session during login", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	cred, err := webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println("Error finishing Webauthn login", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Check for cloned authenticators
	if cred.Authenticator.CloneWarning {
		log.Printf("Error. Authenticator for %s appears to be cloned, failing login", username)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Increment sign counter on user to help avoid clones
	if userCredential, err := user.CredentialById(cred.ID); err != nil {
		log.Println("Error incrementing sign counter on user authenticator", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	} else {
		userCredential.Authenticator.UpdateCounter(cred.Authenticator.SignCount)
	}

	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Values["authenticationtime"] = time.Now().Unix()
	session.Save(r, w)

	successMessage := AuthenticationSuccess{
		Message: "Authentication Successful",
	}
	util.JSONResponse(w, successMessage, http.StatusOK)
	return
}

/*
  /webauthn/register/get_credential_creation_options -
  Step 1 of the registration process, get credential creation options
*/
func GetCredentialCreationOptions(w http.ResponseWriter, r *http.Request) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		log.Println("Error validating origin", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		log.Println("Error getting username", err)
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	// We allow a user to register multiple time with different authenticators.
	// First check if they are an existing user
	user, exists := users[username]
	if !exists {
		// Not found, see if they have registered previously
		if user, exists = registrations[username]; !exists {
			// Create a new user
			user = *u.NewUser(username)
			registrations[username] = user
		}
	}

	// Generate PublicKeyCredentialCreationOptions, session data}
	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		user.UserRegistrationOptions,
	)

	if err != nil {
		log.Println("Error beginning Webauthn registration", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	// Store session data as marshaled JSON
	session, _ := sessionStore.Get(r, SessionKey)
	if err != nil {
		log.Println("Error getting session from session store during registration", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	if err = util.SaveWebauthnSession(session, "registration", sessionData, r, w); err != nil {
		log.Println("Error saving Webauthn session during registration", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, options, http.StatusOK)
	return
}

/*
  /webauthn/register/process_registration_attestation -
  Step 2 of the registration process, process the attestation (new credential) from the client authenticator
*/
func ProcessRegistrationAttestation(w http.ResponseWriter, r *http.Request) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		log.Println("Error validating origin", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		log.Println("Error getting username", err)
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	// First check if they are an existing user
	user, exists := users[username]
	if !exists {
		// Not found, check the registrants pool
		if user, exists = registrations[username]; !exists {
			// Somethings wrong here. We made it here without the registrant going
			// through GetCredentialCreationOptions. Fail this request.
			log.Printf("Registrant %s skipped GetCredentialCreationOptions step, failing registration", username)
			util.JSONResponse(w, registrationError, http.StatusBadRequest)
			return
		}
	}

	// Load the session data
	session, err := sessionStore.Get(r, SessionKey)
	if err != nil {
		log.Println("Error getting session from session store during registration", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	sessionData, err := util.FetchWebauthnSession(session, "registration", r)
	if err != nil {
		log.Println("Error getting Webauthn session during registration", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		log.Println("Error finishing Webauthn registration", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	// Check that the credential doesn't belong to another user or registrant
	for _, u := range users {
		for _, c := range u.Credentials {
			if bytes.Compare(c.ID, credential.ID) == 0 {
				log.Printf("Error registering credential for user %s, matching credential ID with user %s", username, u.Name)
				util.JSONResponse(w, registrationError, http.StatusBadRequest)
				return
			}
		}
	}
	for _, r := range registrations {
		for _, c := range r.Credentials {
			if bytes.Compare(c.ID, credential.ID) == 0 {
				log.Printf("Error registering credential for user %s, matching credential ID with registrant %s", username, r.Name)
				util.JSONResponse(w, registrationError, http.StatusBadRequest)
				return
			}
		}
	}

	// Add the credential to the user
	user.AddCredential(*credential)

	// Note: enabling this can be risky as it allows anyone to add themselves to the proxy.
	// Only enable test mode during testing!
	if configuration.TestMode {
		users[username] = user
		delete(registrations, username)
	}

	// Marshal the user so it can be added to the credentials file
	marshaledUser, err := user.Marshal()
	if err != nil {
		log.Println("Error marshalling user object", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	successMessage := RegistrationSuccess{
		Message: "Registration Successful. Please share the values below with your system administrator so they can add you to the credential file:",
		Data:    fmt.Sprintf("%s: %s", username, marshaledUser),
	}
	util.JSONResponse(w, successMessage, http.StatusOK)
	return
}

// Check that the origin is in our configuration or we're allowing dynamic origins
func checkOrigin(r *http.Request) (*webauthn.WebAuthn, *sessions.CookieStore, error) {
	var webAuthn *webauthn.WebAuthn
	u, err := url.Parse(r.URL.RequestURI())
	if err != nil {
		return nil, nil, fmt.Errorf("RPOrigin not valid URL: %+v", err)
	}

	// Try to determine the scheme, falling back to https
	var scheme string
	if u.Scheme != "" {
		scheme = u.Scheme
	} else if r.Header.Get("X-Forwarded-Proto") != "" {
		scheme = r.Header.Get("X-Forwarded-Proto")
	} else if r.TLS != nil {
		scheme = "https"
	} else {
		scheme = "http"
	}
	origin := fmt.Sprintf("%s://%s", scheme, r.Host)

	if webAuthn, exists := webAuthns[origin]; exists {
		sessionStore, _ := sessionStores[origin]
		return webAuthn, sessionStore, nil
	}

	if !dynamicOrigins {
		return nil, nil, fmt.Errorf("Request origin not valid: %s", origin)
	} else {
		log.Printf("Adding new dynamic origin: %s", origin)
		webAuthn, err = webauthn.New(&webauthn.Config{
			RPDisplayName: configuration.RPDisplayName, // Relying party display name
			RPID:          configuration.RPID,          // Relying party ID
			RPOrigin:      origin,                      // Relying party origin
		})
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to create WebAuthn for origin: %s", origin)
		}
		webAuthns[origin] = webAuthn

		var sessionStoreKey = util.RandStringBytesRmndr(32)
		var sessionStore = sessions.NewCookieStore(sessionStoreKey)
		// Sessions maintained for up to soft timeout limit
		sessionStore.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   configuration.SessionSoftTimeoutSeconds,
			HttpOnly: true,
		}
		sessionStores[origin] = sessionStore
		return webAuthn, sessionStore, nil
	}
}
