package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	u "github.com/Quiq/webauthn_proxy/user"
	util "github.com/Quiq/webauthn_proxy/util"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	yaml "gopkg.in/yaml.v3"
)

type Configuration struct {
	RPDisplayName string   // Relying party display name
	RPID          string   // Relying party ID
	RPOrigins     []string // Relying party origin

	// Note: enabling this can be risky as it allows anyone to add themselves to the proxy.
	// Only enable test mode during testing!
	TestMode bool

	ServerAddress             string
	ServerPort                string
	SessionSoftTimeoutSeconds int
	SessionHardTimeoutSeconds int
	SessionCookieName         string
	UserCookieName            string
	UsernameRegex             string
	CookieSecure              bool
	CookieDomain              string
	CidrNetworks            map[string][]string `yaml:"cidr_networks"`
}

type CredentialsConfiguration struct {
	CookieSecrets []string          `yaml:"cookie_session_secrets"`
	Credentials   map[string]string `yaml:"user_credentials"`
}

type WebAuthnMessage struct {
	Message string
}

type VerificationSuccess struct {
	Status      string `json:"status"`
	MatchMethod string `json:"match_method"`
	WebAuthnIP  string `json:"webauthn_ip,omitempty"`
	UserIP      string `json:"user_ip,omitempty"`
	NetworkName string `json:"network_name,omitempty"`
	MatchedCIDR string `json:"matched_cidr,omitempty"`
}

type RegistrationSuccess struct {
	Message string
	Data    string
}

type LoginVerification struct {
	IPAddr    string
	LoginTime time.Time
}

const (
	AuthenticatedUsernameHeader = "X-Authenticated-User"
	loginVerificationInterval   = 5 * time.Minute
	staticPath                  = "static/"
)

var (
	configuration      Configuration
	loginError         WebAuthnMessage
	registrationError  WebAuthnMessage
	authError          WebAuthnMessage
	users              map[string]u.User
	registrations      map[string]u.User
	cookieSecrets      []string
	dynamicOrigins     bool
	webAuthns          map[string]*webauthn.WebAuthn
	sessionStores      map[string]*sessions.CookieStore
	loginVerifications map[string]*LoginVerification
	logger             *logrus.Entry
)

func main() {
	var (
		genSecretFlag, versionFlag bool
		loggingLevel               string
	)
	flag.StringVar(&loggingLevel, "log-level", "info", "logging level")
	flag.BoolVar(&genSecretFlag, "generate-secret", false, "generate a random string suitable as a cookie secret")
	flag.BoolVar(&versionFlag, "version", false, "show version")
	flag.Parse()
	logger = util.SetupLogging("webauthn_proxy", loggingLevel)

	if genSecretFlag {
		fmt.Println(util.GenChallenge())
		return
	} else if versionFlag {
		fmt.Println(version)
		return
	}

	var err error
	var credfile []byte
	var credentialsConfig CredentialsConfiguration
	// Standard error messages
	loginError = WebAuthnMessage{Message: "Unable to login"}
	registrationError = WebAuthnMessage{Message: "Error during registration"}
	authError = WebAuthnMessage{Message: "Unauthenticated"}

	users = make(map[string]u.User)
	registrations = make(map[string]u.User)
	webAuthns = make(map[string]*webauthn.WebAuthn)
	sessionStores = make(map[string]*sessions.CookieStore)
	loginVerifications = make(map[string]*LoginVerification)

	// Set configuration defaults
	viper.SetDefault("configpath", "./config")
	viper.SetEnvPrefix("webauthn_proxy")
	viper.BindEnv("configpath")
	viper.SetConfigName("config")
	viper.SetConfigType("yml")

	viper.SetDefault("rpdisplayname", "MyCompany")
	viper.SetDefault("rpid", "localhost")
	viper.SetDefault("rporigins", []string{})
	viper.SetDefault("testmode", false)
	viper.SetDefault("serveraddress", "0.0.0.0")
	viper.SetDefault("serverport", "8080")
	viper.SetDefault("sessionsofttimeoutseconds", 28800)
	viper.SetDefault("sessionhardtimeoutseconds", 86400)
	viper.SetDefault("sessioncookiename", "webauthn-proxy-session")
	viper.SetDefault("usercookiename", "webauthn-proxy-username")
	viper.SetDefault("usernameregex", "^.+$")
	viper.SetDefault("cookiesecure", false)
	viper.SetDefault("cookiedomain", "")

	// Read in configuration file
	configpath := viper.GetString("configpath")
	viper.AddConfigPath(configpath)
	logger.Infof("Reading config file %s/config.yml", configpath)
	if err := viper.ReadInConfig(); err != nil {
		logger.Fatalf("Error reading config file %s/config.yml: %s", configpath, err)
	}
	if err = viper.Unmarshal(&configuration); err != nil {
		logger.Fatalf("Unable to decode config file into struct: %s", err)
	}
	// Read in credentials file
	credentialspath := filepath.Join(configpath, "credentials.yml")
	logger.Infof("Reading credentials file %s", credentialspath)

	if credfile, err = os.ReadFile(credentialspath); err != nil {
		logger.Fatalf("Unable to read credential file %s %v", credentialspath, err)
	}
	if err = yaml.Unmarshal(credfile, &credentialsConfig); err != nil {
		logger.Fatalf("Unable to parse YAML credential file %s %v", credentialspath, err)
	}

	logger.Debugf("Configuration: %+v\n", configuration)
	logger.Debugf("Viper AllSettings: %+v\n", viper.AllSettings())

	// Ensure that session soft timeout <= hard timeout
	if configuration.SessionSoftTimeoutSeconds < 1 {
		logger.Fatalf("Invalid session soft timeout of %d, must be > 0", configuration.SessionSoftTimeoutSeconds)
	} else if configuration.SessionHardTimeoutSeconds < 1 {
		logger.Fatalf("Invalid session hard timeout of %d, must be > 0", configuration.SessionHardTimeoutSeconds)
	} else if configuration.SessionHardTimeoutSeconds < configuration.SessionSoftTimeoutSeconds {
		logger.Fatal("Invalid session hard timeout, must be > session soft timeout")
	}

	cookieSecrets = credentialsConfig.CookieSecrets
	if len(cookieSecrets) == 0 {
		logger.Warnf("You did not set any cookie_session_secrets in credentials.yml.")
		logger.Warnf("So it will be dynamic and your cookie sessions will not persist proxy restart.")
		logger.Warnf("Generate one using `-generate-secret` flag and add to credentials.yml.")
	}
	if len(cookieSecrets) > 0 && cookieSecrets[0] == "your-own-cookie-secret" {
		logger.Warnf("You did not set any valid cookie_session_secrets in credentials.yml.")
		logger.Fatalf("Generate one using `-generate-secret` flag and add to credentials.yml.")
	}
	for username, credential := range credentialsConfig.Credentials {
		unmarshaledUser, err := u.UnmarshalUser(credential)
		if err != nil {
			logger.Fatalf("Error unmarshalling user credential %s: %s", username, err)
		}
		if username != unmarshaledUser.Name {
			logger.Fatalf("Credentials for user %s are designated for another one %s", username, unmarshaledUser.Name)
		}
		users[username] = *unmarshaledUser
		if logrus.GetLevel() == logrus.DebugLevel {
			util.PrettyPrint(unmarshaledUser)
		}
	}

	// Print the effective config.
	fmt.Println()
	fmt.Printf("Relying Party Display Name: %s\n", configuration.RPDisplayName)
	fmt.Printf("Relying Party ID: %s\n", configuration.RPID)
	fmt.Printf("Relying Party Origins: %v\n", configuration.RPOrigins)
	fmt.Printf("Test Mode: %v\n", configuration.TestMode)
	fmt.Printf("Server Address: %s\n", configuration.ServerAddress)
	fmt.Printf("Server Port: %s\n", configuration.ServerPort)
	fmt.Printf("Session Soft Timeout: %d\n", configuration.SessionSoftTimeoutSeconds)
	fmt.Printf("Session Hard Timeout: %d\n", configuration.SessionHardTimeoutSeconds)
	fmt.Printf("Session Cookie Name: %s\n", configuration.SessionCookieName)
	fmt.Printf("User Cookie Name: %s\n", configuration.UserCookieName)
	fmt.Printf("Username Regex: %s\n", configuration.UsernameRegex)
	fmt.Printf("Cookie secure: %v\n", configuration.CookieSecure)
	fmt.Printf("Cookie domain: %s\n", configuration.CookieDomain)
	fmt.Printf("Cookie secrets: %d\n", len(cookieSecrets))
	fmt.Printf("User credentials: %d\n", len(users))
	fmt.Println()
	if configuration.TestMode {
		fmt.Printf("Warning!!! Test Mode enabled! This is not safe for production!\n\n")
	}

	// If list of relying party origins has been specified in configuration,
	// create one Webauthn config / Session store per origin, else origins will be dynamic.
	if len(configuration.RPOrigins) > 0 {
		for _, origin := range configuration.RPOrigins {
			if _, _, err := createWebAuthnClient(origin); err != nil {
				logger.Fatalf("Failed to create WebAuthn from config: %s", err)
			}
		}
	} else {
		dynamicOrigins = true
	}

	util.CookieSecure = configuration.CookieSecure
	util.CookieDomain = configuration.CookieDomain
	r := http.NewServeMux()
	fileServer := http.FileServer(http.Dir("./static"))
	r.Handle("/webauthn/static/", http.StripPrefix("/webauthn/static/", fileServer))
	r.HandleFunc("/", HandleIndex)
	r.HandleFunc("/webauthn/login", HandleLogin)
	r.HandleFunc("/webauthn/login/get_credential_request_options", GetCredentialRequestOptions)
	r.HandleFunc("/webauthn/login/process_login_assertion", ProcessLoginAssertion)
	r.HandleFunc("/webauthn/register", HandleRegister)
	r.HandleFunc("/webauthn/register/get_credential_creation_options", GetCredentialCreationOptions)
	r.HandleFunc("/webauthn/register/process_registration_attestation", ProcessRegistrationAttestation)
	r.HandleFunc("/webauthn/auth", HandleAuth)
	r.HandleFunc("/webauthn/verify", HandleVerify)
	r.HandleFunc("/webauthn/logout", HandleLogout)

	listenAddress := fmt.Sprintf("%s:%s", configuration.ServerAddress, configuration.ServerPort)
	logger.Infof("Starting server at %s", listenAddress)
	logger.Fatal(http.ListenAndServe(listenAddress, r))
}

// Root page
func HandleIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/webauthn/login", http.StatusTemporaryRedirect)
}

// /webauthn/auth - Check if user has an authenticated session
// This endpoint can be used for internal nginx checks.
// Also this endpoint prolongs the user session by soft limit interval.
func HandleAuth(w http.ResponseWriter, r *http.Request) {
	_, sessionStore, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, authError, http.StatusBadRequest)
		return
	}

	session, err := sessionStore.Get(r, configuration.SessionCookieName)
	if err != nil {
		logger.Errorf("Error getting session from session store during user auth handler: %s", err)
		util.JSONResponse(w, authError, http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		util.JSONResponse(w, authError, http.StatusUnauthorized)
		return
	}
	username := session.Values["authenticated_user"].(string)
	if time.Now().Unix()-session.Values["authenticated_time"].(int64) >= int64(configuration.SessionHardTimeoutSeconds) {
		// Session has exceeded the hard limit
		logger.Debugf("Expiring user %s session expired by hard limit", username)
		util.ExpireWebauthnSession(session, r, w)
		util.JSONResponse(w, authError, http.StatusUnauthorized)
		return
	}
	userIP := session.Values["authenticated_ip"].(string)
	if userIP != util.GetUserIP(r) {
		// User IP mismatches, let use to re-login
		logger.Debugf("Invalidating user %s session coming from %s while session was created from %s", username, util.GetUserIP(r), userIP)
		util.ExpireWebauthnSession(session, r, w)
		util.JSONResponse(w, authError, http.StatusUnauthorized)
		return
	}

	// Update the session to reset the soft timeout
	session.Save(r, w)
	w.Header().Set(AuthenticatedUsernameHeader, username)
	util.JSONResponse(w, WebAuthnMessage{Message: "OK"}, http.StatusOK)
}

// /webauthn/login - Show authenticated page or serve up login page
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	_, sessionStore, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	session, err := sessionStore.Get(r, configuration.SessionCookieName)
	if err != nil {
		logger.Errorf("Error getting session from session store during login handler: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Prevents html caching because this page serves two different pages.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		content, err := os.ReadFile(filepath.Join(staticPath, "login.html"))
		if err != nil {
			util.JSONResponse(w, loginError, http.StatusNotFound)
			return
		}
		content = []byte(strings.Replace(string(content), configuration.UserCookieName, configuration.UserCookieName, 1))
		reader := bytes.NewReader(content)
		http.ServeContent(w, r, "", time.Time{}, reader)
		return
	}

	if redirectUrl := r.URL.Query().Get("redirect_url"); redirectUrl != "" {
		http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
	} else {
		http.ServeFile(w, r, filepath.Join(staticPath, "authenticated.html"))
	}
}

// /webauthn/logout - Logout page
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	_, sessionStore, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, authError, http.StatusBadRequest)
		return
	}

	session, err := sessionStore.Get(r, configuration.SessionCookieName)
	if err == nil {
		util.ExpireWebauthnSession(session, r, w)
	}
	http.Redirect(w, r, "/webauthn/login", http.StatusTemporaryRedirect)
}

// /webauthn/verify - one-time verification if user has recently authenticated, useful as 2FA check.
func HandleVerify(w http.ResponseWriter, r *http.Request) {
	_, _, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, authError, http.StatusBadRequest)
		return
	}

	username := r.URL.Query().Get("username")
	userIP := r.URL.Query().Get("ip")
	if data, exists := loginVerifications[username]; exists {
		// Check whether this is whithin last 5 min.
		if data.LoginTime.Add(loginVerificationInterval).Before(time.Now()) {
			delete(loginVerifications, username)
			util.JSONResponse(w, authError, http.StatusUnauthorized)
			return
		}
		webAuthnIPStr := data.IPAddr
		// Check for exact IP match first
		if webAuthnIPStr == userIP {
			delete(loginVerifications, username)
			logger.Infof("User %s verified successfully with exact IP match from %s", username, userIP)
			response := VerificationSuccess{
				Status:      "OK",
				MatchMethod: "exact",
			}
			util.JSONResponse(w, response, http.StatusOK)
			return
		}

		// If exact match fails, check for cidr_network CIDR match
		parsedWebAuthnIP := net.ParseIP(webAuthnIPStr)
		parsedUserIP := net.ParseIP(userIP)
		if parsedWebAuthnIP != nil && parsedUserIP != nil {
			for networkName, cidrs := range configuration.CidrNetworks {
				for _, cidrStr := range cidrs {
					_, ipNet, err := net.ParseCIDR(cidrStr)
					if err != nil {
						logger.Warnf("Invalid CIDR in config for %s: %s", networkName, cidrStr)
						continue
					}
					if ipNet.Contains(parsedWebAuthnIP) && ipNet.Contains(parsedUserIP) {
						delete(loginVerifications, username)
						logger.Infof("User %s verified successfully with CIDR match: WebAuthnIP=%s, UserIP=%s, Network=%s, CIDR=%s",
							username, webAuthnIPStr, userIP, networkName, cidrStr)
						response := VerificationSuccess{
							Status:      "OK",
							MatchMethod: "cidr",
							WebAuthnIP:  webAuthnIPStr,
							UserIP:      userIP,
							NetworkName: networkName,
							MatchedCIDR: cidrStr,
						}
						util.JSONResponse(w, response, http.StatusOK)
						return
					}
				}
			}
		}

		// both checks failed
		logger.Warnf("User %s failed verification: auth IP %s, validating IP %s. No exact or CIDR match found.", username, webAuthnIPStr, userIP)
	}
	util.JSONResponse(w, authError, http.StatusUnauthorized)
}

// /webauthn/register - Serve up registration page
func HandleRegister(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(staticPath, "register.html"))
}

/*
/webauthn/login/get_credential_request_options -
Step 1 of the login process, get credential request options for the user
*/
func GetCredentialRequestOptions(w http.ResponseWriter, r *http.Request) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		logger.Errorf("Error getting username: %s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	user, exists := users[username]
	if !exists {
		logger.Warnf("User %s does not exist", username)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Begin the login process
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		logger.Errorf("Error beginning the login process: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Store Webauthn session data
	session, err := sessionStore.Get(r, configuration.SessionCookieName)
	if err != nil {
		logger.Errorf("Error getting session from session store during login: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	err = util.SaveWebauthnSession(session, "authentication", sessionData, r, w)
	if err != nil {
		logger.Errorf("Error saving Webauthn session during login: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, options, http.StatusOK)
}

/*
/webauthn/login/process_login_assertion -
Step 2 of the login process, process the assertion from the client authenticator
*/
func ProcessLoginAssertion(w http.ResponseWriter, r *http.Request) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		logger.Errorf("Error getting username: %s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	user, exists := users[username]
	if !exists {
		logger.Errorf("User %s does not exist", username)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Load the session data
	session, err := sessionStore.Get(r, configuration.SessionCookieName)
	if err != nil {
		logger.Errorf("Error getting session from session store during login: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	sessionData, err := util.FetchWebauthnSession(session, "authentication", r)
	if err != nil {
		logger.Errorf("Error getting Webauthn session during login: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	cred, err := webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		logger.Errorf("Error finishing Webauthn login: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Check for cloned authenticators
	if cred.Authenticator.CloneWarning {
		logger.Errorf("Error. Authenticator for %s appears to be cloned, failing login", username)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Increment sign counter on user to help avoid clones
	if userCredential, err := user.CredentialById(cred.ID); err != nil {
		logger.Errorf("Error incrementing sign counter on user authenticator: %s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	} else {
		userCredential.Authenticator.UpdateCounter(cred.Authenticator.SignCount)
	}

	// Set user as authenticated
	userIP := util.GetUserIP(r)
	loginVerifications[username] = &LoginVerification{IPAddr: userIP, LoginTime: time.Now()}
	// session cookie
	session.Values["authenticated"] = true
	session.Values["authenticated_user"] = username
	session.Values["authenticated_time"] = time.Now().Unix()
	session.Values["authenticated_ip"] = userIP
	session.Save(r, w)
	// username cookie
	ck := http.Cookie{
		Name:    configuration.UserCookieName,
		Domain:  configuration.CookieDomain,
		Path:    "/",
		Value:   username,
		Expires: time.Now().AddDate(1, 0, 0), // 1 year
		Secure:  configuration.CookieSecure,
	}
	http.SetCookie(w, &ck)
	logger.Infof("User %s authenticated successfully from %s", username, userIP)
	util.JSONResponse(w, WebAuthnMessage{Message: "Authentication Successful"}, http.StatusOK)
}

/*
/webauthn/register/get_credential_creation_options -
Step 1 of the registration process, get credential creation options
*/
func GetCredentialCreationOptions(w http.ResponseWriter, r *http.Request) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		logger.Errorf("Error getting username: %s", err)
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
	options, sessionData, err := webAuthn.BeginRegistration(user, user.UserRegistrationOptions)

	if err != nil {
		logger.Errorf("Error beginning Webauthn registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	// Store session data as marshaled JSON
	session, err := sessionStore.Get(r, configuration.SessionCookieName)
	if err != nil {
		logger.Errorf("Error getting session from session store during registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	if err = util.SaveWebauthnSession(session, "registration", sessionData, r, w); err != nil {
		logger.Errorf("Error saving Webauthn session during registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, options, http.StatusOK)
}

/*
/webauthn/register/process_registration_attestation -
Step 2 of the registration process, process the attestation (new credential) from the client authenticator
*/
func ProcessRegistrationAttestation(w http.ResponseWriter, r *http.Request) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err != nil {
		logger.Errorf("Error getting username: %s", err)
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
			logger.Errorf("Registrant %s skipped GetCredentialCreationOptions step, failing registration", username)
			util.JSONResponse(w, registrationError, http.StatusBadRequest)
			return
		}
	}

	// Load the session data
	session, err := sessionStore.Get(r, configuration.SessionCookieName)
	if err != nil {
		logger.Errorf("Error getting session from session store during registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	sessionData, err := util.FetchWebauthnSession(session, "registration", r)
	if err != nil {
		logger.Errorf("Error getting Webauthn session during registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		logger.Errorf("Error finishing Webauthn registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	// Check that the credential doesn't belong to another user or registrant
	for _, u := range users {
		for _, c := range u.Credentials {
			if bytes.Equal(c.ID, credential.ID) {
				logger.Errorf("Error registering credential for user %s, matching credential ID with user %s", username, u.Name)
				util.JSONResponse(w, registrationError, http.StatusBadRequest)
				return
			}
		}
	}
	for _, r := range registrations {
		for _, c := range r.Credentials {
			if bytes.Equal(c.ID, credential.ID) {
				logger.Errorf("Error registering credential for user %s, matching credential ID with registrant %s", username, r.Name)
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
		logger.Errorf("Error marshalling user object: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	userCredText := fmt.Sprintf("%s: %s", username, marshaledUser)
	successMessage := RegistrationSuccess{
		Message: "Registration Successful. Please share the values below with your system administrator so they can add you!",
		Data:    userCredText,
	}
	logger.Infof("New user registration: %s", userCredText)
	util.JSONResponse(w, successMessage, http.StatusOK)
}

// Check that the origin is in our configuration or we're allowing dynamic origins
func checkOrigin(r *http.Request) (*webauthn.WebAuthn, *sessions.CookieStore, error) {
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
		sessionStore := sessionStores[origin]
		return webAuthn, sessionStore, nil
	}

	if !dynamicOrigins {
		return nil, nil, fmt.Errorf("request origin not valid: %s", origin)
	} else {
		logger.Infof("Adding new dynamic origin: %s", origin)
		webAuthn, sessionStore, err := createWebAuthnClient(origin)
		return webAuthn, sessionStore, err
	}
}

// createWebAuthnClient add webauthn client and session store per origin
func createWebAuthnClient(origin string) (*webauthn.WebAuthn, *sessions.CookieStore, error) {
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: configuration.RPDisplayName, // Relying party display name
		RPID:          configuration.RPID,          // Relying party ID
		RPOrigins:     []string{origin},            // Relying party origin
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create WebAuthn for origin: %s", origin)
	}
	webAuthns[origin] = webAuthn

	var stringKeys []string
	var byteKeyPairs [][]byte
	if len(cookieSecrets) == 0 {
		stringKeys = []string{util.GenChallenge()}
	} else {
		stringKeys = cookieSecrets
	}
	// Each keypair consists of auth key and enc key.
	// If auth or enc key is changed all users will have to re-login.
	// enc key is optional and should be up to 32 bytes!
	// Otherwise it will whether fail with unclear error on login/register
	// or if you are lucky complain about the length. Not using enc key (nil).
	for _, s := range stringKeys {
		byteKeyPairs = append(byteKeyPairs, []byte(s), nil)
	}
	var sessionStore = sessions.NewCookieStore(byteKeyPairs...)
	sessionStore.Options = &sessions.Options{
		Domain:   configuration.CookieDomain,
		Path:     "/",
		MaxAge:   configuration.SessionSoftTimeoutSeconds,
		HttpOnly: true,
		Secure:   configuration.CookieSecure,
	}
	sessionStores[origin] = sessionStore
	return webAuthn, sessionStore, nil
}
