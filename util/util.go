package util

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

// Get "username" query param and validate against supplied regex
func GetUsername(r *http.Request, regex string) (string, error) {
	username := r.URL.Query().Get("username")
	if username == "" {
		return "", fmt.Errorf("you must supply a username")
	}
	if matched, err := regexp.MatchString(regex, username); !matched || err != nil {
		return "", fmt.Errorf("you must supply a valid username")
	}
	return username, nil
}

// Marshal object to JSON and write response
func JSONResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

// Fetch webauthn session data from session store
func FetchWebauthnSession(session *sessions.Session, key string, r *http.Request) (webauthn.SessionData, error) {
	sessionData := webauthn.SessionData{}
	assertion, ok := session.Values[key].([]byte)
	if !ok {
		return sessionData, fmt.Errorf("error unmarshaling session data")
	}
	err := json.Unmarshal(assertion, &sessionData)
	if err != nil {
		return sessionData, err
	}
	// Delete the value from the session now that it's been read
	delete(session.Values, key)
	return sessionData, nil
}

// Save webauthn session data to session store
func SaveWebauthnSession(session *sessions.Session, key string, sessionData *webauthn.SessionData, r *http.Request, w http.ResponseWriter) error {
	marshaledData, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}
	session.Values[key] = marshaledData
	session.Save(r, w)
	return nil
}

// ExpireWebauthnSession invalidate session by expiring cookie
func ExpireWebauthnSession(session *sessions.Session, r *http.Request, w http.ResponseWriter) {
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	session.Save(r, w)
}

// GetUserIP return user IP address
func GetUserIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}
	ip = r.Header.Get("X-Real-Ip")
	if ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// Generate crytographically secure challenge
func GenChallenge() string {
	//call on the import DUO method
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		panic("Failed to generate cryptographically secure challenge")
	}
	return base64.RawURLEncoding.EncodeToString(challenge)
}

func PrettyPrint(data interface{}) {
	var p []byte
	p, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s \n", p)
}

// SetupLogging setup logger
func SetupLogging(name, loggingLevel string) *logrus.Entry {
	if loggingLevel != "info" {
		if level, err := logrus.ParseLevel(loggingLevel); err == nil {
			logrus.SetLevel(level)
		}
	}
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: time.RFC3339,
		FullTimestamp:   true,
	})
	// Output to stdout instead of the default stderr.
	logrus.SetOutput(os.Stdout)
	return logrus.WithFields(logrus.Fields{"logger": name})
}
