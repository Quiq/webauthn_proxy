package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"regexp"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/sessions"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Fetch webauthn session data from session store
func FetchWebauthnSession(session *sessions.Session, key string, r *http.Request) (webauthn.SessionData, error) {
	sessionData := webauthn.SessionData{}
	assertion, ok := session.Values[key].([]byte)
	if !ok {
		return sessionData, errors.New("Error unmarshaling session data")
	}
	err := json.Unmarshal(assertion, &sessionData)
	if err != nil {
		return sessionData, err
	}
	// Delete the value from the session now that it's been read
	delete(session.Values, key)
	return sessionData, nil
}

// Get "username" query param and validate against supplied regex
func GetUsername(r *http.Request, regex string) (string, error) {
	usernames, ok := r.URL.Query()["username"]

	if !ok || len(usernames[0]) < 1 {
		log.Println("Url Param 'username' is missing")
		return "", errors.New("You must supply a username")
	}

	username := usernames[0]

	if matched, err := regexp.MatchString(regex, username); !matched || err != nil {
		return "", errors.New("You must supply a valid username")
	}

	return username, nil
}

// Get "redirect_url" query param
func GetRedirectUrl(r *http.Request, defaultUrl string) string {
	urls, ok := r.URL.Query()["redirect_url"]

	if !ok || len(urls[0]) < 1 {
		return defaultUrl
	}

	return urls[0]
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

// Generate a random string of alpha characters of length n
func RandStringBytesRmndr(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return b
}
