package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"regexp"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

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

func GetRedirectUrl(r *http.Request, defaultUrl string) string {
	urls, ok := r.URL.Query()["redirect_url"]

	if !ok || len(urls[0]) < 1 {
		return defaultUrl
	}

	return urls[0]
}

func JSONResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func RandStringBytesRmndr(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return b
}
