package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	u "github.com/Quiq/webauthn_proxy/user"
)

func resetState() {
	users = make(map[string]u.User)
	registrations = make(map[string]u.User)
	registrationTimes = make(map[string]time.Time)
	loginVerifications = make(map[string]*LoginVerification)
}

// Run with -race: concurrent unauthenticated registrations must not corrupt shared maps.
func TestConcurrentRegistrations(t *testing.T) {
	resetState()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("user%d", i)
			if _, err := getOrCreateRegistrant(name); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			lookupUserOrRegistrant(name)
			findCredentialOwner([]byte("x"))
		}(i)
	}
	wg.Wait()
	if len(registrations) != 200 {
		t.Fatalf("expected 200 registrations, got %d", len(registrations))
	}
}

func TestPendingRegistrationsCapAndExpiry(t *testing.T) {
	resetState()
	for i := 0; i < maxPendingRegistrations; i++ {
		if _, err := getOrCreateRegistrant(fmt.Sprintf("u%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := getOrCreateRegistrant("overflow"); err == nil {
		t.Fatal("expected cap error")
	}
	// Existing registrants are still served at the cap.
	if _, err := getOrCreateRegistrant("u1"); err != nil {
		t.Fatal(err)
	}
	// Expired entries are pruned to make room.
	for name := range registrationTimes {
		registrationTimes[name] = time.Now().Add(-2 * registrationTTL)
	}
	if _, err := getOrCreateRegistrant("overflow"); err != nil {
		t.Fatalf("expected expired entries to be pruned: %v", err)
	}
	if len(registrations) != 1 {
		t.Fatalf("expected 1 registration after prune, got %d", len(registrations))
	}
}
