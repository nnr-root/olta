package database

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionWritesAreVisibleInMemoryBeforePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	db, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession("sid", "example", "https://example.test", "agent", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSessionUsername("sid", "authorized-user"); err != nil {
		t.Fatal(err)
	}
	sessions, err := db.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Username != "authorized-user" {
		t.Fatalf("unexpected in-memory session: %#v", sessions)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	sessions, err = reopened.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Username != "authorized-user" {
		t.Fatalf("unexpected persisted session: %#v", sessions)
	}
}

func TestRateLimitUsesImmediateInMemoryState(t *testing.T) {
	db, err := NewDatabase(filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for attempt := 1; attempt <= 3; attempt++ {
		allowed, err := db.AllowRequest("192.0.2.20", 2, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if allowed != (attempt <= 2) {
			t.Fatalf("attempt %d allowed = %t", attempt, allowed)
		}
	}
}

func TestBlockedIPsPersistInBuntDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	db, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.BlockIP("192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	ips, err := reopened.ListBlockedIPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "192.0.2.10" {
		t.Fatalf("blocked IPs = %#v", ips)
	}
}
