package database

import (
	"path/filepath"
	"testing"
)

func TestSessionCaptureSubscriptionReceivesClone(t *testing.T) {
	db, err := NewDatabase(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatalf("NewDatabase() error = %v", err)
	}
	defer db.Close()
	if err := db.CreateSession("sid", "o365", "https://example.test/", "browser", "192.0.2.1"); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	events := make(chan *Session, 1)
	unsubscribe := db.SubscribeSessionCaptures(func(session *Session) { events <- session })
	defer unsubscribe()
	tokens := map[string]map[string]*CookieToken{
		"example.test": {"session": {Name: "session", Value: "original"}},
	}
	if err := db.SetSessionCookieTokens("sid", tokens); err != nil {
		t.Fatalf("SetSessionCookieTokens() error = %v", err)
	}

	event := <-events
	if event.SessionId != "sid" || event.CookieTokens["example.test"]["session"].Value != "original" {
		t.Fatalf("capture event = %+v, want cloned session snapshot", event)
	}
	event.CookieTokens["example.test"]["session"].Value = "mutated"
	sessions, err := db.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if got := sessions[0].CookieTokens["example.test"]["session"].Value; got != "original" {
		t.Errorf("stored cookie = %q, want listener mutation isolation", got)
	}
}
