package e2e

import (
	"path/filepath"
	"testing"

	"github.com/s4l1hs/olta/pkg/proxy/database"
)

// runSessionInterception simulates the proxy's BuntDB-backed victim state
// store: a session is created the moment a victim lands on the phishing
// page, the AiTM capture path records their username, password, a custom
// (non-credential) captured field, and the stolen session cookie tokens, and
// all of it is required to survive a close/reopen of the on-disk BuntDB
// file - the same durability guarantee database_test.go already exercises,
// driven here end-to-end through the public database.Database API.
func runSessionInterception(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "olta.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("NewDatabase() error: %v", err)
	}
	closed := false
	closeDB := func() {
		if closed {
			return
		}
		closed = true
		if err := db.Close(); err != nil {
			t.Fatalf("Database.Close() error: %v", err)
		}
	}
	defer closeDB()

	const sid = "e2e-victim-session"
	if err := db.CreateSession(sid, "e2e-phishlet", "https://phish-corp.test/login", "Mozilla/5.0 (E2E harness)", "203.0.113.7"); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	if err := db.SetSessionUsername(sid, "victim@corp.example"); err != nil {
		t.Fatalf("SetSessionUsername() error: %v", err)
	}
	if err := db.SetSessionPassword(sid, "hunter2-captured"); err != nil {
		t.Fatalf("SetSessionPassword() error: %v", err)
	}
	if err := db.SetSessionCustom(sid, "mfa_code", "482913"); err != nil {
		t.Fatalf("SetSessionCustom() error: %v", err)
	}

	cookieTokens := map[string]map[string]*database.CookieToken{
		"corp.example": {
			"session_id": {Name: "session_id", Value: "aitm-captured-cookie-value", Path: "/", HttpOnly: true},
			"csrf_token": {Name: "csrf_token", Value: "csrf-captured-value", Path: "/"},
		},
	}
	if err := db.SetSessionCookieTokens(sid, cookieTokens); err != nil {
		t.Fatalf("SetSessionCookieTokens() error: %v", err)
	}

	// The write path enqueues to a background persistence goroutine; Flush
	// blocks until it has drained, so the assertions below observe durable
	// state rather than racing the writer.
	db.Flush()
	if err := db.LastPersistenceError(); err != nil {
		t.Fatalf("persistence error after Flush(): %v", err)
	}

	assertSession := func(t *testing.T, sessions []*database.Session) {
		t.Helper()
		if len(sessions) != 1 {
			t.Fatalf("got %d sessions, want 1", len(sessions))
		}
		session := sessions[0]
		if session.SessionId != sid {
			t.Fatalf("SessionId = %q, want %q", session.SessionId, sid)
		}
		if session.Username != "victim@corp.example" {
			t.Fatalf("Username = %q", session.Username)
		}
		if session.Password != "hunter2-captured" {
			t.Fatalf("Password = %q", session.Password)
		}
		if session.Custom["mfa_code"] != "482913" {
			t.Fatalf("Custom[mfa_code] = %q", session.Custom["mfa_code"])
		}
		domainTokens, ok := session.CookieTokens["corp.example"]
		if !ok {
			t.Fatalf("CookieTokens missing domain corp.example: %+v", session.CookieTokens)
		}
		sessionCookie, ok := domainTokens["session_id"]
		if !ok || sessionCookie.Value != "aitm-captured-cookie-value" || !sessionCookie.HttpOnly {
			t.Fatalf("captured session_id cookie = %+v", sessionCookie)
		}
		csrfCookie, ok := domainTokens["csrf_token"]
		if !ok || csrfCookie.Value != "csrf-captured-value" {
			t.Fatalf("captured csrf_token cookie = %+v", csrfCookie)
		}
	}

	// In-memory state is visible immediately, before any reopen.
	sessions, err := db.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions() error: %v", err)
	}
	assertSession(t, sessions)

	// Database locks: closing must succeed and release the BuntDB file lock
	// cleanly, and a subsequent open against the same path must succeed and
	// observe every field written above - proving both a clean close and
	// that the write actually reached disk rather than staying buffered.
	closeDB()

	reopened, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("reopening database after clean close: %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("closing reopened database: %v", err)
		}
	}()

	reopenedSessions, err := reopened.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions() on reopened database: %v", err)
	}
	assertSession(t, reopenedSessions)
}
