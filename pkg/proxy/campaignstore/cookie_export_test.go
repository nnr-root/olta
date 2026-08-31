package campaignstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/s4l1hs/olta/pkg/proxy/database"
)

// TestCookieTokensJSONUsesImportableKeys verifies the dashboard's captured-
// cookie export marshals with the lowercase keys EditThisCookie and
// Cookie-Editor require to import a session (path, domain, name, value,
// expirationDate, httpOnly, hostOnly, secure). Before this fix, the local
// cookie type carried no JSON tags, so encoding/json emitted capitalized Go
// field names instead and neither tool could read the export.
func TestCookieTokensJSONUsesImportableKeys(t *testing.T) {
	tokens := map[string]map[string]*database.CookieToken{
		// A host-only (no leading dot) domain keeps hostOnly=true, so the
		// field is present under omitempty and this test can assert on it
		// directly rather than relying on a value that gets dropped.
		"example.com": {
			"session": {Value: "abc123", Path: "/", HttpOnly: true},
		},
	}

	raw := cookieTokensJSON(tokens)

	var decoded []map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("got %d cookies, want 1", len(decoded))
	}
	cookie := decoded[0]

	for _, key := range []string{"path", "domain", "name", "value", "expirationDate", "hostOnly"} {
		if _, ok := cookie[key]; !ok {
			t.Fatalf("export missing required lowercase key %q: %v", key, cookie)
		}
	}
	// httpOnly is set for this fixture, so it must survive the omitempty tag.
	if _, ok := cookie["httpOnly"]; !ok {
		t.Fatalf("export missing httpOnly key for an HttpOnly cookie: %v", cookie)
	}

	for _, key := range []string{"Path", "Domain", "Value", "Name", "ExpirationDate", "HttpOnly", "HostOnly"} {
		if _, ok := cookie[key]; ok {
			t.Fatalf("export still carries capitalized Go field name %q: %v", key, cookie)
		}
	}

	if got := cookie["domain"]; got != "example.com" {
		t.Fatalf("domain = %v, want %q", got, "example.com")
	}
	if got := cookie["name"]; got != "session" {
		t.Fatalf("name = %v, want %q", got, "session")
	}
	if got := cookie["value"]; got != "abc123" {
		t.Fatalf("value = %v, want %q", got, "abc123")
	}
}

// TestCookieTokensJSONMarksSecurePrefixedCookies verifies the export flags
// __Host-/__Secure- prefixed cookies as secure, matching the terminal's own
// export (pkg/proxy/core/terminal.go cookieTokensToJSON) so the two paths no
// longer silently disagree.
func TestCookieTokensJSONMarksSecurePrefixedCookies(t *testing.T) {
	tokens := map[string]map[string]*database.CookieToken{
		"example.com": {
			"__Secure-session": {Value: "abc123", Path: "/"},
			"plain":            {Value: "def456", Path: "/"},
		},
	}

	raw := cookieTokensJSON(tokens)

	var decoded []map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}

	secureByName := map[string]bool{}
	for _, cookie := range decoded {
		name, _ := cookie["name"].(string)
		_, secure := cookie["secure"]
		secureByName[name] = secure
	}

	if !secureByName["__Secure-session"] {
		t.Fatalf("__Secure- prefixed cookie must be marked secure: %v", decoded)
	}
	if secureByName["plain"] {
		t.Fatalf("unprefixed cookie must not be marked secure: %v", decoded)
	}
}

// TestCookieTokensJSONOmitsSameSite verifies the export does not fabricate a
// sameSite value: database.CookieToken never retains it, so emitting one
// here would be inventing data the proxy never actually observed.
func TestCookieTokensJSONOmitsSameSite(t *testing.T) {
	tokens := map[string]map[string]*database.CookieToken{
		"example.com": {
			"session": {Value: "abc123", Path: "/"},
		},
	}

	raw := cookieTokensJSON(tokens)
	if strings.Contains(raw, "sameSite") {
		t.Fatalf("export must not fabricate a sameSite field: %s", raw)
	}
}
