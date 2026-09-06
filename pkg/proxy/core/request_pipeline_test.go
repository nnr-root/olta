package core

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseSessionScriptRoute(t *testing.T) {
	cases := []struct {
		path      string
		matched   bool
		sessionID string
		scriptID  string
	}{
		{"/s/abc123/inject.js", true, "abc123", "inject"},
		{"/s/abc123/one.two.js", true, "abc123", "one.two"},
		// The shape matches but the second segment is not a script. The
		// route still matches, so it shadows the single-segment route -- see
		// parseSessionScriptRoute's doc comment.
		{"/s/abc123/notascript", true, "abc123", ""},
		{"/s/abc123/.js", true, "abc123", ""},
		// Not the two-segment shape at all.
		{"/s/abc123", false, "", ""},
		{"/s/abc123.js", false, "", ""},
		{"/other/abc/inject.js", false, "", ""},
		{"", false, "", ""},
	}

	// Every input here is a URL *path*: http.Request.URL.Path never carries a
	// query string, so these functions never see one.
	for _, testCase := range cases {
		route, matched := parseSessionScriptRoute(testCase.path)
		if matched != testCase.matched {
			t.Errorf("parseSessionScriptRoute(%q) matched = %v, want %v", testCase.path, matched, testCase.matched)
			continue
		}
		if !matched {
			continue
		}
		if route.SessionID != testCase.sessionID || route.ScriptID != testCase.scriptID {
			t.Errorf("parseSessionScriptRoute(%q) = {%q, %q}, want {%q, %q}",
				testCase.path, route.SessionID, route.ScriptID, testCase.sessionID, testCase.scriptID)
		}
	}
}

func TestParseSessionRoute(t *testing.T) {
	cases := []struct {
		path      string
		matched   bool
		sessionID string
		isScript  bool
	}{
		{"/s/abc123", true, "abc123", false},
		{"/s/abc123.js", true, "abc123", true},
		{"/s/", true, "", false},
		{"/s/abc123/anything", true, "abc123", false},
		{"/other/abc123", false, "", false},
		{"/", false, "", false},
		{"", false, "", false},
	}

	for _, testCase := range cases {
		route, matched := parseSessionRoute(testCase.path)
		if matched != testCase.matched {
			t.Errorf("parseSessionRoute(%q) matched = %v, want %v", testCase.path, matched, testCase.matched)
			continue
		}
		if !matched {
			continue
		}
		if route.SessionID != testCase.sessionID || route.IsScript != testCase.isScript {
			t.Errorf("parseSessionRoute(%q) = {%q, script=%v}, want {%q, script=%v}",
				testCase.path, route.SessionID, route.IsScript, testCase.sessionID, testCase.isScript)
		}
	}
}

// TestScriptRouteShadowsRedirectRoute pins the precedence the original
// closure had and this extraction preserves: a two-segment path is never
// handled as the single-segment redirect API, even when its second segment is
// not a script. Getting this wrong would route /s/<session>/anything into the
// redirect API, which polls and can block.
func TestScriptRouteShadowsRedirectRoute(t *testing.T) {
	const path = "/s/abc123/notascript"

	script, scriptMatched := parseSessionScriptRoute(path)
	if !scriptMatched {
		t.Fatal("the two-segment shape did not match, so it would fall through to the redirect route")
	}
	if script.ScriptID != "" {
		t.Errorf("ScriptID = %q, want empty: the segment is not a script", script.ScriptID)
	}
}

func TestTrimJSSuffix(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		trimmed bool
	}{
		{"inject.js", "inject", true},
		{"a.b.js", "a.b", true},
		{"inject", "inject", false},
		{".js", ".js", false},
		{"", "", false},
		{"js", "js", false},
	}
	for _, testCase := range cases {
		got, trimmed := trimJSSuffix(testCase.in)
		if got != testCase.want || trimmed != testCase.trimmed {
			t.Errorf("trimJSSuffix(%q) = (%q, %v), want (%q, %v)",
				testCase.in, got, trimmed, testCase.want, testCase.trimmed)
		}
	}
}

func TestResolveRequestTargets(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://login.example.com/account/signin?rid=abcdefgh&x=1", nil)
	request.Host = "login.example.com"
	request.URL.Scheme = "https"

	targets := resolveRequestTargets(request)

	if targets.Host != "login.example.com" {
		t.Errorf("Host = %q", targets.Host)
	}
	if targets.Path != "/account/signin" {
		t.Errorf("Path = %q", targets.Path)
	}
	if want := "https://login.example.com/account/signin?rid=abcdefgh&x=1"; targets.URL != want {
		t.Errorf("URL = %q, want %q", targets.URL, want)
	}
	// The lure URL deliberately excludes the query: a lure is identified by
	// its path, so a tracking parameter appended to the link must not stop it
	// matching.
	if want := "https://login.example.com/account/signin"; targets.LureURL != want {
		t.Errorf("LureURL = %q, want %q (the query must not be part of lure matching)", targets.LureURL, want)
	}
}

func TestResolveRequestTargetsWithoutAQuery(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://login.example.com/", nil)
	request.Host = "login.example.com"
	request.URL.Scheme = "https"

	targets := resolveRequestTargets(request)
	if targets.URL != targets.LureURL {
		t.Errorf("URL (%q) and LureURL (%q) should agree with no query string", targets.URL, targets.LureURL)
	}
}

func TestResolveRequestTargetsHandlesNil(t *testing.T) {
	if got := resolveRequestTargets(nil); got != (RequestTargets{}) {
		t.Errorf("resolveRequestTargets(nil) = %+v, want the zero value", got)
	}
	if got := resolveRequestTargets(&http.Request{}); got != (RequestTargets{}) {
		t.Errorf("resolveRequestTargets(request with no URL) = %+v, want the zero value", got)
	}
}

// accessControlProxy builds an HttpProxy with just enough wired up to
// exercise enforceAccessControls: a real database for the rate limiter, a
// real blacklist, and a config whose blacklist mode the test sets.
func accessControlProxy(t *testing.T, blacklistMode string) *HttpProxy {
	t.Helper()
	proxy, _ := newTestHttpProxy(t)
	proxy.cfg.SetBlacklistMode(blacklistMode)
	return proxy
}

func accessControlRequest(remoteAddr string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://login.example.com/", nil)
	request.RemoteAddr = remoteAddr
	request.URL = &url.URL{Scheme: "https", Path: "/"}
	return request
}

func TestAccessControlsAllowAnOrdinaryRequest(t *testing.T) {
	proxy := accessControlProxy(t, "off")

	fromIP, denied := proxy.enforceAccessControls(accessControlRequest("198.51.100.10:44321"))
	if denied != nil {
		t.Fatalf("an ordinary request was denied with HTTP %d", denied.StatusCode)
	}
	if fromIP != "198.51.100.10" {
		t.Errorf("client IP = %q, want the address with the port stripped", fromIP)
	}
}

// TestAccessControlsIgnoreProxyHeadersByDefault is the security property: a
// client that supplies its own X-Forwarded-For must not be able to choose the
// address rate limiting and blacklisting are applied to.
func TestAccessControlsIgnoreProxyHeadersByDefault(t *testing.T) {
	proxy := accessControlProxy(t, "off")

	request := accessControlRequest("198.51.100.10:44321")
	request.Header.Set("X-Forwarded-For", "203.0.113.99")

	fromIP, _ := proxy.enforceAccessControls(request)
	if fromIP != "198.51.100.10" {
		t.Errorf("client IP = %q, want the connection's own address; a client must not choose its identity", fromIP)
	}
}

func TestAccessControlsHonorProxyHeadersWhenTrusted(t *testing.T) {
	proxy := accessControlProxy(t, "off")
	proxy.SetTrustProxyHeaders(true)

	request := accessControlRequest("198.51.100.10:44321")
	request.Header.Set("X-Forwarded-For", "203.0.113.99")

	fromIP, _ := proxy.enforceAccessControls(request)
	if fromIP != "203.0.113.99" {
		t.Errorf("client IP = %q, want the forwarded address when trust is enabled", fromIP)
	}
}

func TestAccessControlsBlockABlacklistedAddress(t *testing.T) {
	proxy := accessControlProxy(t, "unauth")
	if err := proxy.bl.AddIP("198.51.100.10"); err != nil {
		t.Fatal(err)
	}

	_, denied := proxy.enforceAccessControls(accessControlRequest("198.51.100.10:44321"))
	if denied == nil {
		t.Fatal("a blacklisted address was allowed through")
	}
}

// TestBlacklistModeAllRecordsAndBlocks covers the mode that blocks everything
// not explicitly whitelisted, and records the address so the block survives a
// restart. This is the path a spoofable client IP would have poisoned.
func TestBlacklistModeAllRecordsAndBlocks(t *testing.T) {
	proxy := accessControlProxy(t, "all")

	_, denied := proxy.enforceAccessControls(accessControlRequest("198.51.100.77:44321"))
	if denied == nil {
		t.Fatal("blacklist_mode=all allowed an unlisted address through")
	}
	if !proxy.bl.IsBlacklisted("198.51.100.77") {
		t.Error("blacklist_mode=all did not record the address it blocked")
	}
}

func TestBlacklistModeOffSkipsTheBlacklistEntirely(t *testing.T) {
	proxy := accessControlProxy(t, "off")
	if err := proxy.bl.AddIP("198.51.100.10"); err != nil {
		t.Fatal(err)
	}

	_, denied := proxy.enforceAccessControls(accessControlRequest("198.51.100.10:44321"))
	if denied != nil {
		t.Fatalf("blacklist_mode=off still blocked a listed address (HTTP %d)", denied.StatusCode)
	}
}

// TestRateLimitDeniesOnceTheWindowIsExhausted covers the first gate, which
// runs before the blacklist and returns 429 rather than the blacklist's own
// block response.
func TestRateLimitDeniesOnceTheWindowIsExhausted(t *testing.T) {
	proxy := accessControlProxy(t, "off")
	proxy.rateLimit = 2

	request := accessControlRequest("198.51.100.20:44321")
	for attempt := 1; attempt <= 2; attempt++ {
		if _, denied := proxy.enforceAccessControls(request); denied != nil {
			t.Fatalf("request %d was throttled inside the limit", attempt)
		}
	}
	_, denied := proxy.enforceAccessControls(request)
	if denied == nil {
		t.Fatal("the request past the limit was not throttled")
	}
	if denied.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", denied.StatusCode, http.StatusTooManyRequests)
	}
}
