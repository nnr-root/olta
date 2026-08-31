package core

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// stripResponseSecurityHeaders / responseSecurityHeaders
// ---------------------------------------------------------------------------

func TestStripResponseSecurityHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("Content-Security-Policy-Report-Only", "default-src 'self'")
	h.Set("Strict-Transport-Security", "max-age=63072000")
	h.Set("X-XSS-Protection", "1; mode=block")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Type", "text/html")

	stripResponseSecurityHeaders(h, responseSecurityHeaders)

	for _, hdr := range responseSecurityHeaders {
		if h.Get(hdr) != "" {
			t.Errorf("expected %s to be stripped, still present: %q", hdr, h.Get(hdr))
		}
	}
	if h.Get("Content-Type") != "text/html" {
		t.Errorf("unrelated header Content-Type was mutated: %q", h.Get("Content-Type"))
	}
}

// ---------------------------------------------------------------------------
// rewriteAccessControlAllowOrigin
// ---------------------------------------------------------------------------

func TestRewriteAccessControlAllowOrigin(t *testing.T) {
	replaceFn := func(host string) (string, bool) {
		if host == "orig.example.com" {
			return "phished.evil.test", true
		}
		return host, false
	}

	tests := []struct {
		name        string
		allowOrigin string
		wantOrigin  string
		wantCreds   string
		wantErr     bool
	}{
		{
			name:        "empty header is left alone",
			allowOrigin: "",
			wantOrigin:  "",
			wantCreds:   "",
			wantErr:     false,
		},
		{
			name:        "wildcard is left alone",
			allowOrigin: "*",
			wantOrigin:  "*",
			wantCreds:   "",
			wantErr:     false,
		},
		{
			name:        "known origin is rewritten and credentials allowed",
			allowOrigin: "https://orig.example.com",
			wantOrigin:  "https://phished.evil.test",
			wantCreds:   "true",
			wantErr:     false,
		},
		{
			name:        "unknown origin host is left as-is but credentials still allowed",
			allowOrigin: "https://unrelated.example.com",
			wantOrigin:  "https://unrelated.example.com",
			wantCreds:   "true",
			wantErr:     false,
		},
		{
			name:        "unparsable origin still gets credentials header set",
			allowOrigin: "://not a url",
			wantOrigin:  "://not a url",
			wantCreds:   "true",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.allowOrigin != "" {
				h.Set("Access-Control-Allow-Origin", tt.allowOrigin)
			}
			err := rewriteAccessControlAllowOrigin(h, replaceFn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got := h.Get("Access-Control-Allow-Origin"); got != tt.wantOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tt.wantOrigin)
			}
			if got := h.Get("Access-Control-Allow-Credentials"); got != tt.wantCreds {
				t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, tt.wantCreds)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// rewriteLocationURL
// ---------------------------------------------------------------------------

func TestRewriteLocationURL(t *testing.T) {
	replaceFn := func(host string) (string, bool) {
		if host == "orig.example.com" {
			return "phished.evil.test", true
		}
		return host, false
	}

	t.Run("nil URL is a no-op", func(t *testing.T) {
		u, changed := rewriteLocationURL(nil, replaceFn)
		if changed {
			t.Fatalf("expected no change for a nil URL")
		}
		if u != nil {
			t.Fatalf("expected nil URL to stay nil")
		}
	})

	t.Run("known host is rewritten in place", func(t *testing.T) {
		u, _ := url.Parse("https://orig.example.com/path?x=1")
		got, changed := rewriteLocationURL(u, replaceFn)
		if !changed {
			t.Fatalf("expected a rewrite to be applied")
		}
		if got.Host != "phished.evil.test" {
			t.Errorf("Host = %q, want phished.evil.test", got.Host)
		}
		if got.String() != "https://phished.evil.test/path?x=1" {
			t.Errorf("String() = %q", got.String())
		}
	})

	t.Run("unknown host is left untouched", func(t *testing.T) {
		u, _ := url.Parse("https://unrelated.example.com/path")
		got, changed := rewriteLocationURL(u, replaceFn)
		if changed {
			t.Fatalf("expected no rewrite for an unrelated host")
		}
		if got.Host != "unrelated.example.com" {
			t.Errorf("Host = %q, want unchanged", got.Host)
		}
	})
}

// ---------------------------------------------------------------------------
// normalizeResponseCookie
// ---------------------------------------------------------------------------

func TestNormalizeResponseCookie(t *testing.T) {
	t.Run("secure cookie gets SameSite=None", func(t *testing.T) {
		ck := &http.Cookie{Name: "sid", Value: "abc", Secure: true}
		normalizeResponseCookie(ck)
		if ck.SameSite != http.SameSiteNoneMode {
			t.Errorf("SameSite = %v, want SameSiteNoneMode", ck.SameSite)
		}
	})

	t.Run("non-secure cookie SameSite is left alone", func(t *testing.T) {
		ck := &http.Cookie{Name: "sid", Value: "abc", Secure: false}
		normalizeResponseCookie(ck)
		if ck.SameSite != http.SameSite(0) {
			t.Errorf("SameSite = %v, want untouched zero value", ck.SameSite)
		}
	})

	t.Run("RawExpires parsed via RFC850 fallback", func(t *testing.T) {
		ck := &http.Cookie{Name: "sid", Value: "abc", RawExpires: "Sunday, 06-Nov-94 08:49:37 GMT"}
		normalizeResponseCookie(ck)
		want, _ := time.Parse(time.RFC850, ck.RawExpires)
		if !ck.Expires.Equal(want) {
			t.Errorf("Expires = %v, want %v", ck.Expires, want)
		}
	})

	t.Run("RawExpires parsed via ANSIC fallback", func(t *testing.T) {
		ck := &http.Cookie{Name: "sid", Value: "abc", RawExpires: "Sun Nov  6 08:49:37 1994"}
		normalizeResponseCookie(ck)
		want, _ := time.Parse(time.ANSIC, ck.RawExpires)
		if !ck.Expires.Equal(want) {
			t.Errorf("Expires = %v, want %v", ck.Expires, want)
		}
	})

	t.Run("RawExpires parsed via bespoke layout fallback", func(t *testing.T) {
		ck := &http.Cookie{Name: "sid", Value: "abc", RawExpires: "Sunday, 06-Nov-1994 08:49:37 GMT"}
		normalizeResponseCookie(ck)
		want, _ := time.Parse("Monday, 02-Jan-2006 15:04:05 MST", ck.RawExpires)
		if !ck.Expires.Equal(want) {
			t.Errorf("Expires = %v, want %v", ck.Expires, want)
		}
	})

	t.Run("all fallbacks fail leaves the zero-value best-effort parse", func(t *testing.T) {
		ck := &http.Cookie{Name: "sid", Value: "abc", RawExpires: "not-a-date-at-all"}
		normalizeResponseCookie(ck)
		if !ck.Expires.IsZero() {
			t.Errorf("Expires = %v, want zero value for an unparsable RawExpires", ck.Expires)
		}
	})

	t.Run("Expires already set is not overwritten", func(t *testing.T) {
		already := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		ck := &http.Cookie{Name: "sid", Value: "abc", RawExpires: "Sunday, 06-Nov-94 08:49:37 GMT", Expires: already}
		normalizeResponseCookie(ck)
		if !ck.Expires.Equal(already) {
			t.Errorf("Expires = %v, want untouched %v", ck.Expires, already)
		}
	})
}

// ---------------------------------------------------------------------------
// expandSubFilterPattern / expandSubFilterReplacement / applySubFilterRegex
// ---------------------------------------------------------------------------

func TestExpandSubFilterPattern(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		subdomain  string
		domain     string
		baseDomain string
		want       string
	}{
		{
			name:       "hostname macro is regex-escaped",
			pattern:    `https?://{hostname}/`,
			subdomain:  "login",
			domain:     "example.com",
			baseDomain: "phish.test",
			want:       `https?://login\.example\.com/`,
		},
		{
			name:       "subdomain and domain macros",
			pattern:    `{subdomain}\.{domain}`,
			subdomain:  "www",
			domain:     "example.com",
			baseDomain: "phish.test",
			want:       `www\.example\.com`,
		},
		{
			name:       "basedomain macro",
			pattern:    `{basedomain}`,
			subdomain:  "",
			domain:     "example.com",
			baseDomain: "phish.test",
			want:       `phish\.test`,
		},
		{
			name:       "hostname_regexp double-escapes",
			pattern:    `{hostname_regexp}`,
			subdomain:  "a",
			domain:     "b.com",
			baseDomain: "phish.test",
			want:       regexp.QuoteMeta(regexp.QuoteMeta("a.b.com")),
		},
		{
			name:       "no macros present is a no-op",
			pattern:    `literal-pattern-no-macros`,
			subdomain:  "a",
			domain:     "b.com",
			baseDomain: "phish.test",
			want:       `literal-pattern-no-macros`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandSubFilterPattern(tt.pattern, tt.subdomain, tt.domain, tt.baseDomain)
			if got != tt.want {
				t.Errorf("expandSubFilterPattern() = %q, want %q", got, tt.want)
			}
			// the expanded pattern must always compile - that's the whole point
			// of the macro expansion feeding straight into regexp.Compile.
			if _, err := regexp.Compile(got); err != nil {
				t.Errorf("expanded pattern does not compile: %v", err)
			}
		})
	}
}

func TestExpandSubFilterReplacement(t *testing.T) {
	tests := []struct {
		name          string
		replacement   string
		subdomain     string
		domain        string
		baseDomain    string
		phishHostname string
		phishSub      string
		phishDomain   string
		phishDomainOK bool
		want          string
	}{
		{
			name:          "hostname macro uses the phished hostname verbatim",
			replacement:   `{hostname}`,
			subdomain:     "login",
			domain:        "example.com",
			baseDomain:    "phish.test",
			phishHostname: "login.phish.test",
			phishSub:      "login",
			want:          "login.phish.test",
		},
		{
			name:        "orig_hostname and orig_domain are dot-obfuscated",
			replacement: `{orig_hostname} {orig_domain}`,
			subdomain:   "login",
			domain:      "example.com",
			baseDomain:  "phish.test",
			want:        obfuscateDots("login.example.com") + " " + obfuscateDots("example.com"),
		},
		{
			name:          "domain macro only expands when phishDomainOK",
			replacement:   `{domain}`,
			domain:        "example.com",
			phishDomain:   "phish.test",
			phishDomainOK: true,
			want:          "phish.test",
		},
		{
			name:          "domain macro left untouched when phishDomainOK is false",
			replacement:   `{domain}`,
			domain:        "example.com",
			phishDomain:   "phish.test",
			phishDomainOK: false,
			want:          "{domain}",
		},
		{
			name:        "no macros present is a no-op",
			replacement: `no-macros-here`,
			want:        `no-macros-here`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandSubFilterReplacement(tt.replacement, tt.subdomain, tt.domain, tt.baseDomain, tt.phishHostname, tt.phishSub, tt.phishDomain, tt.phishDomainOK)
			if got != tt.want {
				t.Errorf("expandSubFilterReplacement() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplySubFilterRegex(t *testing.T) {
	t.Run("single match is replaced", func(t *testing.T) {
		re := regexp.MustCompile(`example\.com`)
		got := applySubFilterRegex([]byte(`visit https://example.com/login`), re, "phish.test")
		want := `visit https://phish.test/login`
		if string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("multiple matches in one body are all replaced", func(t *testing.T) {
		re := regexp.MustCompile(`example\.com`)
		body := []byte(`https://example.com/a and https://example.com/b and mailto:x@example.com`)
		got := applySubFilterRegex(body, re, "phish.test")
		want := `https://phish.test/a and https://phish.test/b and mailto:x@phish.test`
		if string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("pattern matching nothing returns body unchanged", func(t *testing.T) {
		re := regexp.MustCompile(`not-present-anywhere\.test`)
		body := []byte(`<html><body>hello world</body></html>`)
		got := applySubFilterRegex(body, re, "phish.test")
		if string(got) != string(body) {
			t.Errorf("got %q, want unchanged %q", got, body)
		}
	})

	t.Run("empty body is a no-op", func(t *testing.T) {
		re := regexp.MustCompile(`example\.com`)
		got := applySubFilterRegex([]byte{}, re, "phish.test")
		if len(got) != 0 {
			t.Errorf("got %q, want empty", got)
		}
	})
}

// TestSubFilterPipeline_MultipleFiltersOnOneBody exercises the full
// expand-then-apply pipeline the way the OnResponse closure drives it,
// applying two independent sub_filters to the same body in sequence, the
// way multiple configured sub_filters for the same phishlet/hostname are
// applied one after another.
func TestSubFilterPipeline_MultipleFiltersOnOneBody(t *testing.T) {
	body := []byte(`<a href="https://login.example.com/sso">Sign in</a><script src="https://static.example.com/app.js"></script>`)

	// filter 1: rewrite the login subdomain
	pattern1 := expandSubFilterPattern(`{hostname}`, "login", "example.com", "phish.test")
	replace1 := expandSubFilterReplacement(`{hostname}`, "login", "example.com", "phish.test", "login.phish.test", "login", "", false)
	re1, err := regexp.Compile(pattern1)
	if err != nil {
		t.Fatalf("filter 1 pattern failed to compile: %v", err)
	}
	body = applySubFilterRegex(body, re1, replace1)

	// filter 2: rewrite the static-asset subdomain
	pattern2 := expandSubFilterPattern(`{hostname}`, "static", "example.com", "phish.test")
	replace2 := expandSubFilterReplacement(`{hostname}`, "static", "example.com", "phish.test", "static.phish.test", "static", "", false)
	re2, err := regexp.Compile(pattern2)
	if err != nil {
		t.Fatalf("filter 2 pattern failed to compile: %v", err)
	}
	body = applySubFilterRegex(body, re2, replace2)

	want := `<a href="https://login.phish.test/sso">Sign in</a><script src="https://static.phish.test/app.js"></script>`
	if string(body) != want {
		t.Errorf("got %q, want %q", body, want)
	}
}

// ---------------------------------------------------------------------------
// setModifiedBodyFraming
// ---------------------------------------------------------------------------

func TestSetModifiedBodyFraming(t *testing.T) {
	resp := &http.Response{
		Header:           http.Header{},
		TransferEncoding: []string{"chunked"},
	}
	resp.Header.Set("ETag", `"abc123"`)
	resp.Header.Set("Content-MD5", "deadbeef")
	resp.Header.Set("Transfer-Encoding", "chunked")
	resp.Header.Set("Content-Length", "9999")

	body := []byte("new shorter body")
	setModifiedBodyFraming(resp, body)

	if resp.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(body))
	}
	if got := resp.Header.Get("Content-Length"); got != "16" {
		t.Errorf("Content-Length header = %q, want %q", got, "16")
	}
	if resp.Header.Get("ETag") != "" {
		t.Errorf("ETag should be removed, got %q", resp.Header.Get("ETag"))
	}
	if resp.Header.Get("Content-MD5") != "" {
		t.Errorf("Content-MD5 should be removed, got %q", resp.Header.Get("Content-MD5"))
	}
	if resp.Header.Get("Transfer-Encoding") != "" {
		t.Errorf("Transfer-Encoding header should be removed, got %q", resp.Header.Get("Transfer-Encoding"))
	}
	if resp.TransferEncoding != nil {
		t.Errorf("TransferEncoding field should be nil, got %v", resp.TransferEncoding)
	}
}

// ---------------------------------------------------------------------------
// encoding transformations: obfuscateDots / removeObfuscatedDots
// (shared.go - already pure/free functions, exercised here as part of the
// response body pipeline's encoding step for sub_filter's {orig_hostname}
// and {orig_domain} macros, and the always-on de-obfuscation pass over
// every response body.)
// ---------------------------------------------------------------------------

func TestObfuscateDots_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"simple hostname", "example.com"},
		{"multi-label hostname", "login.static.example.co.uk"},
		{"no dots", "localhost"},
		{"empty string", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obfuscated := obfuscateDots(tt.in)
			if strings.Contains(tt.in, ".") && strings.Contains(obfuscated, ".") {
				t.Errorf("obfuscateDots(%q) = %q, still contains a literal dot", tt.in, obfuscated)
			}
			roundTripped := removeObfuscatedDots(obfuscated)
			if roundTripped != tt.in {
				t.Errorf("round trip = %q, want %q", roundTripped, tt.in)
			}
		})
	}
}

func TestRemoveObfuscatedDots_LeavesUnrelatedTextAlone(t *testing.T) {
	in := "plain text with no markers and a literal . dot"
	got := removeObfuscatedDots(in)
	if got != in {
		t.Errorf("got %q, want unchanged %q", got, in)
	}
}
