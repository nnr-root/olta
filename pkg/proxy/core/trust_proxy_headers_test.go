package core

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestClientIPResolution_TrustDisabled_RateLimitsRealRemoteAddr proves that
// when proxy-header trust is off (the default), the rate limiter keys on
// req.RemoteAddr and cannot be bypassed by rotating a client-controlled
// header such as X-Forwarded-For.
func TestClientIPResolution_TrustDisabled_RateLimitsRealRemoteAddr(t *testing.T) {
	cfg := newTestConfig(t)
	proxy, _ := newProxyWithConfig(t, cfg)
	proxy.rateLimit = 1
	proxy.rateWindow = time.Minute
	// trustProxyHeaders defaults to false: never set here.

	const realIP = "203.0.113.9"
	const spoofedIP = "198.51.100.250"

	// Exhaust the quota for realIP directly against the rate limiter, the
	// same store the request handler consults. No HTTP round trip involved.
	if allowed, err := proxy.db.AllowRequest(realIP, proxy.rateLimit, proxy.rateWindow); err != nil {
		t.Fatalf("AllowRequest() error: %v", err)
	} else if !allowed {
		t.Fatal("first AllowRequest() call unexpectedly throttled")
	}

	req := httptest.NewRequest(http.MethodGet, "https://unrelated.example/anything", nil)
	req.RemoteAddr = realIP + ":51234"
	// A spoofed, never-before-seen header IP: if the handler honored it
	// despite trust being disabled, this request would resolve to a fresh
	// address with quota remaining and would NOT be throttled.
	req.Header.Set("X-Forwarded-For", spoofedIP)

	w := httptest.NewRecorder()
	proxy.Proxy.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d (rate limit must key on RemoteAddr %s, not the spoofed header %s)", w.Code, http.StatusTooManyRequests, realIP, spoofedIP)
	}
}

// TestClientIPResolution_TrustDisabled_BlacklistCannotBePoisoned proves that
// with proxy-header trust off, a client cannot write an arbitrary
// attacker-chosen address into the persistent blacklist by supplying it in
// a header; blacklist_mode=all can only ever blacklist req.RemoteAddr.
func TestClientIPResolution_TrustDisabled_BlacklistCannotBePoisoned(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.SetBlacklistMode("all")
	proxy, _ := newProxyWithConfig(t, cfg)
	// trustProxyHeaders defaults to false: never set here.

	const realIP = "203.0.113.9"
	const spoofedIP = "198.51.100.250"

	req := httptest.NewRequest(http.MethodGet, "https://unrelated.example/anything", nil)
	req.RemoteAddr = realIP + ":51234"
	req.Header.Set("X-Forwarded-For", spoofedIP)

	w := httptest.NewRecorder()
	proxy.Proxy.ServeHTTP(w, req)

	if !proxy.bl.IsBlacklisted(realIP) {
		t.Errorf("blacklist does not contain the real RemoteAddr %s", realIP)
	}
	if proxy.bl.IsBlacklisted(spoofedIP) {
		t.Fatalf("blacklist was poisoned with the client-supplied header value %s; AddIP must never see a header-supplied address while trust is disabled", spoofedIP)
	}
}

// TestClientIPResolution_TrustEnabled_HonorsForwardedHeader proves that once
// proxy-header trust is explicitly enabled (mirroring
// -cloaker-trust-proxy-headers), the resolved client IP follows the header,
// matching asncloak's own precedence so the two subsystems cannot disagree
// about who the client is.
func TestClientIPResolution_TrustEnabled_HonorsForwardedHeader(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.SetBlacklistMode("all")
	proxy, _ := newProxyWithConfig(t, cfg)
	proxy.SetTrustProxyHeaders(true)

	const realIP = "203.0.113.9"
	const forwardedIP = "198.51.100.250"

	req := httptest.NewRequest(http.MethodGet, "https://unrelated.example/anything", nil)
	req.RemoteAddr = realIP + ":51234"
	req.Header.Set("X-Forwarded-For", forwardedIP)

	w := httptest.NewRecorder()
	proxy.Proxy.ServeHTTP(w, req)

	if !proxy.bl.IsBlacklisted(forwardedIP) {
		t.Errorf("blacklist does not contain the forwarded header IP %s; trust-enabled resolution should honor X-Forwarded-For", forwardedIP)
	}
	if proxy.bl.IsBlacklisted(realIP) {
		t.Errorf("blacklist unexpectedly contains RemoteAddr %s once a valid forwarded header is trusted", realIP)
	}
}

// TestClientIPResolution_TrustEnabled_AllSixHeaders is a table-driven check,
// exercised through the real request-handling path (not just the resolver
// helper), that every header asncloak.ResolveClientIP documents as honored
// under trust actually reaches the blacklist write when trust is enabled.
func TestClientIPResolution_TrustEnabled_AllSixHeaders(t *testing.T) {
	headers := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Connecting-IP", "True-Client-IP", "Client-IP"}
	for _, header := range headers {
		t.Run(header, func(t *testing.T) {
			cfg := newTestConfig(t)
			cfg.SetBlacklistMode("all")
			proxy, _ := newProxyWithConfig(t, cfg)
			proxy.SetTrustProxyHeaders(true)

			const realIP = "203.0.113.9"
			const forwardedIP = "198.51.100.251"

			req := httptest.NewRequest(http.MethodGet, "https://unrelated.example/anything", nil)
			req.RemoteAddr = realIP + ":51234"
			req.Header.Set(header, forwardedIP)

			w := httptest.NewRecorder()
			proxy.Proxy.ServeHTTP(w, req)

			if !proxy.bl.IsBlacklisted(forwardedIP) {
				t.Errorf("header %s: blacklist does not contain %s", header, forwardedIP)
			}
			if proxy.bl.IsBlacklisted(realIP) {
				t.Errorf("header %s: blacklist unexpectedly contains RemoteAddr %s", header, realIP)
			}
		})
	}
}
