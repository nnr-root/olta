package asncloak

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestLocalProviderLookup(t *testing.T) {
	provider, err := NewLocalProvider([]Entry{
		{CIDR: "203.0.113.0/24", ASN: 64500, Organization: "example cloud", Category: CategoryCloud},
		{CIDR: "203.0.113.128/25", ASN: 64501, Organization: "example crawler", Category: CategorySecurityCrawler},
		{CIDR: "2001:db8:1234::/48", ASN: 64502, Organization: "example ipv6 cloud", Category: CategoryCloud},
	})
	if err != nil {
		t.Fatalf("NewLocalProvider() error = %v", err)
	}

	tests := []struct {
		name         string
		address      string
		wantMatch    bool
		wantProvider string
	}{
		{name: "IPv4 match", address: "203.0.113.10", wantMatch: true, wantProvider: "example cloud"},
		{name: "longest prefix", address: "203.0.113.200", wantMatch: true, wantProvider: "example crawler"},
		{name: "IPv6 match", address: "2001:db8:1234::42", wantMatch: true, wantProvider: "example ipv6 cloud"},
		{name: "IPv4 miss", address: "198.51.100.1", wantMatch: false},
		{name: "IPv6 miss", address: "2001:db8:5678::1", wantMatch: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			network, matched := provider.Lookup(netip.MustParseAddr(test.address))
			if matched != test.wantMatch {
				t.Fatalf("Lookup(%s) matched = %v, want %v", test.address, matched, test.wantMatch)
			}
			if network.Organization != test.wantProvider {
				t.Errorf("Lookup(%s) organization = %q, want %q", test.address, network.Organization, test.wantProvider)
			}
		})
	}
}

func TestLocalProviderRejectsInvalidCIDR(t *testing.T) {
	if _, err := NewLocalProvider([]Entry{{CIDR: "not-a-cidr"}}); err == nil {
		t.Fatal("NewLocalProvider() error = nil, want invalid CIDR error")
	}
}

func TestEvaluateUserAgentAndHeaderRules(t *testing.T) {
	provider, err := NewLocalProvider(nil)
	if err != nil {
		t.Fatalf("NewLocalProvider() error = %v", err)
	}
	middleware, err := New(Config{
		Enabled:            true,
		Provider:           provider,
		Action:             ActionBlock,
		InspectHeaders:     true,
		RequiredHeaders:    []string{"Accept", "Accept-Language", "Accept-Encoding"},
		MissingHeaderLimit: 3,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		userAgent  string
		headers    map[string]string
		wantMatch  bool
		wantRule   string
		protoMajor int
		protoMinor int
	}{
		{
			name:      "headless user agent",
			userAgent: "Mozilla/5.0 HeadlessChrome/123.0",
			headers:   browserHeaders(),
			wantMatch: true,
			wantRule:  "user-agent",
		},
		{
			name:      "security crawler user agent",
			userAgent: "Proofpoint URL Defense",
			headers:   browserHeaders(),
			wantMatch: true,
			wantRule:  "user-agent",
		},
		{
			name:      "missing automation headers",
			userAgent: "Mozilla/5.0 Chrome/123.0",
			wantMatch: true,
			wantRule:  "headers",
		},
		{
			name:       "legacy protocol with browser user agent",
			userAgent:  "Mozilla/5.0 Firefox/123.0",
			headers:    browserHeaders(),
			wantMatch:  true,
			wantRule:   "protocol",
			protoMajor: 1,
			protoMinor: 0,
		},
		{
			name:      "legitimate browser",
			userAgent: "Mozilla/5.0 Chrome/123.0 Safari/537.36",
			headers:   browserHeaders(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
			request.RemoteAddr = "198.51.100.20:54321"
			request.Header.Set("User-Agent", test.userAgent)
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			if test.protoMajor != 0 {
				request.ProtoMajor = test.protoMajor
				request.ProtoMinor = test.protoMinor
			}

			match, matched := middleware.Evaluate(request)
			if matched != test.wantMatch {
				t.Fatalf("Evaluate() matched = %v, want %v (match: %+v)", matched, test.wantMatch, match)
			}
			if match.Rule != test.wantRule {
				t.Errorf("Evaluate() rule = %q, want %q", match.Rule, test.wantRule)
			}
		})
	}
}

func TestEvaluateNetwork(t *testing.T) {
	provider, err := NewLocalProvider([]Entry{{
		CIDR:         "192.0.2.0/24",
		ASN:          64500,
		Organization: "scanner network",
		Category:     CategorySecurityCrawler,
	}})
	if err != nil {
		t.Fatalf("NewLocalProvider() error = %v", err)
	}
	middleware, err := New(Config{Enabled: true, Provider: provider, Action: ActionBlock})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	request.RemoteAddr = "192.0.2.44:1234"
	match, matched := middleware.Evaluate(request)
	if !matched {
		t.Fatal("Evaluate() matched = false, want true")
	}
	if match.Rule != "network" || match.Network == nil || match.Network.ASN != 64500 {
		t.Fatalf("Evaluate() match = %+v, want network ASN 64500", match)
	}
}

func TestEvaluateUsesTrustedForwardedClientIP(t *testing.T) {
	provider, err := NewLocalProvider([]Entry{{
		CIDR:         "192.0.2.0/24",
		Organization: "cloud reverse proxy",
		Category:     CategoryCloud,
	}})
	if err != nil {
		t.Fatalf("NewLocalProvider() error = %v", err)
	}
	middleware, err := New(Config{
		Enabled:           true,
		Provider:          provider,
		Action:            ActionBlock,
		TrustProxyHeaders: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	request.RemoteAddr = "192.0.2.10:443"
	request.Header.Set("X-Forwarded-For", "198.51.100.25, 192.0.2.10")
	if match, matched := middleware.Evaluate(request); matched {
		t.Fatalf("Evaluate() matched trusted proxy instead of forwarded client: %+v", match)
	}
}

func TestRedirectHandler(t *testing.T) {
	provider, err := NewLocalProvider([]Entry{{CIDR: "192.0.2.0/24", Organization: "scanner network"}})
	if err != nil {
		t.Fatalf("NewLocalProvider() error = %v", err)
	}
	middleware, err := New(Config{
		Enabled:     true,
		Provider:    provider,
		Action:      ActionRedirect,
		RedirectURL: "https://safe.example/",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	downstreamCalls := 0
	downstream := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		downstreamCalls++
		writer.WriteHeader(http.StatusNoContent)
	})
	handler := middleware.Handler(downstream)

	request := httptest.NewRequest(http.MethodGet, "https://example.test/lure", nil)
	request.RemoteAddr = "192.0.2.10:44321"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusFound)
	}
	if location := recorder.Header().Get("Location"); location != "https://safe.example/" {
		t.Errorf("Location = %q, want %q", location, "https://safe.example/")
	}
	if downstreamCalls != 0 {
		t.Errorf("downstream calls = %d, want 0", downstreamCalls)
	}
}

func TestLegitimateRequestPassesThrough(t *testing.T) {
	provider, err := NewLocalProvider([]Entry{{CIDR: "192.0.2.0/24", Organization: "scanner network"}})
	if err != nil {
		t.Fatalf("NewLocalProvider() error = %v", err)
	}
	middleware, err := New(Config{
		Enabled:        true,
		Provider:       provider,
		Action:         ActionBlock,
		InspectHeaders: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	downstream := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	request.RemoteAddr = "198.51.100.10:1234"
	request.Header.Set("User-Agent", "Mozilla/5.0 Chrome/123.0 Safari/537.36")
	for name, value := range browserHeaders() {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	middleware.Handler(downstream).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func browserHeaders() map[string]string {
	return map[string]string{
		"Accept":          "text/html,application/xhtml+xml",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
	}
}

func BenchmarkLocalProviderLookup(b *testing.B) {
	provider, err := NewDefaultProvider()
	if err != nil {
		b.Fatalf("NewDefaultProvider() error = %v", err)
	}
	address := netip.MustParseAddr("206.189.10.20")
	b.ReportAllocs()
	for range b.N {
		_, _ = provider.Lookup(address)
	}
}
