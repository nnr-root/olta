package e2e

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/s4l1hs/olta/pkg/proxy/middleware/asncloak"
	"github.com/s4l1hs/olta/pkg/proxy/middleware/jsinspect"
)

// runGatewayIngestion drives real TLS/TCP traffic through a Start()-ed
// HttpProxy listener (stage b), and, over the same connection pipeline in
// their real production registration order, the JS environment inspector
// and the ASN/CIDR cloaker (stage c). See gateway_test.go's package doc for
// exactly what is and is not exercised end-to-end here, and why.
func runGatewayIngestion(t *testing.T) {
	t.Helper()

	fixture := newGatewayFixture(t,
		asncloak.Config{
			Enabled:           true,
			Provider:          fixtureCloudProvider(t),
			Action:            asncloak.ActionBlock,
			BlockStatus:       http.StatusForbidden,
			InspectHeaders:    true,
			TrustProxyHeaders: true,
		},
		jsinspect.Config{
			Enabled:  true,
			Endpoint: jsInspectEndpoint,
			Action:   jsinspect.ActionBlock,
		},
	)

	// A normal-looking browser request whose path is not the lure's
	// configured path matches neither the cloaker nor the JS-inspect
	// endpoint, so it runs the entire real goproxy request pipeline -
	// blacklist/rate-limit checks, phishlet/lure lookup, session-cookie
	// lookup - and lands on http_proxy.go's "unauthorized request"
	// fallback (blockRequest), which this fixture configured to answer 403
	// with an empty body (see newGatewayFixture's SetUnauthUrl("") call).
	// The exact status code matters less here than what it proves: the
	// listener bound, the SNI-routed TLS MITM handshake completed against a
	// CertDb-issued certificate, and the decrypted HTTP request was parsed
	// and classified for real, all the way to a deterministic response
	// written back over that same TLS connection.
	t.Run("TLSHandshakeAndPipelineCompletes", func(t *testing.T) {
		req := fixture.newRequest(t, http.MethodGet, "/unmatched-path", nil)
		setBrowserHeaders(req)
		resp, err := fixture.client().Do(req)
		if err != nil {
			t.Fatalf("Do() error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d (unauthorized-request fallback)", resp.StatusCode, http.StatusForbidden)
		}
	})

	// developer-mode TLSConfigFromCA never sets tls.Config.NextProtos (see
	// gateway_test.go's package doc, point 3), so even a client that offers
	// "h2" in its ClientHello must never have it selected over ALPN.
	t.Run("HTTP2NeverNegotiatedOverTheMITMListener", func(t *testing.T) {
		conn, err := tls.Dial("tcp", fixture.addr, &tls.Config{
			ServerName:         fixture.tlsHost,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err != nil {
			t.Fatalf("tls.Dial() error: %v", err)
		}
		defer conn.Close()
		if negotiated := conn.ConnectionState().NegotiatedProtocol; negotiated == "h2" {
			t.Fatalf("NegotiatedProtocol = %q, the live MITM listener must never select h2", negotiated)
		}
	})

	t.Run("JSInspectAllowsAConsistentAssertion", func(t *testing.T) {
		const assertion = `{"version":1,"webdriver":false,"headless":false,"phantom":false,"renderer":"ANGLE (Apple, Apple M1, OpenGL 4.1)","software_renderer":false,"canvas_consistent":true}`
		req := fixture.newRequest(t, http.MethodPost, jsInspectEndpoint, []byte(assertion))
		setBrowserHeaders(req)
		req.Header.Set("Content-Type", "application/json")
		resp, err := fixture.client().Do(req)
		if err != nil {
			t.Fatalf("Do() error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want %d (allowed)", resp.StatusCode, http.StatusNoContent)
		}
	})

	t.Run("JSInspectBlocksAHeadlessAssertion", func(t *testing.T) {
		const assertion = `{"version":1,"webdriver":true,"headless":true,"phantom":false,"renderer":"","software_renderer":false,"canvas_consistent":true}`
		req := fixture.newRequest(t, http.MethodPost, jsInspectEndpoint, []byte(assertion))
		setBrowserHeaders(req)
		req.Header.Set("Content-Type", "application/json")
		resp, err := fixture.client().Do(req)
		if err != nil {
			t.Fatalf("Do() error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d (blocked)", resp.StatusCode, http.StatusForbidden)
		}
	})

	t.Run("AsnCloakBlocksASuspiciousUserAgent", func(t *testing.T) {
		req := fixture.newRequest(t, http.MethodGet, "/unmatched-path", nil)
		setBrowserHeaders(req)
		req.Header.Set("User-Agent", "curl/8.4.0") // matches asncloak's defaultSuspiciousUserAgents.
		resp, err := fixture.client().Do(req)
		if err != nil {
			t.Fatalf("Do() error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d (blocked by user-agent rule)", resp.StatusCode, http.StatusForbidden)
		}
	})

	t.Run("AsnCloakBlocksAFixtureCloudNetwork", func(t *testing.T) {
		req := fixture.newRequest(t, http.MethodGet, "/unmatched-path", nil)
		setBrowserHeaders(req)
		req.Header.Set("X-Forwarded-For", cloakScannerIP) // matches fixtureCloudProvider's one CIDR entry.
		resp, err := fixture.client().Do(req)
		if err != nil {
			t.Fatalf("Do() error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d (blocked by fixture network rule)", resp.StatusCode, http.StatusForbidden)
		}
	})
}

// setBrowserHeaders fills in the three headers asncloak's default
// RequiredHeaders check looks for and a normal desktop-browser User-Agent,
// so a request is unambiguously "allowed" by the cloaker rather than
// incidentally matching the missing-headers rule.
func setBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
}
