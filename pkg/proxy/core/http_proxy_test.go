package core

import (
	"bytes"
	"crypto/rc4"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/proxy/database"
	"github.com/s4l1hs/olta/pkg/proxy/log"
	"github.com/s4l1hs/olta/pkg/proxy/middleware/asncloak"
	"github.com/s4l1hs/olta/pkg/proxy/middleware/jsinspect"
)

// stubCampaignEventSink is a hand-rolled CampaignEventSink. CampaignEventSink
// is already an interface at the proxy boundary (see http_proxy.go), so this
// stub requires no production change - it exists purely to let tests observe
// what the proxy would have reported to the campaign layer.
type stubCampaignEventSink struct {
	mu sync.Mutex

	emailOpenedCalls    int
	clickedLinkCalls    int
	submittedDataCalls  int
	capturedCookieCalls int
	capturedOtherCalls  int

	lastRID     string
	lastBrowser map[string]string
}

func (s *stubCampaignEventSink) HandleEmailOpened(rid string, browser map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailOpenedCalls++
	s.lastRID = rid
	s.lastBrowser = browser
	return nil
}

func (s *stubCampaignEventSink) HandleClickedLink(rid string, browser map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clickedLinkCalls++
	s.lastRID = rid
	s.lastBrowser = browser
	return nil
}

func (s *stubCampaignEventSink) HandleSubmittedData(rid, username, password string, browser map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.submittedDataCalls++
	s.lastRID = rid
	return nil
}

func (s *stubCampaignEventSink) HandleCapturedCookieSession(rid string, tokens map[string]map[string]*database.CookieToken, browser map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capturedCookieCalls++
	s.lastRID = rid
	return nil
}

func (s *stubCampaignEventSink) HandleCapturedOtherSession(rid string, tokens map[string]string, browser map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capturedOtherCalls++
	s.lastRID = rid
	return nil
}

// newTestConfig returns a Config rooted in a fresh t.TempDir(), so nothing
// touches a shared path and nothing is left behind.
func newTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg, err := NewConfig(t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewConfig() error: %v", err)
	}
	return cfg
}

// fixturePhishlet registers one enabled phishlet with a landing proxy host
// (orig "www.example.com" <-> phish "phish-corp.com") and a secondary
// subdomain proxy host (orig "sub.example.com" <-> phish
// "sub.phish-corp.com"). The domains deliberately end in ".com" so they also
// exercise patchUrls, which matches against a fixed real-TLD allowlist. It
// also registers a lure with a standalone custom hostname, exercising the
// lure-hostname branch that several *HttpProxy helpers fall back to.
func fixturePhishlet(cfg *Config) *Phishlet {
	pl := &Phishlet{
		Name: "testsite",
		cfg:  cfg,
		proxyHosts: []ProxyHost{
			{phish_subdomain: "", orig_subdomain: "www", domain: "example.com", handle_session: true, is_landing: true, auto_filter: true},
			{phish_subdomain: "sub", orig_subdomain: "sub", domain: "example.com", handle_session: true},
		},
	}
	cfg.phishlets[pl.Name] = pl
	cfg.phishletConfig[pl.Name] = &PhishletConfig{Hostname: "phish-corp.com", Enabled: true, Visible: true}
	cfg.lures = append(cfg.lures, &Lure{Hostname: "lure.corp-example.com", Phishlet: pl.Name, Path: "/go"})
	return pl
}

// newTestHttpProxy builds a fully wired *HttpProxy against a temp-directory
// backed Config, CertDb, and database.Database, and a stub CampaignEventSink.
// It never calls Start(), so nothing listens on a socket or touches the
// network.
func newTestHttpProxy(t *testing.T) (*HttpProxy, *stubCampaignEventSink) {
	t.Helper()
	dir := t.TempDir()

	cfg := newTestConfig(t)

	certDb, err := NewCertDb(filepath.Join(dir, "crt"), cfg, nil)
	if err != nil {
		t.Fatalf("NewCertDb() error: %v", err)
	}

	db, err := database.NewDatabase(filepath.Join(dir, "olta.db"))
	if err != nil {
		t.Fatalf("database.NewDatabase() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	blPath := filepath.Join(dir, "blacklist.txt")
	if err := SaveToFile(nil, blPath, 0600); err != nil {
		t.Fatalf("SaveToFile() error: %v", err)
	}
	bl, err := NewBlacklist(blPath, nil)
	if err != nil {
		t.Fatalf("NewBlacklist() error: %v", err)
	}

	sink := &stubCampaignEventSink{}

	proxy, err := NewHttpProxy("127.0.0.1", 0, cfg, certDb, db, sink, bl, true, false, 0, 0)
	if err != nil {
		t.Fatalf("NewHttpProxy() error: %v", err)
	}
	return proxy, sink
}

func TestNewHttpProxy_ConstructsWiredProxy(t *testing.T) {
	proxy, sink := newTestHttpProxy(t)
	if sink == nil {
		t.Fatal("stub sink was not returned")
	}
	if proxy.Proxy == nil {
		t.Error("Proxy (goproxy handler) was not set")
	}
	if proxy.Server == nil {
		t.Error("Server was not set")
	}
	if proxy.Server.Addr != "127.0.0.1:0" {
		t.Errorf("Server.Addr = %q, want 127.0.0.1:0", proxy.Server.Addr)
	}
	if proxy.sessions == nil || proxy.sids == nil {
		t.Error("session maps were not initialized")
	}
	if proxy.ip_whitelist == nil || proxy.ip_sids == nil {
		t.Error("whitelist maps were not initialized")
	}
	if len(proxy.cookieName) != 8 {
		t.Errorf("cookieName length = %d, want 8", len(proxy.cookieName))
	}
	if proxy.outboundTransport == nil {
		t.Error("outboundTransport was not initialized")
	}
	if proxy.isRunning {
		t.Error("a freshly constructed proxy must not be marked as running")
	}
	if proxy.cloaker != nil {
		t.Error("cloaker must be nil until ConfigureCloaker is called")
	}
	if proxy.jsInspector != nil {
		t.Error("jsInspector must be nil until ConfigureJSInspect is called")
	}
}

// TestNewHttpProxy_MisconfiguredUpstreamProxyDoesNotPanic exercises the
// graceful-degradation path: an invalid upstream proxy configuration is
// logged and disabled rather than surfaced as a NewHttpProxy error or a
// panic. NewHttpProxy itself has no other reachable validation-error path -
// the one explicit error return guards an internal type assertion that
// cannot fail through this constructor, so it is not exercised here (see
// report for detail).
func TestNewHttpProxy_MisconfiguredUpstreamProxyDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestConfig(t)
	cfg.proxyConfig.Enabled = true
	cfg.proxyConfig.Type = "not-a-real-proxy-type"
	cfg.proxyConfig.Address = "127.0.0.1"
	cfg.proxyConfig.Port = 8080

	certDb, err := NewCertDb(filepath.Join(dir, "crt"), cfg, nil)
	if err != nil {
		t.Fatalf("NewCertDb() error: %v", err)
	}
	db, err := database.NewDatabase(filepath.Join(dir, "olta.db"))
	if err != nil {
		t.Fatalf("database.NewDatabase() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blPath := filepath.Join(dir, "blacklist.txt")
	if err := SaveToFile(nil, blPath, 0600); err != nil {
		t.Fatal(err)
	}
	bl, err := NewBlacklist(blPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewHttpProxy() panicked on invalid upstream proxy config: %v", r)
		}
	}()
	proxy, err := NewHttpProxy("127.0.0.1", 0, cfg, certDb, db, &stubCampaignEventSink{}, bl, true, false, 0, 0)
	if err != nil {
		t.Fatalf("NewHttpProxy() error: %v", err)
	}
	if proxy == nil {
		t.Fatal("NewHttpProxy() returned a nil proxy without an error")
	}
	if cfg.proxyConfig.Enabled {
		t.Error("invalid upstream proxy config should have been disabled rather than left enabled")
	}
}

func TestGetPhishletByOrigHost(t *testing.T) {
	cfg := newTestConfig(t)
	pl := fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	cases := []struct {
		name string
		host string
		want *Phishlet
	}{
		{"landing orig host", "www.example.com", pl},
		{"sub orig host", "sub.example.com", pl},
		{"unrelated host", "unrelated.com", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := proxy.getPhishletByOrigHost(tc.host); got != tc.want {
				t.Errorf("getPhishletByOrigHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestGetPhishletByPhishHost(t *testing.T) {
	cfg := newTestConfig(t)
	pl := fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	cases := []struct {
		name string
		host string
		want *Phishlet
	}{
		{"landing phish host", "phish-corp.com", pl},
		{"sub phish host", "sub.phish-corp.com", pl},
		{"lure hostname", "lure.corp-example.com", pl},
		{"unrelated host", "unrelated.com", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := proxy.getPhishletByPhishHost(tc.host); got != tc.want {
				t.Errorf("getPhishletByPhishHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestReplaceHostWithOriginal(t *testing.T) {
	cfg := newTestConfig(t)
	fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	cases := []struct {
		name     string
		host     string
		wantHost string
		wantOk   bool
	}{
		{"landing phish host", "phish-corp.com", "www.example.com", true},
		{"sub phish host", "sub.phish-corp.com", "sub.example.com", true},
		{"with leading dot", ".phish-corp.com", ".www.example.com", true},
		{"unrelated host", "unrelated.com", "unrelated.com", false},
		{"empty host", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := proxy.replaceHostWithOriginal(tc.host)
			if got != tc.wantHost || ok != tc.wantOk {
				t.Errorf("replaceHostWithOriginal(%q) = (%q, %v), want (%q, %v)", tc.host, got, ok, tc.wantHost, tc.wantOk)
			}
		})
	}
}

func TestReplaceHostWithPhished(t *testing.T) {
	cfg := newTestConfig(t)
	fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	cases := []struct {
		name     string
		host     string
		wantHost string
		wantOk   bool
	}{
		{"landing orig host", "www.example.com", "phish-corp.com", true},
		{"sub orig host", "sub.example.com", "sub.phish-corp.com", true},
		{"bare domain fallback", "example.com", "phish-corp.com", true},
		{"unrelated host", "unrelated.com", "unrelated.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := proxy.replaceHostWithPhished(tc.host)
			if got != tc.wantHost || ok != tc.wantOk {
				t.Errorf("replaceHostWithPhished(%q) = (%q, %v), want (%q, %v)", tc.host, got, ok, tc.wantHost, tc.wantOk)
			}
		})
	}
}

func TestReplaceUrlWithPhished(t *testing.T) {
	cfg := newTestConfig(t)
	fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	cases := []struct {
		name   string
		in     string
		want   string
		wantOk bool
		wantIn bool // if true, expect the input to be returned unchanged
	}{
		{"matching host", "https://www.example.com/path?a=1", "https://phish-corp.com/path?a=1", true, false},
		{"unrelated host", "https://unrelated.com/path", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := proxy.replaceUrlWithPhished(tc.in)
			if ok != tc.wantOk {
				t.Fatalf("replaceUrlWithPhished(%q) ok = %v, want %v", tc.in, ok, tc.wantOk)
			}
			if tc.wantIn {
				if got != tc.in {
					t.Errorf("replaceUrlWithPhished(%q) = %q, want unchanged input", tc.in, got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("replaceUrlWithPhished(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGetPhishDomain(t *testing.T) {
	cfg := newTestConfig(t)
	fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	cases := []struct {
		name   string
		host   string
		want   string
		wantOk bool
	}{
		{"landing phish host", "phish-corp.com", "phish-corp.com", true},
		{"sub phish host", "sub.phish-corp.com", "phish-corp.com", true},
		{"lure hostname", "lure.corp-example.com", "phish-corp.com", true},
		{"unrelated host", "unrelated.com", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := proxy.getPhishDomain(tc.host)
			if got != tc.want || ok != tc.wantOk {
				t.Errorf("getPhishDomain(%q) = (%q, %v), want (%q, %v)", tc.host, got, ok, tc.want, tc.wantOk)
			}
		})
	}
}

func TestGetPhishSub(t *testing.T) {
	cfg := newTestConfig(t)
	fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	cases := []struct {
		name   string
		host   string
		want   string
		wantOk bool
	}{
		{"landing phish host", "phish-corp.com", "", true},
		{"sub phish host", "sub.phish-corp.com", "sub", true},
		{"unrelated host", "unrelated.com", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := proxy.getPhishSub(tc.host)
			if got != tc.want || ok != tc.wantOk {
				t.Errorf("getPhishSub(%q) = (%q, %v), want (%q, %v)", tc.host, got, ok, tc.want, tc.wantOk)
			}
		})
	}
}

func TestHandleSession(t *testing.T) {
	cfg := newTestConfig(t)
	fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	cases := []struct {
		name string
		host string
		want bool
	}{
		{"landing phish host", "phish-corp.com", true},
		{"sub phish host", "sub.phish-corp.com", true},
		{"lure hostname", "lure.corp-example.com", true},
		{"unrelated host", "unrelated.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := proxy.handleSession(tc.host); got != tc.want {
				t.Errorf("handleSession(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// newProxyWithConfig constructs an *HttpProxy sharing the given already
// populated *Config, so tests can register phishlets/lures on the Config
// before wiring the proxy.
func newProxyWithConfig(t *testing.T, cfg *Config) (*HttpProxy, *stubCampaignEventSink) {
	t.Helper()
	dir := t.TempDir()
	certDb, err := NewCertDb(filepath.Join(dir, "crt"), cfg, nil)
	if err != nil {
		t.Fatalf("NewCertDb() error: %v", err)
	}
	db, err := database.NewDatabase(filepath.Join(dir, "olta.db"))
	if err != nil {
		t.Fatalf("database.NewDatabase() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blPath := filepath.Join(dir, "blacklist.txt")
	if err := SaveToFile(nil, blPath, 0600); err != nil {
		t.Fatal(err)
	}
	bl, err := NewBlacklist(blPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := &stubCampaignEventSink{}
	proxy, err := NewHttpProxy("127.0.0.1", 0, cfg, certDb, db, sink, bl, true, false, 0, 0)
	if err != nil {
		t.Fatalf("NewHttpProxy() error: %v", err)
	}
	return proxy, sink
}

func TestIsForwarderUrl(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	validParam := func() string {
		buf := make([]byte, 5)
		copy(buf[1:], []byte{1, 2, 3, 4})
		var crc byte
		for _, b := range buf[1:] {
			crc += b
		}
		buf[0] = crc
		return base64.RawURLEncoding.EncodeToString(buf)
	}()
	invalidParam := func() string {
		buf := make([]byte, 5)
		copy(buf[1:], []byte{1, 2, 3, 4})
		buf[0] = 0xFF // wrong checksum
		return base64.RawURLEncoding.EncodeToString(buf)
	}()

	cases := []struct {
		name string
		u    *url.URL
		want bool
	}{
		{"valid forwarder param", &url.URL{RawQuery: "x=" + validParam}, true},
		{"checksum mismatch", &url.URL{RawQuery: "x=" + invalidParam}, false},
		{"no query", &url.URL{}, false},
		{"unrelated query", &url.URL{RawQuery: "a=b&c=d"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := proxy.isForwarderUrl(tc.u); got != tc.want {
				t.Errorf("isForwarderUrl(%q) = %v, want %v", tc.u.RawQuery, got, tc.want)
			}
		})
	}
}

// encodeLureParam mirrors the encoding extractParams decodes: an 8-byte RC4
// key prefix followed by base64url(crc-byte || rc4(plaintext)), where crc is
// the sum of the plaintext bytes.
func encodeLureParam(key string, plain string) string {
	if len(key) != 8 {
		panic("encodeLureParam: key must be exactly 8 bytes")
	}
	var crc byte
	for _, b := range []byte(plain) {
		crc += b
	}
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(plain))
	cipher.XORKeyStream(ciphertext, []byte(plain))
	payload := append([]byte{crc}, ciphertext...)
	return key + base64.RawURLEncoding.EncodeToString(payload)
}

func TestExtractParams(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	t.Run("valid encoded params are decoded", func(t *testing.T) {
		session, err := NewSession("testsite")
		if err != nil {
			t.Fatal(err)
		}
		encoded := encodeLureParam("abcdefgh", "foo=bar&baz=qux")
		u := &url.URL{RawQuery: "z=" + encoded}

		if ok := proxy.extractParams(session, u); !ok {
			t.Fatal("extractParams() = false, want true for a validly encoded param")
		}
		if session.Params["foo"] != "bar" {
			t.Errorf("Params[foo] = %q, want bar", session.Params["foo"])
		}
		if session.Params["baz"] != "qux" {
			t.Errorf("Params[baz] = %q, want qux", session.Params["baz"])
		}
	})

	t.Run("checksum mismatch leaves params untouched", func(t *testing.T) {
		session, err := NewSession("testsite")
		if err != nil {
			t.Fatal(err)
		}
		encoded := encodeLureParam("abcdefgh", "foo=bar")
		// Corrupt one character of the encoded payload (past the 8-byte key
		// prefix) so the RC4-decrypted checksum no longer matches.
		corrupted := []byte(encoded)
		i := len(corrupted) - 1
		if corrupted[i] == 'A' {
			corrupted[i] = 'B'
		} else {
			corrupted[i] = 'A'
		}
		u := &url.URL{RawQuery: "z=" + string(corrupted)}

		if ok := proxy.extractParams(session, u); ok {
			t.Fatal("extractParams() = true, want false for a corrupted payload")
		}
		if len(session.Params) != 0 {
			t.Errorf("Params = %v, want empty after a checksum mismatch", session.Params)
		}
	})

	t.Run("short query values are ignored", func(t *testing.T) {
		session, err := NewSession("testsite")
		if err != nil {
			t.Fatal(err)
		}
		u := &url.URL{RawQuery: "z=short"}
		if ok := proxy.extractParams(session, u); ok {
			t.Fatal("extractParams() = true, want false for a value too short to carry a key")
		}
	})
}

func TestReplaceHtmlParams(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	body := "HTML:{lure_url_html}:ENDHTML JS:{lure_url_js}:ENDJS PARAM:{username}:ENDPARAM"
	params := &map[string]string{"username": "Bob <3"}
	result := proxy.replaceHtmlParams(body, "https://phish-corp.com/abc", params)

	htmlVal := between(t, result, "HTML:", ":ENDHTML")
	jsVal := between(t, result, "JS:", ":ENDJS")
	paramVal := between(t, result, "PARAM:", ":ENDPARAM")

	if !strings.HasPrefix(htmlVal, "https://phish-corp.com/abc?") {
		t.Errorf("lure_url_html = %q, want prefix %q", htmlVal, "https://phish-corp.com/abc?")
	}
	if paramVal != "Bob &lt;3" {
		t.Errorf("username param = %q, want HTML-escaped %q", paramVal, "Bob &lt;3")
	}

	// Reconstruct the JS-chunked URL: each chunk is single-quoted and joined
	// with " + ". It must reassemble into exactly the same URL used for the
	// HTML placeholder, since replaceHtmlParams computes the forwarder URL
	// once and reuses it for both substitutions.
	var reconstructed strings.Builder
	for _, chunk := range strings.Split(jsVal, " + ") {
		reconstructed.WriteString(strings.Trim(chunk, "'"))
	}
	if reconstructed.String() != htmlVal {
		t.Errorf("reconstructed lure_url_js = %q, want %q (must match lure_url_html)", reconstructed.String(), htmlVal)
	}
}

func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i == -1 {
		t.Fatalf("marker %q not found in %q", start, s)
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j == -1 {
		t.Fatalf("marker %q not found after index %d in %q", end, i, s)
	}
	return s[i : i+j]
}

func TestPatchUrls(t *testing.T) {
	cfg := newTestConfig(t)
	pl := fixturePhishlet(cfg)
	proxy, _ := newProxyWithConfig(t, cfg)

	t.Run("with scheme, to phishing", func(t *testing.T) {
		body := []byte("check https://www.example.com/page and https://sub.example.com/x")
		got := string(proxy.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS))
		if !strings.Contains(got, "https://phish-corp.com/page") {
			t.Errorf("result = %q, want it to contain the landing phish host", got)
		}
		if !strings.Contains(got, "https://sub.phish-corp.com/x") {
			t.Errorf("result = %q, want it to contain the sub phish host", got)
		}
	})

	t.Run("with scheme, to original", func(t *testing.T) {
		body := []byte("check https://phish-corp.com/page and https://sub.phish-corp.com/x")
		got := string(proxy.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS))
		if !strings.Contains(got, "https://www.example.com/page") {
			t.Errorf("result = %q, want it to contain the landing orig host", got)
		}
		if !strings.Contains(got, "https://sub.example.com/x") {
			t.Errorf("result = %q, want it to contain the sub orig host", got)
		}
	})

	t.Run("without scheme, to phishing", func(t *testing.T) {
		body := []byte("bare host www.example.com mentioned in text")
		got := string(proxy.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS))
		if !strings.Contains(got, "phish-corp.com") {
			t.Errorf("result = %q, want it to contain the phish host", got)
		}
		if strings.Contains(got, "www.example.com") {
			t.Errorf("result = %q, original host should have been replaced", got)
		}
	})
}

func TestInjectJavascriptIntoBody(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	t.Run("inline script", func(t *testing.T) {
		body := []byte("<html><body>content</body></html>")
		got := string(proxy.injectJavascriptIntoBody(body, "alert(1)", ""))
		if !strings.Contains(got, "<script>alert(1)</script>") {
			t.Errorf("result = %q, want it to contain the inline script", got)
		}
		if !strings.Contains(got, "</body></html>") {
			t.Errorf("result = %q, original closing tags should be preserved", got)
		}
	})

	t.Run("src url", func(t *testing.T) {
		body := []byte("<html><body>content</body></html>")
		got := string(proxy.injectJavascriptIntoBody(body, "", "/s/abc.js"))
		if !strings.Contains(got, `src="/s/abc.js"`) {
			t.Errorf("result = %q, want it to reference the src URL", got)
		}
	})

	t.Run("both empty leaves body unchanged", func(t *testing.T) {
		body := []byte("<html><body>content</body></html>")
		got := proxy.injectJavascriptIntoBody(body, "", "")
		if string(got) != string(body) {
			t.Errorf("result = %q, want unchanged %q", got, body)
		}
	})

	t.Run("no closing body tag leaves body unchanged", func(t *testing.T) {
		body := []byte("<html><div>fragment</div></html>")
		got := proxy.injectJavascriptIntoBody(body, "alert(1)", "")
		if string(got) != string(body) {
			t.Errorf("result = %q, want unchanged %q", got, body)
		}
	})

	t.Run("nonce is propagated", func(t *testing.T) {
		body := []byte(`<html><head><script nonce="xyz123">1</script></head><body>content</body></html>`)
		got := string(proxy.injectJavascriptIntoBody(body, "alert(1)", ""))
		if !strings.Contains(got, `nonce="xyz123"`) {
			t.Errorf("result = %q, want the existing nonce propagated onto the injected script", got)
		}
	})
}

func TestBlockRequest(t *testing.T) {
	t.Run("phishlet unauth url redirects", func(t *testing.T) {
		cfg := newTestConfig(t)
		fixturePhishlet(cfg)
		cfg.PhishletConfig("testsite").UnauthUrl = "https://blocked.example/unauth"
		proxy, _ := newProxyWithConfig(t, cfg)

		req := httptest.NewRequest(http.MethodGet, "https://phish-corp.com/anything", nil)
		_, resp := proxy.blockRequest(req)
		if resp == nil {
			t.Fatal("blockRequest() returned a nil response")
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("StatusCode = %d, want 200 (javascript redirect)", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "https://blocked.example/unauth") {
			t.Errorf("body = %q, want it to reference the unauth URL", body)
		}
	})

	t.Run("no unauth url falls back to 403", func(t *testing.T) {
		cfg := newTestConfig(t)
		// NewConfig seeds a default general.UnauthUrl (a rickroll) on a
		// freshly created config; clear it so blockRequest has no fallback
		// redirect target and takes the plain-403 path this case exercises.
		cfg.general.UnauthUrl = ""
		proxy, _ := newProxyWithConfig(t, cfg)
		req := httptest.NewRequest(http.MethodGet, "https://unrelated.example/anything", nil)
		_, resp := proxy.blockRequest(req)
		if resp == nil {
			t.Fatal("blockRequest() returned a nil response")
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("StatusCode = %d, want 403", resp.StatusCode)
		}
	})
}

func TestTrackerImage(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)
	req := httptest.NewRequest(http.MethodGet, "https://phish-corp.com/s/abc?o=track&rid=x", nil)
	_, resp := proxy.trackerImage(req)
	if resp == nil {
		t.Fatal("trackerImage() returned a nil response")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", got)
	}
}

func TestRedirectTurnstile(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)
	req := httptest.NewRequest(http.MethodGet, "https://phish-corp.com/", nil)
	req.Host = "phish-corp.com"
	_, resp := proxy.redirectTurnstile(req, "rid-123")
	if resp == nil {
		t.Fatal("redirectTurnstile() returned a nil response")
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	want := "https://phish-corp.com/validate-captcha?client_id=rid-123"
	if loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}

func TestInterceptRequest(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	t.Run("default mime falls back to text/plain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://phish-corp.com/x", nil)
		_, resp := proxy.interceptRequest(req, http.StatusTeapot, "hello", "")
		if resp.StatusCode != http.StatusTeapot {
			t.Errorf("StatusCode = %d, want 418", resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != "text/plain" {
			t.Errorf("Content-Type = %q, want text/plain", got)
		}
	})

	t.Run("explicit mime and origin reflection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://phish-corp.com/x", nil)
		req.Header.Set("Origin", "https://caller.example")
		_, resp := proxy.interceptRequest(req, http.StatusOK, `{"ok":true}`, "application/json")
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://caller.example" {
			t.Errorf("Access-Control-Allow-Origin = %q, want reflected origin", got)
		}
	})
}

func TestJavascriptRedirect(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)
	req := httptest.NewRequest(http.MethodGet, "https://phish-corp.com/x", nil)
	_, resp := proxy.javascriptRedirect(req, "https://target.example/landing")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "top.location.href='https://target.example/landing'") {
		t.Errorf("body = %q, want it to contain the redirect target", body)
	}
}

func TestSetSessionUsernamePasswordCustom(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)
	session, err := NewSession("testsite")
	if err != nil {
		t.Fatal(err)
	}
	proxy.sessions[session.Id] = session

	proxy.setSessionUsername(session.Id, "alice")
	proxy.setSessionPassword(session.Id, "hunter2")
	proxy.setSessionCustom(session.Id, "mfa", "654321")

	if session.Username != "alice" {
		t.Errorf("Username = %q, want alice", session.Username)
	}
	if session.Password != "hunter2" {
		t.Errorf("Password = %q, want hunter2", session.Password)
	}
	if session.Custom["mfa"] != "654321" {
		t.Errorf("Custom[mfa] = %q, want 654321", session.Custom["mfa"])
	}

	t.Run("empty sid is a no-op", func(t *testing.T) {
		proxy.setSessionUsername("", "should-not-apply")
		// Reaching here without a panic and without mutating any session is
		// the assertion; there is no session keyed by "" to check.
	})

	t.Run("unknown sid is a no-op", func(t *testing.T) {
		proxy.setSessionUsername("does-not-exist", "should-not-apply")
		if _, ok := proxy.sessions["does-not-exist"]; ok {
			t.Fatal("an unknown sid must not create a session entry")
		}
	})
}

func TestConfigureCloaker(t *testing.T) {
	t.Run("disabled clears the cloaker", func(t *testing.T) {
		proxy, _ := newTestHttpProxy(t)
		if err := proxy.ConfigureCloaker(asncloak.Config{Enabled: false}); err != nil {
			t.Fatalf("ConfigureCloaker() error: %v", err)
		}
		if proxy.cloaker != nil {
			t.Fatal("cloaker must be nil when Enabled is false")
		}
	})

	t.Run("valid config installs the cloaker", func(t *testing.T) {
		proxy, _ := newTestHttpProxy(t)
		err := proxy.ConfigureCloaker(asncloak.Config{
			Enabled:        true,
			Action:         asncloak.ActionBlock,
			BlockStatus:    http.StatusNotFound,
			InspectHeaders: true,
		})
		if err != nil {
			t.Fatalf("ConfigureCloaker() error: %v", err)
		}
		if proxy.cloaker == nil {
			t.Fatal("cloaker was not installed")
		}
	})

	t.Run("invalid config returns an error and does not install", func(t *testing.T) {
		proxy, _ := newTestHttpProxy(t)
		err := proxy.ConfigureCloaker(asncloak.Config{
			Enabled: true,
			Action:  "not-a-real-action",
		})
		if err == nil {
			t.Fatal("ConfigureCloaker() expected an error for an unknown action")
		}
		if proxy.cloaker != nil {
			t.Fatal("cloaker must remain nil after a failed configuration")
		}
	})
}

func TestConfigureJSInspect(t *testing.T) {
	t.Run("disabled clears the inspector", func(t *testing.T) {
		proxy, _ := newTestHttpProxy(t)
		if err := proxy.ConfigureJSInspect(jsinspect.Config{Enabled: false}); err != nil {
			t.Fatalf("ConfigureJSInspect() error: %v", err)
		}
		if proxy.jsInspector != nil {
			t.Fatal("jsInspector must be nil when Enabled is false")
		}
	})

	t.Run("valid config installs the inspector", func(t *testing.T) {
		proxy, _ := newTestHttpProxy(t)
		err := proxy.ConfigureJSInspect(jsinspect.Config{
			Enabled:  true,
			Endpoint: "/_assets/js/v.js",
			Action:   jsinspect.ActionBlock,
		})
		if err != nil {
			t.Fatalf("ConfigureJSInspect() error: %v", err)
		}
		if proxy.jsInspector == nil {
			t.Fatal("jsInspector was not installed")
		}
	})

	t.Run("invalid endpoint returns an error and does not install", func(t *testing.T) {
		proxy, _ := newTestHttpProxy(t)
		err := proxy.ConfigureJSInspect(jsinspect.Config{
			Enabled:  true,
			Endpoint: "/v.js?query=not-allowed",
		})
		if err == nil {
			t.Fatal("ConfigureJSInspect() expected an error for an endpoint with a query string")
		}
		if proxy.jsInspector != nil {
			t.Fatal("jsInspector must remain nil after a failed configuration")
		}
	})
}

// TestCheckCookieHttpOnlyDrift covers the phishlet-drift signal wired at the
// cookie-auth-token capture site in http_proxy.go: the declared http_only
// modifier is only ever compared against the observed Set-Cookie HttpOnly
// flag to log a drift warning - it must never be used to decide what gets
// captured or stored.
func TestCheckCookieHttpOnlyDrift(t *testing.T) {
	newPhishlet := func(t *testing.T, tok string) *Phishlet {
		t.Helper()
		p := &Phishlet{}
		p.Clear()
		if err := p.addCookieAuthTokens("example.com", []string{tok}); err != nil {
			t.Fatalf("addCookieAuthTokens: %v", err)
		}
		return p
	}

	captureLog := func(t *testing.T, fn func()) string {
		t.Helper()
		orig := log.GetOutput()
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer log.SetOutput(orig)
		fn()
		return buf.String()
	}

	t.Run("declared http_only but observed cookie is not HttpOnly logs drift", func(t *testing.T) {
		pl := newPhishlet(t, "sess:http_only")
		out := captureLog(t, func() {
			checkCookieHttpOnlyDrift(pl, "example.com", "sess", false)
		})
		if !strings.Contains(out, "phishlet drift") {
			t.Errorf("expected a phishlet drift warning, got: %q", out)
		}
		if !strings.Contains(out, "declared=true") || !strings.Contains(out, "observed=false") {
			t.Errorf("drift log missing declared/observed values: %q", out)
		}
	})

	t.Run("declared and observed agree produces no drift log", func(t *testing.T) {
		pl := newPhishlet(t, "sess:http_only")
		out := captureLog(t, func() {
			checkCookieHttpOnlyDrift(pl, "example.com", "sess", true)
		})
		if strings.Contains(out, "phishlet drift") {
			t.Errorf("did not expect a drift warning when declared and observed agree, got: %q", out)
		}
	})

	t.Run("no declaration and observed cookie not HttpOnly agree produces no drift log", func(t *testing.T) {
		pl := newPhishlet(t, "sid") // no :http_only modifier -> declared defaults to false
		out := captureLog(t, func() {
			checkCookieHttpOnlyDrift(pl, "example.com", "sid", false)
		})
		if strings.Contains(out, "phishlet drift") {
			t.Errorf("did not expect a drift warning, got: %q", out)
		}
	})

	t.Run("no declaration but observed cookie is HttpOnly logs drift", func(t *testing.T) {
		pl := newPhishlet(t, "sid")
		out := captureLog(t, func() {
			checkCookieHttpOnlyDrift(pl, "example.com", "sid", true)
		})
		if !strings.Contains(out, "phishlet drift") {
			t.Errorf("expected a phishlet drift warning, got: %q", out)
		}
	})

	t.Run("nil phishlet is a no-op", func(t *testing.T) {
		out := captureLog(t, func() {
			checkCookieHttpOnlyDrift(nil, "example.com", "sid", true)
		})
		if out != "" {
			t.Errorf("expected no log output for a nil phishlet, got: %q", out)
		}
	})
}

// TestCookieAuthTokenCapture_StoredHttpOnlyMatchesObserved is the hard
// constraint from the http_only drift feature: whatever the phishlet
// declares, the HttpOnly value actually stored on the session's captured
// cookie token must always equal the value observed on the origin's
// Set-Cookie header - never the phishlet's declared value. This exercises
// the same sequence the response pipeline runs (drift check, then capture)
// for both an agreeing and a drifted phishlet declaration.
func TestCookieAuthTokenCapture_StoredHttpOnlyMatchesObserved(t *testing.T) {
	cases := []struct {
		name             string
		declaredModifier string // token modifier suffix, e.g. ":http_only" or ""
		observedHttpOnly bool
	}{
		{"declared http_only, observed not HttpOnly (drift)", ":http_only", false},
		{"declared http_only, observed HttpOnly (agree)", ":http_only", true},
		{"not declared, observed HttpOnly (drift)", "", true},
		{"not declared, observed not HttpOnly (agree)", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pl := &Phishlet{}
			pl.Clear()
			if err := pl.addCookieAuthTokens("example.com", []string{"sess" + tc.declaredModifier}); err != nil {
				t.Fatalf("addCookieAuthTokens: %v", err)
			}

			s, err := NewSession("test")
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}

			// Run the drift check exactly as the response pipeline does -
			// it must not influence what gets captured.
			checkCookieHttpOnlyDrift(pl, "example.com", "sess", tc.observedHttpOnly)
			s.AddCookieAuthToken("example.com", "sess", "value123", "/", tc.observedHttpOnly, time.Time{})

			stored, ok := s.CookieTokens["example.com"]["sess"]
			if !ok {
				t.Fatalf("cookie token was not captured")
			}
			if stored.HttpOnly != tc.observedHttpOnly {
				t.Errorf("stored HttpOnly = %v, want %v (the observed value, regardless of the declared %q)", stored.HttpOnly, tc.observedHttpOnly, tc.declaredModifier)
			}
		})
	}
}

// newTestHttpProxyAgainstDB is like newTestHttpProxy but takes an
// already-open *database.Database, so a test can control exactly what was
// persisted before the proxy is constructed - the setup a restart-rehydration
// test needs.
func newTestHttpProxyAgainstDB(t *testing.T, dir string, db *database.Database) *HttpProxy {
	t.Helper()

	cfg := newTestConfig(t)

	certDb, err := NewCertDb(filepath.Join(dir, "crt"), cfg, nil)
	if err != nil {
		t.Fatalf("NewCertDb() error: %v", err)
	}

	blPath := filepath.Join(dir, "blacklist.txt")
	if err := SaveToFile(nil, blPath, 0600); err != nil {
		t.Fatalf("SaveToFile() error: %v", err)
	}
	bl, err := NewBlacklist(blPath, nil)
	if err != nil {
		t.Fatalf("NewBlacklist() error: %v", err)
	}

	proxy, err := NewHttpProxy("127.0.0.1", 0, cfg, certDb, db, &stubCampaignEventSink{}, bl, true, false, 0, 0)
	if err != nil {
		t.Fatalf("NewHttpProxy() error: %v", err)
	}
	return proxy
}

// TestRehydrateSessions_RestoresIdentityCorrelationAcrossRestart is the
// core test for Item #14: a proxy restart must not sever the session id ->
// RID/phishlet correlation for an in-flight victim, even though the
// process's in-memory p.sessions/p.sids maps start out empty again.
//
// It simulates a restart at both layers that matter: the database is
// closed and reopened from the same file (exactly what loadSessions does
// on the next process's database.NewDatabase call), and a brand new
// *HttpProxy is constructed against that reopened database (exactly what
// NewHttpProxy does on the next process's startup).
func TestRehydrateSessions_RestoresIdentityCorrelationAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "olta.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("database.NewDatabase() error: %v", err)
	}

	// Three victims from a prior "process lifetime": two correlated to a
	// campaign recipient (RID), one anonymous (no RID, e.g. direct
	// navigation to the lure without gophish tracking params).
	if err := db.CreateSession("sid-alice", "o365", "https://phish.test/login", "ua-1", "203.0.113.1"); err != nil {
		t.Fatalf("CreateSession(alice): %v", err)
	}
	if err := db.SetSessionRID("sid-alice", "rid-alice"); err != nil {
		t.Fatalf("SetSessionRID(alice): %v", err)
	}
	if err := db.CreateSession("sid-bob", "o365", "https://phish.test/login", "ua-2", "203.0.113.2"); err != nil {
		t.Fatalf("CreateSession(bob): %v", err)
	}
	if err := db.SetSessionRID("sid-bob", "rid-bob"); err != nil {
		t.Fatalf("SetSessionRID(bob): %v", err)
	}
	if err := db.CreateSession("sid-anon", "o365", "https://phish.test/login", "ua-3", "203.0.113.3"); err != nil {
		t.Fatalf("CreateSession(anon): %v", err)
	}
	db.Flush()

	// Restart, layer 1: close and reopen the database from the same file.
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close(): %v", err)
	}
	reopened, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("database.NewDatabase() reopen error: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	// Restart, layer 2: a fresh HttpProxy, as a new process would build.
	proxy := newTestHttpProxyAgainstDB(t, dir, reopened)

	// Identity correlation must be restored for every session id.
	for _, tc := range []struct {
		sid, wantPhishlet, wantRID string
	}{
		{"sid-alice", "o365", "rid-alice"},
		{"sid-bob", "o365", "rid-bob"},
		{"sid-anon", "o365", ""},
	} {
		s, ok := proxy.getSession(tc.sid)
		if !ok {
			t.Fatalf("getSession(%q) not found after rehydration", tc.sid)
		}
		if s.Name != tc.wantPhishlet {
			t.Errorf("getSession(%q).Name = %q, want %q", tc.sid, s.Name, tc.wantPhishlet)
		}
		if s.RId != tc.wantRID {
			t.Errorf("getSession(%q).RId = %q, want %q", tc.sid, s.RId, tc.wantRID)
		}
		if s.Id != tc.sid {
			t.Errorf("getSession(%q).Id = %q, want %q", tc.sid, s.Id, tc.sid)
		}

		// Ceremony state must NOT be resurrected - it must look exactly
		// like a session NewSession() just created.
		if s.IsDone {
			t.Errorf("getSession(%q).IsDone = true, want false (ceremony state must not be restored)", tc.sid)
		}
		if s.IsCaptchaDone {
			t.Errorf("getSession(%q).IsCaptchaDone = true, want false", tc.sid)
		}
		if s.ProgressIndex != 0 {
			t.Errorf("getSession(%q).ProgressIndex = %d, want 0", tc.sid, s.ProgressIndex)
		}
		if s.DoneSignal == nil {
			t.Errorf("getSession(%q).DoneSignal = nil, want a fresh (unclosed) channel like NewSession() makes", tc.sid)
		} else {
			select {
			case <-s.DoneSignal:
				t.Errorf("getSession(%q).DoneSignal is already closed, want an untouched fresh channel", tc.sid)
			default:
			}
		}
	}

	// last_sid must not collide with any restored index: every persisted
	// session's numeric id must have a matching, distinct p.sids entry, and
	// last_sid must be strictly greater than all of them.
	maxRestored := -1
	for _, sid := range []string{"sid-alice", "sid-bob", "sid-anon"} {
		idx, ok := proxy.getSessionIndex(sid)
		if !ok {
			t.Fatalf("getSessionIndex(%q) not found after rehydration", sid)
		}
		if idx > maxRestored {
			maxRestored = idx
		}
	}
	seen := map[int]string{}
	for _, sid := range []string{"sid-alice", "sid-bob", "sid-anon"} {
		idx, _ := proxy.getSessionIndex(sid)
		if other, dup := seen[idx]; dup {
			t.Fatalf("sids %q and %q collide on the same restored index %d", other, sid, idx)
		}
		seen[idx] = sid
	}

	// A newly assigned session after rehydration must not reuse a restored
	// index.
	newSession, err := NewSession("o365")
	if err != nil {
		t.Fatalf("NewSession(): %v", err)
	}
	newIdx := proxy.addSession(newSession)
	if newIdx <= maxRestored {
		t.Errorf("addSession() after rehydration returned index %d, want strictly greater than max restored index %d", newIdx, maxRestored)
	}
	if _, dup := seen[newIdx]; dup {
		t.Errorf("addSession() after rehydration returned index %d, which collides with a restored session's index", newIdx)
	}
}

// TestRehydrateSessions_Empty confirms rehydration against an empty store is
// a clean no-op: no sessions are restored and last_sid starts at 0, exactly
// as it does today without this feature.
func TestRehydrateSessions_Empty(t *testing.T) {
	dir := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(dir, "olta.db"))
	if err != nil {
		t.Fatalf("database.NewDatabase() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	proxy := newTestHttpProxyAgainstDB(t, dir, db)

	if proxy.last_sid != 0 {
		t.Errorf("last_sid = %d, want 0 for an empty store", proxy.last_sid)
	}
	if len(proxy.sessions) != 0 {
		t.Errorf("sessions = %v, want empty", proxy.sessions)
	}
	if len(proxy.sids) != 0 {
		t.Errorf("sids = %v, want empty", proxy.sids)
	}
}
