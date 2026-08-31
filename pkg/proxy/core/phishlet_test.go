package core

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

// writeYAML writes content to a phishlet.yaml file inside a fresh temp dir
// and returns its path.
func writeYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "phishlet.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	return path
}

// load writes content to a temp file and loads it as a phishlet named "site".
func load(t *testing.T, content string) (*Phishlet, error) {
	t.Helper()
	path := writeYAML(t, content)
	return NewPhishlet("site", path, nil, nil)
}

// loadWithParams is like load but forwards customParams to NewPhishlet.
func loadWithParams(t *testing.T, content string, customParams *map[string]string) (*Phishlet, error) {
	t.Helper()
	path := writeYAML(t, content)
	return NewPhishlet("site", path, customParams, nil)
}

// testCfg builds a minimal *Config sufficient for the Phishlet Get* methods
// that dereference p.cfg (GetPhishHosts, GetLureUrl, GetLandingPhishHost).
func testCfg(site, phishDomain, baseDomain string) *Config {
	return &Config{
		general: &GeneralConfig{Domain: baseDomain},
		phishletConfig: map[string]*PhishletConfig{
			site: {Hostname: phishDomain},
		},
	}
}

// fullValidPhishlet is a realistic, fully-featured 2.3.0 phishlet exercising
// every section LoadFromFile understands. Field shapes mirror real fixtures
// under cmd/olta-proxy/legacy_phishlets/ (o365.yaml, linkedin.yaml, okta.yaml).
const fullValidPhishlet = `
author: '@tester'
min_ver: '2.3.0'
redirect_url: 'https://example.com/'
params:
  - name: 'email'
    default: 'user@example.com'
    required: false
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'example.com', session: true, is_landing: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'example.com', session: false, is_landing: false, auto_filter: false}
sub_filters:
  - {triggers_on: 'login.example.com', orig_sub: 'login', domain: 'example.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json']}
  - {triggers_on: 'login.example.com', orig_sub: 'login', domain: 'example.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html'], redirect_only: true, with_params: ['redir']}
auth_tokens:
  - domain: '.login.example.com'
    keys: ['sessid', 'csrf:opt', 'persist:always']
  - domain: 'login.example.com'
    type: 'body'
    path: '/api/token'
    name: 'access_token'
    search: '"access_token":"([^"]*)"'
  - domain: 'login.example.com'
    type: 'http'
    path: '/api/session'
    name: 'x-session'
    header: 'X-Session-Token'
auth_urls:
  - '/api/token'
credentials:
  username:
    key: '(login|user)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd|pass)'
    search: '(.*)'
    type: 'post'
  custom:
    - key: 'otp'
      search: '(.*)'
      type: 'post'
login:
  domain: 'login.example.com'
  path: '/signin'
js_inject:
  - trigger_domains: ['login.example.com']
    trigger_paths: ['/signin']
    trigger_params: ['email']
    script: |
      var e = "{email}";
force_post:
  - path: '/signin'
    type: 'post'
    search:
      - {key: 'csrf', search: '.*'}
    force:
      - {key: 'persist', value: 'true'}
intercept:
  - domain: 'login.example.com'
    path: '/blocked'
    http_status: 404
    body: 'not found'
    mime: 'text/plain'
landing_path:
  - '/signin'
  - '/signin?{email}'
`

// ---------------------------------------------------------------------------
// LoadFromFile / NewPhishlet - happy path round trip
// ---------------------------------------------------------------------------

func TestNewPhishlet_ValidRoundTrip(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.Name != "site" {
		t.Errorf("Name = %q, want %q", p.Name, "site")
	}
	if p.Author != "@tester" {
		t.Errorf("Author = %q, want %q", p.Author, "@tester")
	}
	if p.RedirectUrl != "https://example.com/" {
		t.Errorf("RedirectUrl = %q", p.RedirectUrl)
	}
	if p.Version.major != 2 || p.Version.minor != 3 || p.Version.build != 0 {
		t.Errorf("Version = %+v, want 2.3.0", p.Version)
	}

	// proxy_hosts
	if len(p.proxyHosts) != 2 {
		t.Fatalf("proxyHosts len = %d, want 2", len(p.proxyHosts))
	}
	if !p.proxyHosts[0].handle_session {
		t.Errorf("proxyHosts[0].handle_session = false, want true (explicit session:true)")
	}
	if !p.proxyHosts[0].is_landing {
		t.Errorf("proxyHosts[0].is_landing = false, want true (explicit is_landing:true)")
	}
	if !p.proxyHosts[1].auto_filter == false {
		// auto_filter explicit false must be honored
	}
	if p.proxyHosts[1].auto_filter != false {
		t.Errorf("proxyHosts[1].auto_filter = true, want false (explicit auto_filter:false)")
	}
	if len(p.domains) != 1 || p.domains[0] != "example.com" {
		t.Errorf("domains = %v, want [example.com] (deduped)", p.domains)
	}

	// sub_filters
	sf, ok := p.subfilters["login.example.com"]
	if !ok || len(sf) != 2 {
		t.Fatalf("subfilters[login.example.com] = %v, want 2 entries", sf)
	}
	if sf[1].redirect_only != true {
		t.Errorf("sub_filters[1].redirect_only = false, want true")
	}
	if len(sf[1].with_params) != 1 || sf[1].with_params[0] != "redir" {
		t.Errorf("sub_filters[1].with_params = %v, want [redir]", sf[1].with_params)
	}
	if len(sf[0].with_params) != 0 {
		t.Errorf("sub_filters[0].with_params = %v, want empty (omitted in yaml)", sf[0].with_params)
	}
	if sf[0].mime[0] != "text/html" || sf[0].mime[1] != "application/json" {
		t.Errorf("sub_filters[0].mime = %v", sf[0].mime)
	}

	// auth_tokens: cookie
	cookies, ok := p.cookieAuthTokens[".login.example.com"]
	if !ok || len(cookies) != 3 {
		t.Fatalf("cookieAuthTokens[.login.example.com] = %v, want 3 entries", cookies)
	}
	if cookies[0].name != "sessid" || cookies[0].optional || cookies[0].always {
		t.Errorf("cookies[0] = %+v, want plain sessid", cookies[0])
	}
	if cookies[1].name != "csrf" || !cookies[1].optional {
		t.Errorf("cookies[1] = %+v, want csrf optional", cookies[1])
	}
	if cookies[2].name != "persist" || !cookies[2].always {
		t.Errorf("cookies[2] = %+v, want persist always", cookies[2])
	}
	// None of this fixture's keys use the ":http_only" modifier, so the
	// default (false) must hold; see TestAddCookieAuthTokens_Direct and
	// TestNewPhishlet_CookieAuthTokenHttpOnlyModifier for the opt-in case.
	for i, c := range cookies {
		if c.http_only {
			t.Errorf("cookies[%d].http_only = true, want false (fixture does not opt in via :http_only)", i)
		}
	}

	// auth_tokens: body
	bt, ok := p.bodyAuthTokens["access_token"]
	if !ok {
		t.Fatalf("bodyAuthTokens[access_token] missing")
	}
	if bt.domain != "login.example.com" || !bt.search.MatchString(`"access_token":"abc123"`) {
		t.Errorf("bodyAuthTokens[access_token] = %+v", bt)
	}

	// auth_tokens: http
	ht, ok := p.httpAuthTokens["x-session"]
	if !ok || ht.header != "X-Session-Token" {
		t.Fatalf("httpAuthTokens[x-session] = %+v", ht)
	}

	// auth_urls
	if len(p.authUrls) != 1 || !p.authUrls[0].MatchString("/api/token") {
		t.Errorf("authUrls = %v", p.authUrls)
	}

	// credentials
	if !p.username.key.MatchString("login") || !p.username.search.MatchString("bob") {
		t.Errorf("username postfield mismatch: %+v", p.username)
	}
	if p.username.tp != "post" {
		t.Errorf("username.tp = %q, want post", p.username.tp)
	}
	if !p.password.key.MatchString("passwd") {
		t.Errorf("password postfield mismatch: %+v", p.password)
	}
	if len(p.custom) != 1 || p.custom[0].key_s != "otp" {
		t.Fatalf("custom = %+v, want 1 entry named otp", p.custom)
	}

	// login
	if p.login.domain != "login.example.com" || p.login.path != "/signin" {
		t.Errorf("login = %+v", p.login)
	}

	// js_inject
	if len(p.js_inject) != 1 {
		t.Fatalf("js_inject len = %d, want 1", len(p.js_inject))
	}
	if len(p.js_inject[0].id) != 64 {
		t.Errorf("js_inject[0].id len = %d, want 64 (sha256 hex)", len(p.js_inject[0].id))
	}
	if p.js_inject[0].trigger_domains[0] != "login.example.com" {
		t.Errorf("js_inject[0].trigger_domains = %v", p.js_inject[0].trigger_domains)
	}

	// force_post
	if len(p.forcePost) != 1 {
		t.Fatalf("forcePost len = %d, want 1", len(p.forcePost))
	}
	if !p.forcePost[0].path.MatchString("/signin") {
		t.Errorf("forcePost[0].path did not match /signin")
	}
	if len(p.forcePost[0].force) != 1 || p.forcePost[0].force[0].key != "persist" {
		t.Errorf("forcePost[0].force = %+v", p.forcePost[0].force)
	}

	// intercept
	if len(p.intercept) != 1 || p.intercept[0].http_status != 404 {
		t.Fatalf("intercept = %+v", p.intercept)
	}

	// landing_path
	if len(p.landing_path) != 2 || p.landing_path[0] != "/signin" {
		t.Errorf("landing_path = %v", p.landing_path)
	}
}

// ---------------------------------------------------------------------------
// file-level failures
// ---------------------------------------------------------------------------

func TestNewPhishlet_NonExistentFile(t *testing.T) {
	_, err := NewPhishlet("site", "/nonexistent/dir/phishlet.yaml", nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("err = %v, want an os.IsNotExist error", err)
	}
}

func TestNewPhishlet_InvalidYAMLSyntax(t *testing.T) {
	_, err := load(t, "foo: [1, 2\nbar: baz\n")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var perr viper.ConfigParseError
	if !errors.As(err, &perr) {
		t.Errorf("err type = %T, want viper.ConfigParseError; err = %v", err, err)
	}
	if !strings.Contains(err.Error(), "While parsing config") {
		t.Errorf("err = %v, want message to mention parsing failure", err)
	}
}

func TestNewPhishlet_WrongShape(t *testing.T) {
	// Valid top-level YAML map, but proxy_hosts is a scalar instead of a
	// list of maps: mapstructure's weak-typed decode wraps the scalar into
	// a one-element slice, then fails to decode that string as a struct.
	content := `
author: test
min_ver: '2.3.0'
proxy_hosts: "not-a-list"
auth_tokens: []
credentials:
  username: {}
  password: {}
login: {}
`
	_, err := load(t, content)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "expected a map, got 'string'") {
		t.Errorf("err = %v, want mapstructure type-mismatch message", err)
	}
}

// ---------------------------------------------------------------------------
// version handling
// ---------------------------------------------------------------------------

func TestParseVersion(t *testing.T) {
	p := &Phishlet{}
	cases := []struct {
		name    string
		in      string
		want    PhishletVersion
		wantErr bool
	}{
		{"valid", "2.3.0", PhishletVersion{2, 3, 0}, false},
		{"valid double digit", "10.20.30", PhishletVersion{10, 20, 30}, false},
		{"too few parts", "2.3", PhishletVersion{}, true},
		{"too many parts", "2.3.0.1", PhishletVersion{}, true},
		{"empty", "", PhishletVersion{}, true},
		{"non-numeric major", "a.3.0", PhishletVersion{}, true},
		{"non-numeric minor", "2.b.0", PhishletVersion{}, true},
		{"non-numeric build", "2.3.c", PhishletVersion{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.parseVersion(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.in)
				}
				if err.Error() != "invalid version format (must be X.Y.Z)" && tc.name != "non-numeric major" && tc.name != "non-numeric minor" && tc.name != "non-numeric build" {
					t.Errorf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("parseVersion(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseVersion_MalformedFormatMessage(t *testing.T) {
	p := &Phishlet{}
	_, err := p.parseVersion("2.3")
	if err == nil || err.Error() != "invalid version format (must be X.Y.Z)" {
		t.Errorf("err = %v, want exact format error", err)
	}
}

func TestIsVersionHigherEqual(t *testing.T) {
	p := &Phishlet{}
	cases := []struct {
		name string
		pv   PhishletVersion
		cver string
		want bool
	}{
		{"exact match", PhishletVersion{2, 3, 0}, "2.3.0", true},
		{"higher major", PhishletVersion{3, 0, 0}, "2.9.0", true},
		{"lower major", PhishletVersion{1, 9, 9}, "2.0.0", false},
		{"same major higher minor", PhishletVersion{2, 5, 0}, "2.3.0", true},
		{"same major lower minor", PhishletVersion{2, 1, 0}, "2.3.0", false},
		{"malformed cver", PhishletVersion{2, 3, 0}, "not-a-version", false},
		// Documents current behavior: the patch/build component is parsed
		// but never compared, so a lower build is still "higher-or-equal".
		{"build number ignored", PhishletVersion{2, 3, 0}, "2.3.99", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.isVersionHigherEqual(&tc.pv, tc.cver); got != tc.want {
				t.Errorf("isVersionHigherEqual(%+v, %q) = %v, want %v", tc.pv, tc.cver, got, tc.want)
			}
		})
	}
}

func TestNewPhishlet_MinVerMalformed(t *testing.T) {
	content := "author: test\nmin_ver: 'bogus'\nproxy_hosts: []\n"
	_, err := load(t, content)
	if err == nil || err.Error() != "invalid version format (must be X.Y.Z)" {
		t.Errorf("err = %v", err)
	}
}

func TestNewPhishlet_MinVerTooOldFor220(t *testing.T) {
	content := "author: test\nmin_ver: '2.1.0'\nproxy_hosts: []\n"
	_, err := load(t, content)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "in each `sub_filters` item change `hostname` to `triggers_on`") {
		t.Errorf("err = %v, want 2.2.0 migration message", err)
	}
}

func TestNewPhishlet_MinVerTooOldFor230(t *testing.T) {
	// 2.2.0 satisfies the >=2.2.0 gate but fails the >=2.3.0 gate.
	content := "author: test\nmin_ver: '2.2.0'\nproxy_hosts: []\n"
	_, err := load(t, content)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "replace `landing_path` with `login` section") {
		t.Errorf("err = %v, want 2.3.0 migration message", err)
	}
}

// ---------------------------------------------------------------------------
// top-level required sections
// ---------------------------------------------------------------------------

func TestNewPhishlet_MissingTopLevelSections(t *testing.T) {
	header := "author: test\nmin_ver: '2.3.0'\n"
	validProxyHosts := "proxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	validAuthTokens := "auth_tokens: []\n"
	validCreds := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"
	validLogin := "login: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "missing proxy_hosts",
			content: header + validAuthTokens + validCreds + validLogin,
			wantErr: "missing `proxy_hosts` section",
		},
		{
			name:    "missing auth_tokens",
			content: header + validProxyHosts + validCreds + validLogin,
			wantErr: "missing `auth_tokens` section",
		},
		{
			name:    "missing credentials",
			content: header + validProxyHosts + validAuthTokens + validLogin,
			wantErr: "missing `credentials` section",
		},
		{
			name:    "missing credentials.username",
			content: header + validProxyHosts + validAuthTokens + "credentials:\n  password: {key: 'p', search: '(.*)'}\n" + validLogin,
			wantErr: "credentials: missing `username` section",
		},
		{
			name:    "missing credentials.password",
			content: header + validProxyHosts + validAuthTokens + "credentials:\n  username: {key: 'u', search: '(.*)'}\n" + validLogin,
			wantErr: "credentials: missing `password` section",
		},
		{
			name:    "missing login",
			content: header + validProxyHosts + validAuthTokens + validCreds,
			wantErr: "missing `login` section",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, tc.content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// proxy_hosts
// ---------------------------------------------------------------------------

func TestNewPhishlet_ProxyHostsFieldValidation(t *testing.T) {
	tail := "auth_tokens: []\ncredentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"
	cases := []struct {
		name    string
		hosts   string
		wantErr string
	}{
		{"missing phish_sub", "proxy_hosts:\n  - {orig_sub: '', domain: 'example.com'}\n", "proxy_hosts: missing `phish_sub` field"},
		{"missing orig_sub", "proxy_hosts:\n  - {phish_sub: '', domain: 'example.com'}\n", "proxy_hosts: missing `orig_sub` field"},
		{"missing domain", "proxy_hosts:\n  - {phish_sub: '', orig_sub: ''}\n", "proxy_hosts: missing `domain` field"},
		{"empty list", "proxy_hosts: []\n", "proxy_hosts: list cannot be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := "author: test\nmin_ver: '2.3.0'\n" + tc.hosts + tail
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPhishlet_ProxyHostsSessionAndLandingDefaults(t *testing.T) {
	tail := "auth_tokens: []\ncredentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'a.example.com', path: '/'}\n"

	t.Run("no explicit session or landing defaults to first host", func(t *testing.T) {
		content := "author: test\nmin_ver: '2.3.0'\n" +
			"proxy_hosts:\n" +
			"  - {phish_sub: 'a', orig_sub: 'a', domain: 'example.com'}\n" +
			"  - {phish_sub: 'b', orig_sub: 'b', domain: 'example.com'}\n" + tail
		p, err := load(t, content)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !p.proxyHosts[0].handle_session || !p.proxyHosts[0].is_landing {
			t.Errorf("proxyHosts[0] = %+v, want session+landing defaults applied", p.proxyHosts[0])
		}
		if p.proxyHosts[1].handle_session || p.proxyHosts[1].is_landing {
			t.Errorf("proxyHosts[1] = %+v, want no defaults applied to non-first host", p.proxyHosts[1])
		}
	})

	t.Run("explicit session on second host is honored, first is not overridden", func(t *testing.T) {
		content := "author: test\nmin_ver: '2.3.0'\n" +
			"proxy_hosts:\n" +
			"  - {phish_sub: 'a', orig_sub: 'a', domain: 'example.com'}\n" +
			"  - {phish_sub: 'b', orig_sub: 'b', domain: 'example.com', session: true, is_landing: true}\n" + tail
		p, err := load(t, content)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.proxyHosts[0].handle_session || p.proxyHosts[0].is_landing {
			t.Errorf("proxyHosts[0] = %+v, want no defaults (a later host already set session/landing)", p.proxyHosts[0])
		}
		if !p.proxyHosts[1].handle_session || !p.proxyHosts[1].is_landing {
			t.Errorf("proxyHosts[1] = %+v, want explicit session+landing honored", p.proxyHosts[1])
		}
	})
}

func TestNewPhishlet_ProxyHostsAutoFilterDefault(t *testing.T) {
	tail := "auth_tokens: []\ncredentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"
	content := "author: test\nmin_ver: '2.3.0'\n" +
		"proxy_hosts:\n" +
		"  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n" +
		"  - {phish_sub: 'x', orig_sub: 'x', domain: 'example.com', auto_filter: false}\n" + tail
	p, err := load(t, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.proxyHosts[0].auto_filter {
		t.Errorf("proxyHosts[0].auto_filter = false, want true (default when omitted)")
	}
	if p.proxyHosts[1].auto_filter {
		t.Errorf("proxyHosts[1].auto_filter = true, want false (explicit)")
	}
}

func TestAddProxyHost_LowercasesAndDedupesDomains(t *testing.T) {
	p := &Phishlet{}
	p.Clear()
	p.addProxyHost("LOGIN", "LOGIN", "EXAMPLE.COM", true, true, true)
	p.addProxyHost("WWW", "WWW", "example.com", false, false, true)

	if p.proxyHosts[0].phish_subdomain != "login" || p.proxyHosts[0].domain != "example.com" {
		t.Errorf("proxyHosts[0] = %+v, want lowercased", p.proxyHosts[0])
	}
	if len(p.domains) != 1 {
		t.Errorf("domains = %v, want deduped to 1 entry", p.domains)
	}
}

// ---------------------------------------------------------------------------
// sub_filters
// ---------------------------------------------------------------------------

func TestNewPhishlet_SubFiltersFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	tail := "auth_tokens: []\ncredentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		sf      string
		wantErr string
	}{
		{"missing triggers_on", "sub_filters:\n  - {orig_sub: '', domain: 'example.com', search: 'a', replace: 'b', mimes: ['text/html']}\n", "sub_filters: missing `triggers_on` field"},
		{"missing orig_sub", "sub_filters:\n  - {triggers_on: 'example.com', domain: 'example.com', search: 'a', replace: 'b', mimes: ['text/html']}\n", "sub_filters: missing `orig_sub` field"},
		{"missing domain", "sub_filters:\n  - {triggers_on: 'example.com', orig_sub: '', search: 'a', replace: 'b', mimes: ['text/html']}\n", "sub_filters: missing `domain` field"},
		{"missing mimes", "sub_filters:\n  - {triggers_on: 'example.com', orig_sub: '', domain: 'example.com', search: 'a', replace: 'b'}\n", "sub_filters: missing `mimes` field"},
		{"missing search", "sub_filters:\n  - {triggers_on: 'example.com', orig_sub: '', domain: 'example.com', replace: 'b', mimes: ['text/html']}\n", "sub_filters: missing `search` field"},
		{"missing replace", "sub_filters:\n  - {triggers_on: 'example.com', orig_sub: '', domain: 'example.com', search: 'a', mimes: ['text/html']}\n", "sub_filters: missing `replace` field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.sf + tail
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestAddSubFilter_Direct(t *testing.T) {
	p := &Phishlet{}
	p.Clear()
	p.addSubFilter("LOGIN.Example.COM", "Login", "EXAMPLE.com", []string{"TEXT/HTML", "Application/JSON"}, "foo", "bar", true, []string{"redir"})

	sf, ok := p.subfilters["login.example.com"]
	if !ok || len(sf) != 1 {
		t.Fatalf("subfilters = %v", p.subfilters)
	}
	got := sf[0]
	if got.subdomain != "login" || got.domain != "example.com" {
		t.Errorf("subdomain/domain not lowercased: %+v", got)
	}
	if got.mime[0] != "text/html" || got.mime[1] != "application/json" {
		t.Errorf("mime not lowercased: %v", got.mime)
	}
	if !got.redirect_only {
		t.Errorf("redirect_only = false, want true")
	}
	if len(got.with_params) != 1 || got.with_params[0] != "redir" {
		t.Errorf("with_params = %v", got.with_params)
	}
}

// ---------------------------------------------------------------------------
// auth_tokens
// ---------------------------------------------------------------------------

func TestNewPhishlet_AuthTokensUnknownType(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	tail := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"
	content := head + "auth_tokens:\n  - {domain: 'example.com', type: 'ftp', keys: ['a']}\n" + tail
	_, err := load(t, content)
	if err == nil || err.Error() != "auth_tokens: invalid token type: ftp" {
		t.Errorf("err = %v", err)
	}
}

func TestNewPhishlet_AuthTokensCookieFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	tail := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		at      string
		wantErr string
	}{
		{"missing domain", "auth_tokens:\n  - {keys: ['a']}\n", "auth_tokens: 'domain' not found for cookie auth token"},
		{"missing keys", "auth_tokens:\n  - {domain: 'example.com'}\n", "auth_tokens: 'keys' not found for cookie auth token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.at + tail
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPhishlet_AuthTokensBodyFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	tail := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		at      string
		wantErr string
	}{
		{"missing domain", "auth_tokens:\n  - {type: 'body', path: '/a', name: 'n', search: 's'}\n", "auth_tokens: 'domain' not found for body auth token"},
		{"missing path", "auth_tokens:\n  - {type: 'body', domain: 'd', name: 'n', search: 's'}\n", "auth_tokens: 'path' not found for body auth token"},
		{"missing name", "auth_tokens:\n  - {type: 'body', domain: 'd', path: '/a', search: 's'}\n", "auth_tokens: 'name' not found for body auth token"},
		{"missing search", "auth_tokens:\n  - {type: 'body', domain: 'd', path: '/a', name: 'n'}\n", "auth_tokens: 'search' not found for body auth token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.at + tail
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPhishlet_AuthTokensHttpFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	tail := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		at      string
		wantErr string
	}{
		{"missing domain", "auth_tokens:\n  - {type: 'http', path: '/a', name: 'n', header: 'H'}\n", "auth_tokens: 'domain' not found for http auth token"},
		{"missing path", "auth_tokens:\n  - {type: 'http', domain: 'd', name: 'n', header: 'H'}\n", "auth_tokens: 'path' not found for http auth token"},
		{"missing name", "auth_tokens:\n  - {type: 'http', domain: 'd', path: '/a', header: 'H'}\n", "auth_tokens: 'name' not found for http auth token"},
		{"missing header", "auth_tokens:\n  - {type: 'http', domain: 'd', path: '/a', name: 'n'}\n", "auth_tokens: 'header' not found for http auth token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.at + tail
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestAddCookieAuthTokens_Direct(t *testing.T) {
	p := &Phishlet{}
	p.Clear()

	t.Run("plain name", func(t *testing.T) {
		if err := p.addCookieAuthTokens("d1", []string{"sid"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		at := p.cookieAuthTokens["d1"][0]
		if at.name != "sid" || at.re != nil || at.optional || at.always {
			t.Errorf("token = %+v", at)
		}
	})

	t.Run("colon opt modifier", func(t *testing.T) {
		if err := p.addCookieAuthTokens("d2", []string{"tok:opt"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		at := p.cookieAuthTokens["d2"][0]
		if at.name != "tok" || !at.optional {
			t.Errorf("token = %+v", at)
		}
	})

	t.Run("colon always modifier", func(t *testing.T) {
		if err := p.addCookieAuthTokens("d3", []string{"tok:always"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		at := p.cookieAuthTokens["d3"][0]
		if !at.always {
			t.Errorf("token = %+v", at)
		}
	})

	t.Run("comma modifier variant", func(t *testing.T) {
		if err := p.addCookieAuthTokens("d4", []string{"tok,opt"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		at := p.cookieAuthTokens["d4"][0]
		if !at.optional {
			t.Errorf("token = %+v, want optional via comma form", at)
		}
	})

	t.Run("regexp modifier compiles name as pattern", func(t *testing.T) {
		if err := p.addCookieAuthTokens("d5", []string{"^tok[0-9]+$:regexp"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		at := p.cookieAuthTokens["d5"][0]
		if at.re == nil || !at.re.MatchString("tok123") {
			t.Errorf("token = %+v, want compiled regexp matching tok123", at)
		}
	})

	t.Run("regexp modifier with invalid pattern errors", func(t *testing.T) {
		err := p.addCookieAuthTokens("d6", []string{"(:regexp"})
		if err == nil {
			t.Fatal("expected error for invalid regexp name")
		}
		wantErr := "error parsing regexp: missing closing ): `(`"
		if err.Error() != wantErr {
			t.Errorf("err = %v, want %q", err, wantErr)
		}
	})
}

func TestAddBodyAuthToken_Direct(t *testing.T) {
	p := &Phishlet{}
	p.Clear()

	if err := p.addBodyAuthToken("d", "/api", "tok", "\"tok\":\"([^\"]*)\""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.bodyAuthTokens["tok"]; !ok {
		t.Fatalf("bodyAuthTokens missing tok")
	}

	if err := p.addBodyAuthToken("d", "(", "tok2", ".*"); err == nil {
		t.Error("expected error for invalid path regexp")
	}
	if err := p.addBodyAuthToken("d", ".*", "tok3", "("); err == nil {
		t.Error("expected error for invalid search regexp")
	}
}

func TestAddHttpAuthToken_Direct(t *testing.T) {
	p := &Phishlet{}
	p.Clear()

	if err := p.addHttpAuthToken("d", "/api", "tok", "X-Header"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.httpAuthTokens["tok"]; !ok {
		t.Fatalf("httpAuthTokens missing tok")
	}
	if err := p.addHttpAuthToken("d", "(", "tok2", "X-Header"); err == nil {
		t.Error("expected error for invalid path regexp")
	}
}

// TestNewPhishlet_AuthTokensBadRegexThroughLoadFromFile exercises the error
// return paths inside LoadFromFile's auth_tokens loop (as opposed to calling
// addCookieAuthTokens/addBodyAuthToken/addHttpAuthToken directly), so that
// the `if err != nil { return err }` lines right after each add* call are
// covered too, not just the add* functions themselves.
func TestNewPhishlet_AuthTokensBadRegexThroughLoadFromFile(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	tail := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name string
		at   string
	}{
		{"cookie regexp modifier bad pattern", "auth_tokens:\n  - {domain: 'd', keys: ['(:regexp']}\n"},
		{"body bad path regex", "auth_tokens:\n  - {type: 'body', domain: 'd', path: '(', name: 'n', search: 's'}\n"},
		{"body bad search regex", "auth_tokens:\n  - {type: 'body', domain: 'd', path: '/a', name: 'n', search: '('}\n"},
		{"http bad path regex", "auth_tokens:\n  - {type: 'http', domain: 'd', path: '(', name: 'n', header: 'H'}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.at + tail
			_, err := load(t, content)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewPhishlet_AuthUrlsBadRegex(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	tail := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\nlogin: {domain: 'example.com', path: '/'}\n"
	content := head + "auth_tokens: []\nauth_urls:\n  - '('\n" + tail

	_, err := load(t, content)
	wantErr := "error parsing regexp: missing closing ): `(`"
	if err == nil || err.Error() != wantErr {
		t.Errorf("err = %v, want %q", err, wantErr)
	}
	// cross-check against what regexp.Compile itself reports for the same
	// pattern, so this assertion tracks the stdlib rather than a hardcoded
	// string that could silently drift.
	_, wantCompileErr := regexp.Compile("(")
	if err.Error() != wantCompileErr.Error() {
		t.Errorf("err = %v, want match to regexp.Compile's own error %v", err, wantCompileErr)
	}
}

// ---------------------------------------------------------------------------
// credentials
// ---------------------------------------------------------------------------

func TestNewPhishlet_CredentialsFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	loginTail := "login: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		creds   string
		wantErr string
	}{
		{"missing username key", "credentials:\n  username: {search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n", "credentials: missing username `key` field"},
		{"missing username search", "credentials:\n  username: {key: 'u'}\n  password: {key: 'p', search: '(.*)'}\n", "credentials: missing username `search` field"},
		{"missing password key", "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {search: '(.*)'}\n", "credentials: missing password `key` field"},
		{"missing password search", "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p'}\n", "credentials: missing password `search` field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.creds + loginTail
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPhishlet_CredentialsBadRegex(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	loginTail := "login: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name  string
		creds string
	}{
		{"bad username key regex", "credentials:\n  username: {key: '(', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"},
		{"bad username search regex", "credentials:\n  username: {key: 'u', search: '('}\n  password: {key: 'p', search: '(.*)'}\n"},
		{"bad password key regex", "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: '(', search: '(.*)'}\n"},
		{"bad password search regex", "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '('}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.creds + loginTail
			_, err := load(t, content)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.HasPrefix(err.Error(), "credentials: ") {
				t.Errorf("err = %v, want prefixed with 'credentials: '", err)
			}
			if !strings.Contains(err.Error(), "missing closing )") {
				t.Errorf("err = %v, want to wrap a regexp compile error", err)
			}
		})
	}
}

func TestNewPhishlet_CredentialsUsernameTypeDefaultsToPost(t *testing.T) {
	content := "author: test\nmin_ver: '2.3.0'\n" +
		"proxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n" +
		"auth_tokens: []\n" +
		"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n" +
		"login: {domain: 'example.com', path: '/'}\n"
	p, err := load(t, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.username.tp != "post" || p.password.tp != "post" {
		t.Errorf("username.tp=%q password.tp=%q, want post/post", p.username.tp, p.password.tp)
	}
}

func TestNewPhishlet_CredentialsCustomFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	loginTail := "login: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		creds   string
		wantErr string
	}{
		{
			"missing custom key",
			"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n  custom:\n    - {search: '(.*)'}\n",
			"credentials: missing custom `key` field",
		},
		{
			"missing custom search",
			"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n  custom:\n    - {key: 'c'}\n",
			"credentials: missing custom `search` field",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.creds + loginTail
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestNewPhishlet_CredentialsCustomBadRegexThroughLoadFromFile hits both
// error-return statements for a custom credential's regex compile failures
// (custom.key wraps the error as "credentials: %v"; custom.search - unlike
// every other regex compile failure in this file - returns the bare
// regexp.Compile error unwrapped; see the report for this inconsistency).
func TestNewPhishlet_CredentialsCustomBadRegexThroughLoadFromFile(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	loginTail := "login: {domain: 'example.com', path: '/'}\n"

	t.Run("bad custom key regex is wrapped", func(t *testing.T) {
		content := head +
			"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n  custom:\n    - {key: '(', search: '(.*)'}\n" +
			loginTail
		_, err := load(t, content)
		if err == nil || !strings.HasPrefix(err.Error(), "credentials: ") {
			t.Errorf("err = %v, want prefixed with 'credentials: '", err)
		}
	})

	t.Run("bad custom search regex is returned unwrapped", func(t *testing.T) {
		content := head +
			"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n  custom:\n    - {key: 'c', search: '('}\n" +
			loginTail
		_, err := load(t, content)
		if err == nil {
			t.Fatal("expected error")
		}
		_, wantErr := regexp.Compile("(")
		if err.Error() != wantErr.Error() {
			t.Errorf("err = %v, want the bare regexp.Compile error %v (unwrapped, unlike custom.key)", err, wantErr)
		}
	})
}

func TestNewPhishlet_CredentialsCustomTypeDefaultsToPost(t *testing.T) {
	content := "author: test\nmin_ver: '2.3.0'\n" +
		"proxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n" +
		"auth_tokens: []\n" +
		"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n  custom:\n    - {key: 'c', search: '(.*)'}\n" +
		"login: {domain: 'example.com', path: '/'}\n"
	p, err := load(t, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.custom) != 1 || p.custom[0].tp != "post" {
		t.Errorf("custom = %+v, want tp defaulted to post", p.custom)
	}
}

// TestNewPhishlet_CredentialsCustomAsSingleMap documents a real-world shape:
// several shipped phishlets (e.g. tiktok.yaml) write `custom:` as a single
// mapping rather than a one-item list. Viper's WeaklyTypedInput decoding
// wraps a lone map into a one-element slice, so this parses successfully.
func TestNewPhishlet_CredentialsCustomAsSingleMap(t *testing.T) {
	content := "author: test\nmin_ver: '2.3.0'\n" +
		"proxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n" +
		"auth_tokens: []\n" +
		"credentials:\n" +
		"  username: {key: 'u', search: '(.*)'}\n" +
		"  password: {key: 'p', search: '(.*)'}\n" +
		"  custom:\n" +
		"    key: 'mobile'\n" +
		"    search: '(.*)'\n" +
		"    type: 'post'\n" +
		"login: {domain: 'example.com', path: '/'}\n"
	p, err := load(t, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.custom) != 1 || p.custom[0].key_s != "mobile" {
		t.Errorf("custom = %+v, want single mobile entry", p.custom)
	}
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

func TestNewPhishlet_LoginFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	creds := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"

	cases := []struct {
		name    string
		login   string
		wantErr string
	}{
		{"missing domain", "login: {path: '/'}\n", "login: missing `domain` field"},
		{"missing path", "login: {domain: 'example.com'}\n", "login: missing `path` field"},
		{"empty domain", "login: {domain: '', path: '/'}\n", "login: `domain` field cannot be empty"},
		{
			"domain not in proxy_hosts",
			"login: {domain: 'not-registered.example.com', path: '/'}\n",
			"login: `domain` must contain a value of one of the hostnames (`orig_subdomain` + `domain`) defined in `proxy_hosts` section",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + creds + tc.login
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPhishlet_LoginPathDefaultsAndNormalizes(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	creds := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"

	t.Run("empty path defaults to /", func(t *testing.T) {
		p, err := load(t, head+creds+"login: {domain: 'example.com', path: ''}\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.login.path != "/" {
			t.Errorf("login.path = %q, want /", p.login.path)
		}
	})

	t.Run("path without leading slash is prefixed", func(t *testing.T) {
		p, err := load(t, head+creds+"login: {domain: 'example.com', path: 'signin'}\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.login.path != "/signin" {
			t.Errorf("login.path = %q, want /signin", p.login.path)
		}
	})

	t.Run("domain match is case-insensitive against orig_sub+domain", func(t *testing.T) {
		content := "author: test\nmin_ver: '2.3.0'\n" +
			"proxy_hosts:\n  - {phish_sub: 'Login', orig_sub: 'Login', domain: 'Example.COM', session: true, is_landing: true}\n" +
			"auth_tokens: []\n" + creds + "login: {domain: 'LOGIN.example.com', path: '/'}\n"
		p, err := load(t, content)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.login.domain != "LOGIN.example.com" {
			t.Errorf("login.domain = %q", p.login.domain)
		}
	})
}

func TestGetLoginUrl(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "https://login.example.com/signin"
	if got := p.GetLoginUrl(); got != want {
		t.Errorf("GetLoginUrl() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// force_post
// ---------------------------------------------------------------------------

func TestNewPhishlet_ForcePostFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	creds := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"
	login := "login: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		fp      string
		wantErr string
	}{
		{"missing path", "force_post:\n  - {type: 'post', force: [{key: 'k', value: 'v'}]}\n", "force_post: missing or empty `path` field"},
		{"empty path", "force_post:\n  - {path: '', type: 'post', force: [{key: 'k', value: 'v'}]}\n", "force_post: missing or empty `path` field"},
		{"missing type", "force_post:\n  - {path: '/a', force: [{key: 'k', value: 'v'}]}\n", "force_post: unknown type - only 'post' is currently supported"},
		{"wrong type", "force_post:\n  - {path: '/a', type: 'json', force: [{key: 'k', value: 'v'}]}\n", "force_post: unknown type - only 'post' is currently supported"},
		{"missing force", "force_post:\n  - {path: '/a', type: 'post'}\n", "force_post: missing or empty `force` field"},
		{"empty force", "force_post:\n  - {path: '/a', type: 'post', force: []}\n", "force_post: missing or empty `force` field"},
		{"search missing key", "force_post:\n  - {path: '/a', type: 'post', search: [{search: 's'}], force: [{key: 'k', value: 'v'}]}\n", "force_post: missing search `key` field"},
		{"search missing search", "force_post:\n  - {path: '/a', type: 'post', search: [{key: 'k'}], force: [{key: 'k', value: 'v'}]}\n", "force_post: missing search `search` field"},
		{"force missing key", "force_post:\n  - {path: '/a', type: 'post', force: [{value: 'v'}]}\n", "force_post: missing force `key` field"},
		{"force missing value", "force_post:\n  - {path: '/a', type: 'post', force: [{key: 'k'}]}\n", "force_post: missing force `value` field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + creds + login + tc.fp
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPhishlet_ForcePostBadRegex(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	creds := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"
	login := "login: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name string
		fp   string
	}{
		{"bad path regex", "force_post:\n  - {path: '(', type: 'post', force: [{key: 'k', value: 'v'}]}\n"},
		{"bad search key regex", "force_post:\n  - {path: '/a', type: 'post', search: [{key: '(', search: 's'}], force: [{key: 'k', value: 'v'}]}\n"},
		{"bad search search regex", "force_post:\n  - {path: '/a', type: 'post', search: [{key: 'k', search: '('}], force: [{key: 'k', value: 'v'}]}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + creds + login + tc.fp
			_, err := load(t, content)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "missing closing )") {
				t.Errorf("err = %v, want a regexp compile failure", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// js_inject
// ---------------------------------------------------------------------------

func TestNewPhishlet_JsInjectFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	creds := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"
	login := "login: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		js      string
		wantErr string
	}{
		{"missing trigger_domains", "js_inject:\n  - {trigger_paths: ['/a'], script: 's'}\n", "js_inject: missing `trigger_domains` field"},
		{"missing trigger_paths", "js_inject:\n  - {trigger_domains: ['example.com'], script: 's'}\n", "js_inject: missing `trigger_paths` field"},
		{"missing script", "js_inject:\n  - {trigger_domains: ['example.com'], trigger_paths: ['/a']}\n", "js_inject: missing `script` field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + creds + login + tc.js
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPhishlet_JsInjectBadTriggerPathRegex(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\nauth_tokens: []\n"
	creds := "credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"
	login := "login: {domain: 'example.com', path: '/'}\n"
	js := "js_inject:\n  - {trigger_domains: ['example.com'], trigger_paths: ['('], script: 's'}\n"

	_, err := load(t, head+creds+login+js)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.HasPrefix(err.Error(), "js_inject: ") {
		t.Errorf("err = %v, want prefixed with js_inject:", err)
	}
}

func TestAddJsInject_TriggerPathsAreAnchored(t *testing.T) {
	p := &Phishlet{}
	p.Clear()
	if err := p.addJsInject([]string{"Example.COM"}, []string{"/foo"}, nil, "s"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.js_inject[0].trigger_domains[0] != "example.com" {
		t.Errorf("trigger_domains not lowercased: %v", p.js_inject[0].trigger_domains)
	}
	re := p.js_inject[0].trigger_paths[0]
	if !re.MatchString("/foo") {
		t.Errorf("expected /foo to match anchored pattern")
	}
	if re.MatchString("/foobar") {
		t.Errorf("pattern is anchored with ^...$, /foobar should not match plain /foo")
	}
}

func TestGetScriptInject(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	params := map[string]string{"email": "victim@example.com"}
	id, script, err := p.GetScriptInject("login.example.com", "/signin", &params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == "" {
		t.Errorf("id is empty")
	}
	if !strings.Contains(script, "victim@example.com") {
		t.Errorf("script = %q, want {email} substituted", script)
	}

	if _, _, err := p.GetScriptInject("other.example.com", "/signin", &params); err == nil {
		t.Errorf("expected 'script not found' for non-matching host")
	}
	if _, _, err := p.GetScriptInject("login.example.com", "/other", &params); err == nil {
		t.Errorf("expected 'script not found' for non-matching path")
	}

	missingParams := map[string]string{}
	if _, _, err := p.GetScriptInject("login.example.com", "/signin", &missingParams); err == nil {
		t.Errorf("expected 'script not found' when required trigger_params are absent")
	}

	// A nil params pointer is treated as "no trigger_params required" and
	// short-circuits straight to a match (params_matched = true).
	if id2, script2, err2 := p.GetScriptInject("login.example.com", "/signin", nil); err2 != nil || id2 == "" || strings.Contains(script2, "victim@example.com") {
		t.Errorf("GetScriptInject with nil params: id=%q script=%q err=%v, want a match with placeholders left unsubstituted", id2, script2, err2)
	}

	got, err := p.GetScriptInjectById(id, &params)
	if err != nil || !strings.Contains(got, "victim@example.com") {
		t.Errorf("GetScriptInjectById = %q, err=%v", got, err)
	}
	if _, err := p.GetScriptInjectById("bogus-id", &params); err == nil {
		t.Errorf("expected error for unknown id")
	}
}

// ---------------------------------------------------------------------------
// intercept
// ---------------------------------------------------------------------------

func TestNewPhishlet_InterceptFieldValidation(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	creds := "auth_tokens: []\ncredentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"
	login := "login: {domain: 'example.com', path: '/'}\n"

	cases := []struct {
		name    string
		ic      string
		wantErr string
	}{
		{"missing domain", "intercept:\n  - {path: '/a', http_status: 404}\n", "intercept: missing `domain` field"},
		{"empty domain", "intercept:\n  - {domain: '', path: '/a', http_status: 404}\n", "intercept: `domain` field cannot be empty"},
		{"missing path", "intercept:\n  - {domain: 'd', http_status: 404}\n", "intercept: missing `path` field"},
		{"missing http_status", "intercept:\n  - {domain: 'd', path: '/a'}\n", "intercept: missing `http_status` field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := head + tc.ic + creds + login
			_, err := load(t, content)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPhishlet_InterceptBadPathRegex(t *testing.T) {
	head := "author: test\nmin_ver: '2.3.0'\nproxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n"
	creds := "auth_tokens: []\ncredentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n"
	login := "login: {domain: 'example.com', path: '/'}\n"
	ic := "intercept:\n  - {domain: 'd', path: '(', http_status: 404}\n"

	_, err := load(t, head+ic+creds+login)
	if err == nil || !strings.Contains(err.Error(), "intercept: `path` invalid regular expression") {
		t.Errorf("err = %v", err)
	}
}

func TestAddIntercept_Direct(t *testing.T) {
	p := &Phishlet{}
	p.Clear()
	re := regexp.MustCompile("/blocked")
	if err := p.addIntercept("EXAMPLE.com", re, 403, "body", "text/plain"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.intercept) != 1 || p.intercept[0].domain != "example.com" {
		t.Errorf("intercept = %+v, want lowercased domain", p.intercept)
	}
}

// ---------------------------------------------------------------------------
// landing_path
// ---------------------------------------------------------------------------

func TestNewPhishlet_LandingPathParamSubstitution(t *testing.T) {
	content := "author: test\nmin_ver: '2.3.0'\n" +
		"params:\n  - {name: 'tok', default: 'abc', required: false}\n" +
		"proxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n" +
		"auth_tokens: []\n" +
		"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n" +
		"login: {domain: 'example.com', path: '/'}\n" +
		"landing_path:\n  - '/signin?t={tok}'\n"
	customParams := map[string]string{"tok": "xyz"}
	p, err := loadWithParams(t, content, &customParams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.landing_path[0] != "/signin?t=xyz" {
		t.Errorf("landing_path = %v, want param substituted", p.landing_path)
	}
}

// ---------------------------------------------------------------------------
// params / templates
// ---------------------------------------------------------------------------

func minimalTemplateHead(params string) string {
	return "author: test\nmin_ver: '2.3.0'\n" + params +
		"proxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: '{domain}', session: true, is_landing: true}\n" +
		"auth_tokens: []\n" +
		"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n" +
		"login: {domain: '{domain}', path: '/'}\n"
}

func TestNewPhishlet_ParamsTemplateMode(t *testing.T) {
	content := minimalTemplateHead(
		"params:\n  - {name: 'domain', required: true}\n  - {name: 'opt', default: 'fallback', required: false}\n",
	)
	// customParams == nil => template/catalog mode: fields keep their {placeholders}.
	p, err := loadWithParams(t, content, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.isTemplate {
		t.Errorf("isTemplate = false, want true when params are defined and no values supplied")
	}
	if p.customParams["domain"] != "(required)" {
		t.Errorf("customParams[domain] = %q, want (required) marker", p.customParams["domain"])
	}
	if p.customParams["opt"] != "fallback" {
		t.Errorf("customParams[opt] = %q, want default fallback", p.customParams["opt"])
	}
	// In template mode the placeholders themselves are preserved verbatim.
	if p.login.domain != "{domain}" {
		t.Errorf("login.domain = %q, want literal placeholder in template mode", p.login.domain)
	}
}

func TestNewPhishlet_ParamsMissingRequiredValue(t *testing.T) {
	content := minimalTemplateHead("params:\n  - {name: 'domain', required: true}\n")
	customParams := map[string]string{}
	_, err := loadWithParams(t, content, &customParams)
	if err == nil {
		t.Fatal("expected error for missing required param")
	}
	if !strings.HasPrefix(err.Error(), "missing custom parameter values during initalization:") {
		t.Errorf("err = %v", err)
	}
}

func TestNewPhishlet_ParamsSubstitutedWhenSupplied(t *testing.T) {
	content := minimalTemplateHead("params:\n  - {name: 'domain', required: true}\n")
	customParams := map[string]string{"domain": "victim.example.com"}
	p, err := loadWithParams(t, content, &customParams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.isTemplate {
		t.Errorf("isTemplate = true, want false once concrete values are supplied")
	}
	if p.login.domain != "victim.example.com" {
		t.Errorf("login.domain = %q, want substituted value", p.login.domain)
	}
}

func TestNewPhishlet_ParamsUnknownKeyIsDroppedNotFatal(t *testing.T) {
	content := minimalTemplateHead("params:\n  - {name: 'domain', required: true}\n")
	customParams := map[string]string{"domain": "victim.example.com", "bogus": "x"}
	p, err := loadWithParams(t, content, &customParams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := customParams["bogus"]; ok {
		t.Errorf("customParams still contains unknown key %q; want it removed", "bogus")
	}
	if p.login.domain != "victim.example.com" {
		t.Errorf("login.domain = %q", p.login.domain)
	}
}

func TestParamVal(t *testing.T) {
	p := &Phishlet{customParams: map[string]string{"x": "1", "y": "2"}, isTemplate: false}
	if got := p.paramVal("a{x}b{y}c"); got != "a1b2c" {
		t.Errorf("paramVal = %q", got)
	}

	pTemplate := &Phishlet{customParams: map[string]string{"x": "1"}, isTemplate: true}
	if got := pTemplate.paramVal("a{x}b"); got != "a{x}b" {
		t.Errorf("paramVal in template mode = %q, want placeholder preserved", got)
	}
}

// ---------------------------------------------------------------------------
// domainExists / getAuthToken / isAuthToken / isTokenHttpOnly / MimeExists
// ---------------------------------------------------------------------------

func TestDomainExists(t *testing.T) {
	p := &Phishlet{}
	p.Clear()
	p.addProxyHost("", "", "example.com", true, true, true)
	if !p.domainExists("example.com") {
		t.Errorf("domainExists(example.com) = false, want true")
	}
	if p.domainExists("other.com") {
		t.Errorf("domainExists(other.com) = true, want false")
	}
}

func TestGetAuthTokenAndVariants(t *testing.T) {
	p := &Phishlet{}
	p.Clear()
	if err := p.addCookieAuthTokens("d", []string{"sid", "^csrf[0-9]+$:regexp"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if at := p.getAuthToken("d", "sid"); at == nil || at.name != "sid" {
		t.Errorf("getAuthToken(d, sid) = %v", at)
	}
	if at := p.getAuthToken("d", "csrf42"); at == nil {
		t.Errorf("getAuthToken(d, csrf42) = nil, want regexp match")
	}
	if at := p.getAuthToken("d", "nope"); at != nil {
		t.Errorf("getAuthToken(d, nope) = %v, want nil", at)
	}
	if at := p.getAuthToken("other-domain", "sid"); at != nil {
		t.Errorf("getAuthToken(other-domain, sid) = %v, want nil", at)
	}

	if !p.isAuthToken("d", "sid") {
		t.Errorf("isAuthToken(d, sid) = false")
	}
	if p.isAuthToken("d", "nope") {
		t.Errorf("isAuthToken(d, nope) = true")
	}
	// sid carries no :http_only modifier, so it keeps today's default; see
	// TestCookieAuthToken_HttpOnlyModifier and
	// TestNewPhishlet_CookieAuthTokenHttpOnlyModifier for the opt-in case.
	if p.isTokenHttpOnly("d", "sid") {
		t.Errorf("isTokenHttpOnly(d, sid) = true, want false")
	}
	if p.isTokenHttpOnly("d", "no-such-token") {
		t.Errorf("isTokenHttpOnly(d, no-such-token) = true, want false (token not found)")
	}
}

// TestCookieAuthToken_HttpOnlyModifier verifies that the ":http_only"
// modifier - the same colon-suffix form used by ":opt", ":always" and
// ":regexp" - sets CookieAuthToken.http_only, and that only that exact,
// case-sensitive spelling is recognized: plausible near-misses an operator
// might type ("httponly", "HttpOnly") are left unrecognized and keep the
// default of false, exactly like any other unrecognized modifier. A key
// without any modifier also keeps today's default.
func TestCookieAuthToken_HttpOnlyModifier(t *testing.T) {
	p := &Phishlet{}
	p.Clear()

	cases := []struct {
		domain string
		tok    string
		want   bool
	}{
		{"d1", "sid", false},        // no modifier: today's default
		{"d2", "b:http_only", true}, // exact spelling: recognized
		{"d3", "a:httponly", false}, // missing underscore: not recognized
		{"d4", "c:HttpOnly", false}, // wrong case: not recognized
	}
	for _, c := range cases {
		if err := p.addCookieAuthTokens(c.domain, []string{c.tok}); err != nil {
			t.Fatalf("unexpected error for %q: %v", c.tok, err)
		}
		tk := p.cookieAuthTokens[c.domain][0]
		if tk.http_only != c.want {
			t.Errorf("addCookieAuthTokens(%q, %q): http_only = %v, want %v", c.domain, c.tok, tk.http_only, c.want)
		}
	}
}

// TestNewPhishlet_CookieAuthTokenHttpOnlyModifier exercises the
// ":http_only" modifier through the full YAML parse path (LoadFromFile) and
// confirms isTokenHttpOnly() reflects the parsed value for both an opted-in
// and a default token, and that omitting the modifier changes nothing about
// existing phishlet behavior.
func TestNewPhishlet_CookieAuthTokenHttpOnlyModifier(t *testing.T) {
	content := `
author: test
min_ver: '2.3.0'
proxy_hosts:
  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}
auth_tokens:
  - domain: 'example.com'
    keys: ['sid', 'sess:http_only']
credentials:
  username: {key: 'u', search: '(.*)'}
  password: {key: 'p', search: '(.*)'}
login: {domain: 'example.com', path: '/'}
`
	p, err := load(t, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cookies := p.cookieAuthTokens["example.com"]
	if len(cookies) != 2 {
		t.Fatalf("cookieAuthTokens[example.com] = %+v, want 2 entries", cookies)
	}
	if cookies[0].name != "sid" || cookies[0].http_only {
		t.Errorf("cookies[0] = %+v, want sid with http_only=false (today's default)", cookies[0])
	}
	if cookies[1].name != "sess" || !cookies[1].http_only {
		t.Errorf("cookies[1] = %+v, want sess with http_only=true (:http_only modifier)", cookies[1])
	}

	if p.isTokenHttpOnly("example.com", "sid") {
		t.Errorf("isTokenHttpOnly(example.com, sid) = true, want false (no :http_only modifier)")
	}
	if !p.isTokenHttpOnly("example.com", "sess") {
		t.Errorf("isTokenHttpOnly(example.com, sess) = false, want true (:http_only modifier set)")
	}
}

func TestMimeExists_AlwaysFalse(t *testing.T) {
	p := &Phishlet{}
	if p.MimeExists("text/html") {
		t.Errorf("MimeExists = true, want false (stub always returns false)")
	}
}

// ---------------------------------------------------------------------------
// GetPhishHosts / GetLureUrl / GetLandingPhishHost / GenerateTokenSet
// ---------------------------------------------------------------------------

func TestGetPhishHosts(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p.cfg = testCfg("site", "evil.io", "evil.io")

	hosts := p.GetPhishHosts(false)
	if len(hosts) != 2 || hosts[0] != "login.evil.io" || hosts[1] != "www.evil.io" {
		t.Errorf("GetPhishHosts(false) = %v", hosts)
	}

	wildcard := p.GetPhishHosts(true)
	if len(wildcard) != 1 || wildcard[0] != "*.evil.io" {
		t.Errorf("GetPhishHosts(true) = %v", wildcard)
	}

	// site not registered in cfg.phishletConfig => GetSiteDomain not ok => nil slice
	p.cfg = testCfg("other-site", "evil.io", "evil.io")
	if got := p.GetPhishHosts(false); got != nil {
		t.Errorf("GetPhishHosts with unregistered site = %v, want nil", got)
	}
}

func TestGetLureUrl(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p.cfg = testCfg("site", "evil.io", "base.example")

	got, err := p.GetLureUrl("/x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "https://login.evil.io/x"
	if got != want {
		t.Errorf("GetLureUrl = %q, want %q", got, want)
	}

	// If the site is not registered, GetLureUrl falls back to the base domain.
	p.cfg = testCfg("other-site", "evil.io", "base.example")
	got, err = p.GetLureUrl("/x")
	if err != nil || got != "https://base.example/x" {
		t.Errorf("GetLureUrl fallback = %q, err=%v", got, err)
	}
}

func TestGetLandingPhishHost(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p.cfg = testCfg("site", "evil.io", "evil.io")
	if got := p.GetLandingPhishHost(); got != "login.evil.io" {
		t.Errorf("GetLandingPhishHost = %q, want login.evil.io", got)
	}

	p.cfg = testCfg("other-site", "evil.io", "evil.io")
	if got := p.GetLandingPhishHost(); got != "" {
		t.Errorf("GetLandingPhishHost unregistered = %q, want empty", got)
	}
}

func TestGenerateTokenSet(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokens := map[string]string{
		"sessid":  "abc",
		"unknown": "ignored",
	}
	set := p.GenerateTokenSet(tokens)
	dom, ok := set[".login.example.com"]
	if !ok {
		t.Fatalf("GenerateTokenSet result missing domain key: %v", set)
	}
	if dom["sessid"] != "abc" {
		t.Errorf("token set = %v, want sessid=abc", dom)
	}
	if _, ok := dom["unknown"]; ok {
		t.Errorf("token set contains unrecognized token %v", dom)
	}
}

// ---------------------------------------------------------------------------
// Clear()
// ---------------------------------------------------------------------------

func TestClear_ResetsParsedCollections(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p.Clear()

	if p.Name != "" || p.Author != "" {
		t.Errorf("Name/Author not cleared: %q / %q", p.Name, p.Author)
	}
	if p.Path != "" {
		t.Errorf("Path not cleared: %q", p.Path)
	}
	if p.RedirectUrl != "" {
		t.Errorf("RedirectUrl not cleared: %q", p.RedirectUrl)
	}
	if p.Version != (PhishletVersion{}) {
		t.Errorf("Version not cleared: %+v", p.Version)
	}
	if p.login != (LoginUrl{}) {
		t.Errorf("login not cleared: %+v", p.login)
	}
	if len(p.landing_path) != 0 {
		t.Errorf("landing_path not cleared: %v", p.landing_path)
	}
	if len(p.js_inject) != 0 {
		t.Errorf("js_inject not cleared: %v", p.js_inject)
	}
	if len(p.intercept) != 0 {
		t.Errorf("intercept not cleared: %v", p.intercept)
	}
	if len(p.proxyHosts) != 0 || len(p.domains) != 0 {
		t.Errorf("proxyHosts/domains not cleared")
	}
	if len(p.subfilters) != 0 || len(p.cookieAuthTokens) != 0 || len(p.bodyAuthTokens) != 0 || len(p.httpAuthTokens) != 0 {
		t.Errorf("auth/subfilter maps not cleared")
	}
	if len(p.authUrls) != 0 || p.username.key != nil || p.password.key != nil || len(p.custom) != 0 || len(p.forcePost) != 0 {
		t.Errorf("credential/forcePost state not cleared")
	}
	if p.username.tp != "" || p.username.key_s != "" || p.password.tp != "" || p.password.key_s != "" {
		t.Errorf("username/password tp and key_s not cleared: username=%+v password=%+v", p.username, p.password)
	}
	if len(p.customParams) != 0 || p.isTemplate {
		t.Errorf("customParams/isTemplate not cleared")
	}
}

// TestClear_ReloadSameObjectMatchesFreshLoad reloads the same *Phishlet
// object with identical content and asserts the result matches a single
// fresh load: no duplicated js_inject or intercept entries. Before the
// Clear() fix, js_inject and intercept were append-only, so a reload
// doubled their length instead of matching a fresh load.
func TestClear_ReloadSameObjectMatchesFreshLoad(t *testing.T) {
	fresh, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error loading fresh phishlet: %v", err)
	}
	if len(fresh.js_inject) == 0 || len(fresh.intercept) == 0 {
		t.Fatalf("fixture must define at least one js_inject and intercept entry")
	}

	reused, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error loading reused phishlet: %v", err)
	}

	// Reload the SAME phishlet object with the same fully valid content.
	path := writeYAML(t, fullValidPhishlet)
	if err := reused.LoadFromFile("site", path, nil); err != nil {
		t.Fatalf("unexpected error on reload: %v", err)
	}

	if len(reused.js_inject) != len(fresh.js_inject) {
		t.Errorf("js_inject len after reload = %d, want %d (matching a single fresh load, not duplicated)", len(reused.js_inject), len(fresh.js_inject))
	}
	if len(reused.intercept) != len(fresh.intercept) {
		t.Errorf("intercept len after reload = %d, want %d (matching a single fresh load, not duplicated)", len(reused.intercept), len(fresh.intercept))
	}
	for i := range fresh.js_inject {
		f, r := fresh.js_inject[i], reused.js_inject[i]
		if r.script != f.script || strings.Join(r.trigger_domains, ",") != strings.Join(f.trigger_domains, ",") || strings.Join(r.trigger_params, ",") != strings.Join(f.trigger_params, ",") {
			t.Errorf("js_inject[%d] after reload = %+v, want to match a fresh load %+v", i, r, f)
		}
	}
	for i := range fresh.intercept {
		f, r := fresh.intercept[i], reused.intercept[i]
		if r.domain != f.domain || r.http_status != f.http_status || r.body != f.body || r.mime != f.mime || r.path.String() != f.path.String() {
			t.Errorf("intercept[%d] after reload = %+v, want to match a fresh load %+v", i, r, f)
		}
	}
}

// TestClear_StaleLandingPathDoesNotSurviveAFailedReload covers the sharper
// edge of the same gap: when a second LoadFromFile call on the same object
// fails partway through (here, at force_post validation, which runs before
// landing_path is parsed), the *previous* load's landing_path must not be
// left in place - Clear() zeroes it at the top of LoadFromFile, and the
// failing load never reaches the code that would repopulate it, so it must
// stay cleared rather than leak the first load's value.
func TestClear_StaleLandingPathDoesNotSurviveAFailedReload(t *testing.T) {
	first := "author: test\nmin_ver: '2.3.0'\n" +
		"proxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n" +
		"auth_tokens: []\n" +
		"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n" +
		"login: {domain: 'example.com', path: '/'}\n" +
		"landing_path:\n  - '/from-first-load'\n"
	p, err := load(t, first)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.landing_path) != 1 || p.landing_path[0] != "/from-first-load" {
		t.Fatalf("landing_path after first load = %v", p.landing_path)
	}

	// Second load is valid through login, then fails in force_post - before
	// the point where landing_path would be (re)assigned.
	second := "author: test\nmin_ver: '2.3.0'\n" +
		"proxy_hosts:\n  - {phish_sub: '', orig_sub: '', domain: 'example.com', session: true, is_landing: true}\n" +
		"auth_tokens: []\n" +
		"credentials:\n  username: {key: 'u', search: '(.*)'}\n  password: {key: 'p', search: '(.*)'}\n" +
		"login: {domain: 'example.com', path: '/'}\n" +
		"force_post:\n  - {path: '', type: 'post', force: [{key: 'k', value: 'v'}]}\n" +
		"landing_path:\n  - '/from-second-load'\n"
	path := writeYAML(t, second)
	err = p.LoadFromFile("site", path, nil)
	if err == nil {
		t.Fatal("expected the second load to fail at force_post validation")
	}

	if len(p.landing_path) != 0 {
		t.Errorf("landing_path after failed reload = %v, want empty (Clear() must not leave the first load's value in place)", p.landing_path)
	}
}

// TestClear_MalformedReloadLeavesNoStaleState loads a valid phishlet, then
// attempts to load a malformed (unparseable) file into the same object. The
// malformed load fails inside c.ReadInConfig(), before LoadFromFile
// reassigns any field, so only Clear() stands between this call and stale
// data from the first load surviving on every field the parser owns.
func TestClear_MalformedReloadLeavesNoStaleState(t *testing.T) {
	p, err := load(t, fullValidPhishlet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.RedirectUrl == "" || p.login.domain == "" || len(p.landing_path) == 0 || len(p.js_inject) == 0 || len(p.intercept) == 0 {
		t.Fatalf("fixture must populate RedirectUrl/login/landing_path/js_inject/intercept for this test to be meaningful")
	}

	malformedPath := writeYAML(t, "not: [valid: yaml")
	err = p.LoadFromFile("site", malformedPath, nil)
	if err == nil {
		t.Fatal("expected malformed YAML to fail parsing")
	}

	if p.Name != "" {
		t.Errorf("Name after failed reload = %q, want \"\" (stale value from first load survived)", p.Name)
	}
	if p.RedirectUrl != "" {
		t.Errorf("RedirectUrl after failed reload = %q, want \"\" (stale value from first load survived)", p.RedirectUrl)
	}
	if p.Version != (PhishletVersion{}) {
		t.Errorf("Version after failed reload = %+v, want zero value (stale value from first load survived)", p.Version)
	}
	if p.login != (LoginUrl{}) {
		t.Errorf("login after failed reload = %+v, want zero value (stale value from first load survived)", p.login)
	}
	if len(p.landing_path) != 0 {
		t.Errorf("landing_path after failed reload = %v, want empty (stale value from first load survived)", p.landing_path)
	}
	if len(p.js_inject) != 0 {
		t.Errorf("js_inject after failed reload = %v, want empty (stale value from first load survived)", p.js_inject)
	}
	if len(p.intercept) != 0 {
		t.Errorf("intercept after failed reload = %v, want empty (stale value from first load survived)", p.intercept)
	}
}
