package jsinspect

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInjectHTML(t *testing.T) {
	middleware := newTestMiddleware(t, ActionBlock)
	body := []byte(`<!doctype html><HTML><head class="app"><title>Olta</title></head><body></body></HTML>`)

	injected := middleware.InjectHTML(body)
	text := string(injected)
	if !strings.Contains(text, `<head class="app"><script data-olta-js-inspect>`) {
		t.Fatalf("InjectHTML() did not inject immediately after head: %s", text)
	}
	if !strings.Contains(text, middleware.Endpoint()) {
		t.Errorf("InjectHTML() script does not contain endpoint %q", middleware.Endpoint())
	}
	if got := middleware.InjectHTML(injected); string(got) != text {
		t.Fatal("InjectHTML() injected the script more than once")
	}
	fragment := []byte(`<div>no head</div>`)
	if got := middleware.InjectHTML(fragment); string(got) != string(fragment) {
		t.Fatalf("InjectHTML() changed fragment without head: %s", got)
	}
}

func TestScriptGeneration(t *testing.T) {
	middleware, err := New(Config{Enabled: true, Endpoint: "/internal/check.js", Action: ActionBlock})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	script := string(middleware.Script())
	for _, expected := range []string{
		`navigator.webdriver`, `window.callPhantom`, `WEBGL_debug_renderer_info`,
		`swiftshader|llvmpipe|mesa`, `toDataURL()`, `"/internal/check.js"`,
		`window.PublicKeyCredential`, `isUserVerifyingPlatformAuthenticatorAvailable`,
		`isConditionalMediationAvailable`, `navigator.credentials`, `opts.publicKey`,
		`orig.apply(this,arguments)`,
	} {
		if !strings.Contains(script, expected) {
			t.Errorf("Script() does not contain %q", expected)
		}
	}
}

func TestParseAssertion(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantErr        bool
		wantSuspicious bool
	}{
		{
			name: "legitimate browser",
			body: `{"version":1,"webdriver":false,"headless":false,"phantom":false,"renderer":"ANGLE (Apple, Apple M2, Metal)","software_renderer":false,"canvas_consistent":true}`,
		},
		{
			name:           "webdriver",
			body:           `{"version":1,"webdriver":true,"headless":false,"phantom":false,"renderer":"ANGLE","software_renderer":false,"canvas_consistent":true}`,
			wantSuspicious: true,
		},
		{
			name:           "renderer is checked server side",
			body:           `{"version":1,"webdriver":false,"headless":false,"phantom":false,"renderer":"Google SwiftShader","software_renderer":false,"canvas_consistent":true}`,
			wantSuspicious: true,
		},
		{name: "unsupported version", body: `{"version":2}`, wantErr: true},
		{name: "unknown field", body: `{"version":1,"extra":true}`, wantErr: true},
		{name: "invalid JSON", body: `{`, wantErr: true},
		{
			// An older injected script (before the WebAuthn fields
			// existed) never sends these keys. The assertion must still
			// parse, with every new field defaulting to false.
			name: "older script without webauthn fields",
			body: `{"version":1,"webdriver":false,"headless":false,"phantom":false,"renderer":"ANGLE","software_renderer":false,"canvas_consistent":true}`,
		},
		{
			// A browser lacking every WebAuthn API still produces a valid
			// assertion: the script guards each check, so the fields are
			// present but false rather than causing a throw that would
			// have broken headless/canvas detection too.
			name: "browser lacking webauthn apis",
			body: `{"version":1,"canvas_consistent":true,"webauthn_supported":false,"platform_authenticator_available":false,"conditional_mediation_supported":false,"conditional_mediation_available":false,"webauthn_ceremony_observed":false}`,
		},
		{
			name: "full webauthn capability and ceremony observed",
			body: `{"version":1,"canvas_consistent":true,"webauthn_supported":true,"platform_authenticator_available":true,"conditional_mediation_supported":true,"conditional_mediation_available":true,"webauthn_ceremony_observed":true}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertion, err := ParseAssertion(strings.NewReader(test.body))
			if (err != nil) != test.wantErr {
				t.Fatalf("ParseAssertion() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && assertion.Suspicious() != test.wantSuspicious {
				t.Errorf("Suspicious() = %v, want %v", assertion.Suspicious(), test.wantSuspicious)
			}
		})
	}
}

// TestParseAssertionWebAuthnFieldsAreOptional pins backward compatibility
// for the new fields directly: an assertion missing them decodes with every
// one at its zero value (false), and one carrying them decodes their exact
// values, rather than the decoder rejecting either shape.
func TestParseAssertionWebAuthnFieldsAreOptional(t *testing.T) {
	older, err := ParseAssertion(strings.NewReader(`{"version":1,"canvas_consistent":true}`))
	if err != nil {
		t.Fatalf("older assertion without webauthn fields: ParseAssertion() error = %v", err)
	}
	if older.WebAuthnSupported || older.PlatformAuthenticatorAvailable ||
		older.ConditionalMediationSupported || older.ConditionalMediationAvailable ||
		older.WebAuthnCeremonyObserved {
		t.Fatalf("older assertion = %+v, want every webauthn field false", older)
	}

	full, err := ParseAssertion(strings.NewReader(
		`{"version":1,"canvas_consistent":true,"webauthn_supported":true,` +
			`"platform_authenticator_available":true,"conditional_mediation_supported":true,` +
			`"conditional_mediation_available":true,"webauthn_ceremony_observed":true}`))
	if err != nil {
		t.Fatalf("full assertion: ParseAssertion() error = %v", err)
	}
	if !full.WebAuthnSupported || !full.PlatformAuthenticatorAvailable ||
		!full.ConditionalMediationSupported || !full.ConditionalMediationAvailable ||
		!full.WebAuthnCeremonyObserved {
		t.Fatalf("full assertion = %+v, want every webauthn field true", full)
	}
	// New fields must never make an otherwise-clean assertion suspicious.
	if full.Suspicious() {
		t.Fatal("Suspicious() = true for a clean assertion with webauthn fields set")
	}
}

func TestHandleRequest(t *testing.T) {
	t.Run("legitimate POST", func(t *testing.T) {
		middleware := newTestMiddleware(t, ActionBlock)
		request := httptest.NewRequest(http.MethodPost, "https://example.test"+middleware.Endpoint(), strings.NewReader(`{"version":1,"renderer":"ANGLE","canvas_consistent":true}`))
		response, handled := middleware.HandleRequest(request)
		if !handled || response.StatusCode != http.StatusNoContent {
			t.Fatalf("HandleRequest() = handled %v, status %d; want true, %d", handled, response.StatusCode, http.StatusNoContent)
		}
	})

	t.Run("suspicious GET redirects", func(t *testing.T) {
		middleware := newTestMiddleware(t, ActionRedirect)
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"version":1,"webdriver":true,"canvas_consistent":true}`))
		request := httptest.NewRequest(http.MethodGet, "https://example.test"+middleware.Endpoint()+"?assertion="+payload, nil)
		response, handled := middleware.HandleRequest(request)
		if !handled || response.StatusCode != http.StatusFound {
			t.Fatalf("HandleRequest() = handled %v, status %d; want true, %d", handled, response.StatusCode, http.StatusFound)
		}
		if got := response.Header.Get("Location"); got != "https://safe.example/" {
			t.Errorf("Location = %q, want safe URL", got)
		}
	})

	t.Run("suspicious GET blocks", func(t *testing.T) {
		middleware := newTestMiddleware(t, ActionBlock)
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"version":1,"renderer":"llvmpipe","canvas_consistent":true}`))
		request := httptest.NewRequest(http.MethodGet, "https://example.test"+middleware.Endpoint()+"?assertion="+payload, nil)
		response, handled := middleware.HandleRequest(request)
		if !handled || response.StatusCode != http.StatusForbidden {
			t.Fatalf("HandleRequest() = handled %v, status %d; want true, %d", handled, response.StatusCode, http.StatusForbidden)
		}
	})

	t.Run("unrelated request", func(t *testing.T) {
		middleware := newTestMiddleware(t, ActionBlock)
		request := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
		response, handled := middleware.HandleRequest(request)
		if handled || response != nil {
			t.Fatalf("HandleRequest() = handled %v, response %#v; want pass-through", handled, response)
		}
	})
}

func TestNewRejectsInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{"relative", "https://example.test/check", "/check?x=1", "/"} {
		if _, err := New(Config{Enabled: true, Endpoint: endpoint, Action: ActionBlock}); err == nil {
			t.Errorf("New() endpoint %q error = nil, want error", endpoint)
		}
	}
}

func newTestMiddleware(t *testing.T, action Action) *Middleware {
	t.Helper()
	middleware, err := New(Config{
		Enabled:     true,
		Endpoint:    "/_assets/js/v.js",
		Action:      action,
		RedirectURL: "https://safe.example/",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return middleware
}
