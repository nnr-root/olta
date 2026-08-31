package jsinspect

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

type captureEmitter struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (e *captureEmitter) Emit(event telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *captureEmitter) all() []telemetry.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]telemetry.Event(nil), e.events...)
}

func newMiddleware(t *testing.T, emitter telemetry.Emitter) *Middleware {
	t.Helper()
	middleware, err := New(Config{
		Enabled:     true,
		Endpoint:    "/_assets/js/v.js",
		Action:      ActionBlock,
		RedirectURL: "https://www.google.com/",
		Emitter:     emitter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return middleware
}

func assertionRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://lure.example/_assets/js/v.js", strings.NewReader(body))
	request.Header.Set("User-Agent", "Mozilla/5.0")
	return request
}

func TestHandleRequestEmitsBlockedOnSuspiciousAssertion(t *testing.T) {
	emitter := &captureEmitter{}
	middleware := newMiddleware(t, emitter)

	body := `{"version":1,"webdriver":true,"headless":true,"canvas_consistent":true}`
	if _, handled := middleware.HandleRequest(assertionRequest(body)); !handled {
		t.Fatal("HandleRequest() did not handle the verification endpoint")
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	event := events[0]
	if event.Stage != telemetry.StageVerify {
		t.Fatalf("Stage = %q", event.Stage)
	}
	if event.Outcome != telemetry.OutcomeBlocked {
		t.Fatalf("Outcome = %q", event.Outcome)
	}
	if len(event.Techniques) != 1 || event.Techniques[0] != telemetry.TechniqueSandboxEvasion {
		t.Fatalf("Techniques = %v", event.Techniques)
	}
	if event.Detail["webdriver"] != true || event.Detail["headless"] != true {
		t.Fatalf("Detail = %v", event.Detail)
	}
}

func TestHandleRequestEmitsAllowedOnCleanAssertion(t *testing.T) {
	emitter := &captureEmitter{}
	middleware := newMiddleware(t, emitter)

	body := `{"version":1,"renderer":"ANGLE (NVIDIA GeForce RTX 3060)","canvas_consistent":true}`
	if _, handled := middleware.HandleRequest(assertionRequest(body)); !handled {
		t.Fatal("HandleRequest() did not handle the verification endpoint")
	}

	// A non-suspicious assertion now emits two events: the existing
	// bot/automation StageVerify, and StageWebAuthn carrying the passkey
	// capability/ceremony signal from the same assertion.
	events := emitter.all()
	if len(events) != 2 {
		t.Fatalf("events = %+v, want 2 (verify + webauthn)", events)
	}
	if events[0].Stage != telemetry.StageVerify || events[0].Outcome != telemetry.OutcomeAllowed {
		t.Fatalf("events[0] = %+v, want verify/allowed", events[0])
	}
	if events[1].Stage != telemetry.StageWebAuthn || events[1].Outcome != telemetry.OutcomeAllowed {
		t.Fatalf("events[1] = %+v, want webauthn/allowed", events[1])
	}
}

// TestHandleRequestSuppressesWebAuthnForSuspiciousAssertion pins that
// StageWebAuthn is only emitted for the non-suspicious path: the
// suspicious/blocked path in generateScript redirects the browser away
// before it ever runs the capability or ceremony-observation checks, so
// there is nothing genuine to report, and emitting a zero-valued event
// would misrepresent "never checked" as "checked, found nothing".
func TestHandleRequestSuppressesWebAuthnForSuspiciousAssertion(t *testing.T) {
	emitter := &captureEmitter{}
	middleware := newMiddleware(t, emitter)

	body := `{"version":1,"webdriver":true,"headless":true,"canvas_consistent":true}`
	if _, handled := middleware.HandleRequest(assertionRequest(body)); !handled {
		t.Fatal("HandleRequest() did not handle the verification endpoint")
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("events = %+v, want 1 (verify only)", events)
	}
	if events[0].Stage != telemetry.StageVerify {
		t.Fatalf("events[0].Stage = %q, want verify", events[0].Stage)
	}
}

// TestWebAuthnEventCarriesOnlyScalarCapabilityBooleans is the no-loot
// pinning test for the new stage: the assertion's WebAuthn fields must
// reach telemetry as plain scalar booleans, and the detail map must
// contain nothing that looks like credential material, a challenge, or a
// user handle -- capability and ceremony-occurred booleans only.
func TestWebAuthnEventCarriesOnlyScalarCapabilityBooleans(t *testing.T) {
	emitter := &captureEmitter{}
	middleware := newMiddleware(t, emitter)

	body := `{"version":1,"renderer":"ANGLE","canvas_consistent":true,` +
		`"webauthn_supported":true,"platform_authenticator_available":true,` +
		`"conditional_mediation_supported":true,"conditional_mediation_available":true,` +
		`"webauthn_ceremony_observed":true}`
	if _, handled := middleware.HandleRequest(assertionRequest(body)); !handled {
		t.Fatal("HandleRequest() did not handle the verification endpoint")
	}

	events := emitter.all()
	if len(events) != 2 {
		t.Fatalf("events = %+v, want 2", events)
	}
	webauthn := events[1]
	if webauthn.Stage != telemetry.StageWebAuthn {
		t.Fatalf("events[1].Stage = %q, want webauthn", webauthn.Stage)
	}
	if len(webauthn.Techniques) != 0 {
		t.Fatalf("Techniques = %v, want none: a passkey control is not adversary behavior", webauthn.Techniques)
	}
	wantKeys := []string{
		"webauthn_supported", "platform_authenticator_available",
		"conditional_mediation_supported", "conditional_mediation_available",
		"webauthn_ceremony_observed",
	}
	if len(webauthn.Detail) != len(wantKeys) {
		t.Fatalf("Detail = %v, want exactly %v", webauthn.Detail, wantKeys)
	}
	for _, key := range wantKeys {
		value, ok := webauthn.Detail[key]
		if !ok {
			t.Fatalf("Detail missing key %q: %v", key, webauthn.Detail)
		}
		b, ok := value.(bool)
		if !ok || !b {
			t.Fatalf("Detail[%q] = %#v (%T), want scalar bool true", key, value, value)
		}
	}
	for _, forbidden := range []string{"challenge", "credential_id", "user_handle", "signature", "attestation"} {
		if _, present := webauthn.Detail[forbidden]; present {
			t.Fatalf("Detail unexpectedly carries %q -- credential material must never reach telemetry", forbidden)
		}
	}
}

func TestHandleRequestEmitsNothingForUnrelatedPath(t *testing.T) {
	emitter := &captureEmitter{}
	middleware := newMiddleware(t, emitter)

	request := httptest.NewRequest(http.MethodGet, "https://lure.example/login", nil)
	if _, handled := middleware.HandleRequest(request); handled {
		t.Fatal("unrelated path should not be handled")
	}
	if len(emitter.all()) != 0 {
		t.Fatal("unrelated path must not emit a verify event")
	}
}

func TestNilEmitterIsSafe(t *testing.T) {
	middleware := newMiddleware(t, nil)
	body := `{"version":1,"webdriver":true,"canvas_consistent":true}`
	if _, handled := middleware.HandleRequest(assertionRequest(body)); !handled {
		t.Fatal("HandleRequest() did not handle the verification endpoint")
	}
	// Reaching here without a panic is the assertion.
}
