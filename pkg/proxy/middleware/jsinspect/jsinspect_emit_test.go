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

	events := emitter.all()
	if len(events) != 1 || events[0].Outcome != telemetry.OutcomeAllowed {
		t.Fatalf("events = %+v, want one allowed outcome", events)
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
