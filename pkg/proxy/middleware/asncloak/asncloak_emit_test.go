package asncloak

import (
	"net/http"
	"net/http/httptest"
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

func TestEvaluateEmitsBlockedCloakEvent(t *testing.T) {
	emitter := &captureEmitter{}
	middleware, err := New(Config{
		Enabled:        true,
		Action:         ActionBlock,
		BlockStatus:    404,
		InspectHeaders: true,
		Emitter:        emitter,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	request.Header.Set("User-Agent", "curl/8.4.0")
	request.RemoteAddr = "203.0.113.9:51234"

	if _, matched := middleware.Evaluate(request); !matched {
		t.Fatal("Evaluate() did not match a suspicious user agent")
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	event := events[0]
	if event.Stage != telemetry.StageCloak {
		t.Fatalf("Stage = %q", event.Stage)
	}
	if event.Outcome != telemetry.OutcomeBlocked {
		t.Fatalf("Outcome = %q, want blocked for ActionBlock", event.Outcome)
	}
	if len(event.Techniques) != 1 || event.Techniques[0] != telemetry.TechniqueProxy {
		t.Fatalf("Techniques = %v", event.Techniques)
	}
	if event.RID != "" || event.CampaignID != 0 {
		t.Fatal("cloak events fire before lure validation and must be unattributed")
	}
	if event.Detail["rule"] != "user-agent" {
		t.Fatalf("Detail = %v", event.Detail)
	}
}

func TestEvaluateEmitsRedirectOutcome(t *testing.T) {
	emitter := &captureEmitter{}
	middleware, err := New(Config{
		Enabled:        true,
		Action:         ActionRedirect,
		RedirectURL:    "https://www.google.com/",
		InspectHeaders: true,
		Emitter:        emitter,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	request.Header.Set("User-Agent", "python-requests/2.31.0")
	if _, matched := middleware.Evaluate(request); !matched {
		t.Fatal("Evaluate() did not match")
	}

	events := emitter.all()
	if len(events) != 1 || events[0].Outcome != telemetry.OutcomeRedirected {
		t.Fatalf("events = %+v, want one redirected outcome", events)
	}
}

func TestEvaluateEmitsNothingWhenRequestIsClean(t *testing.T) {
	emitter := &captureEmitter{}
	middleware, err := New(Config{Enabled: true, Action: ActionBlock, BlockStatus: 404, Emitter: emitter})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	if _, matched := middleware.Evaluate(request); matched {
		t.Fatal("clean request should not match")
	}
	if len(emitter.all()) != 0 {
		t.Fatal("a clean request must not emit a cloak event")
	}
}

func TestNilEmitterIsSafe(t *testing.T) {
	middleware, err := New(Config{Enabled: true, Action: ActionBlock, BlockStatus: 404, InspectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	request.Header.Set("User-Agent", "curl/8.4.0")
	if _, matched := middleware.Evaluate(request); !matched {
		t.Fatal("Evaluate() did not match")
	}
	// Reaching here without a panic is the assertion.
}
