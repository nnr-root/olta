package validation_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/proxy/database"
	"github.com/s4l1hs/olta/pkg/proxy/validation"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

type blockingValidator struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (validator *blockingValidator) Validate(_ context.Context, event validation.Event) validation.Result {
	validator.once.Do(func() { close(validator.started) })
	<-validator.release
	return validation.Result{Status: validation.StatusValid, Identity: event.Identity}
}

func TestWorkerQueuesWithoutBlockingAndDrains(t *testing.T) {
	validator := &blockingValidator{started: make(chan struct{}), release: make(chan struct{})}
	results := make(chan validation.Result, 2)
	worker, err := validation.NewWorker(validation.WorkerConfig{
		Workers:   1,
		QueueSize: 1,
		Validator: validator,
		OnResult:  func(result validation.Result) { results <- result },
	})
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}

	if err := worker.Enqueue(testEvent("session-1")); err != nil {
		t.Fatalf("Enqueue(first) error = %v", err)
	}
	select {
	case <-validator.started:
	case <-time.After(time.Second):
		t.Fatal("validator did not start")
	}
	if err := worker.Enqueue(testEvent("session-2")); err != nil {
		t.Fatalf("Enqueue(second) error = %v", err)
	}
	if err := worker.Enqueue(testEvent("session-3")); !errors.Is(err, validation.ErrQueueFull) {
		t.Fatalf("Enqueue(full) error = %v, want ErrQueueFull", err)
	}
	if err := worker.Enqueue(testEvent("session-2")); !errors.Is(err, validation.ErrDuplicateEvent) {
		t.Fatalf("Enqueue(duplicate) error = %v, want ErrDuplicateEvent", err)
	}

	close(validator.release)
	worker.Close()
	close(results)
	count := 0
	for range results {
		count++
	}
	if count != 2 {
		t.Fatalf("processed results = %d, want 2", count)
	}
	if err := worker.Enqueue(testEvent("session-4")); !errors.Is(err, validation.ErrWorkerClosed) {
		t.Fatalf("Enqueue(closed) error = %v, want ErrWorkerClosed", err)
	}
}

func TestHTTPValidatorSendsCookiesAndExtractsMetadata(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if cookie := request.Header.Get("Cookie"); !strings.Contains(cookie, "session=secret-value") {
			t.Fatalf("Cookie header = %q, want captured session cookie", cookie)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"tenantId":"tenant-42","organization":"SOC Lab"}`)),
			Request:    request,
		}, nil
	})
	validator := validation.NewHTTPValidator(&http.Client{Transport: transport})
	result := validator.Validate(context.Background(), testEvent("session-http"))
	if result.Status != validation.StatusValid {
		t.Errorf("status = %q, want valid", result.Status)
	}
	if result.Identity.TenantID != "tenant-42" || result.Identity.Organization != "SOC Lab" {
		t.Errorf("identity = %+v, want extracted tenant and organization", result.Identity)
	}
}

type capturingEmitter struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (e *capturingEmitter) Emit(event telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *capturingEmitter) all() []telemetry.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]telemetry.Event(nil), e.events...)
}

type statusValidator struct{ status validation.Status }

func (v statusValidator) Validate(_ context.Context, event validation.Event) validation.Result {
	return validation.Result{Status: v.status, Identity: event.Identity}
}

func TestWorkerEmitsReplayTelemetryPerResult(t *testing.T) {
	cases := []struct {
		name    string
		status  validation.Status
		outcome telemetry.Outcome
	}{
		{"valid session survives replay", validation.StatusValid, telemetry.OutcomeAllowed},
		{"invalid session was blocked", validation.StatusInvalid, telemetry.OutcomeBlocked},
		{"error maps to failed", validation.StatusError, telemetry.OutcomeFailed},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			emitter := &capturingEmitter{}
			done := make(chan struct{})
			worker, err := validation.NewWorker(validation.WorkerConfig{
				Workers:   1,
				QueueSize: 1,
				Validator: statusValidator{status: testCase.status},
				Emitter:   emitter,
				OnResult:  func(validation.Result) { close(done) },
			})
			if err != nil {
				t.Fatalf("NewWorker() error = %v", err)
			}
			if err := worker.Enqueue(testEvent("replay-" + string(testCase.status))); err != nil {
				t.Fatalf("Enqueue() error = %v", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("validator did not complete")
			}
			worker.Close()

			events := emitter.all()
			if len(events) != 1 {
				t.Fatalf("emitted %d events, want 1", len(events))
			}
			if events[0].Stage != telemetry.StageReplay {
				t.Fatalf("Stage = %q, want replay", events[0].Stage)
			}
			if events[0].Outcome != testCase.outcome {
				t.Fatalf("Outcome = %q, want %q", events[0].Outcome, testCase.outcome)
			}
			if events[0].Techniques[0] != telemetry.TechniqueWebSessionCookie {
				t.Fatalf("Techniques = %v, want [%q]", events[0].Techniques, telemetry.TechniqueWebSessionCookie)
			}
		})
	}
}

func TestWorkerIsSafeWithNoEmitter(t *testing.T) {
	done := make(chan struct{})
	worker, err := validation.NewWorker(validation.WorkerConfig{
		Workers:   1,
		QueueSize: 1,
		Validator: statusValidator{status: validation.StatusValid},
		OnResult:  func(validation.Result) { close(done) },
	})
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	if err := worker.Enqueue(testEvent("no-emitter")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("validator did not complete")
	}
	worker.Close()
	// Reaching here without a panic is the assertion.
}

// Webhook payload formatting moved to pkg/telemetry/sink/webhook along with
// the dispatcher it used to belong to (see webhook_test.go's
// TestSinkPostsEvent and TestSinkCarriesNoLoot for the equivalent coverage
// against telemetry.Event, which is what the payload builder takes now).

func TestNewEventExtractsAllowlistedMetadata(t *testing.T) {
	event, err := validation.NewEvent(&database.Session{
		SessionId: "sid",
		Phishlet:  "o365",
		Username:  "user@example.test",
		Custom: map[string]string{
			"tenant_id": "tenant-42",
			"org":       "SOC Lab",
			"password":  "must-not-be-extracted",
		},
		CookieTokens: map[string]map[string]*database.CookieToken{
			".example.test": {"session": {Name: "session", Value: "secret-value"}},
		},
	})
	if err != nil {
		t.Fatalf("NewEvent() error = %v", err)
	}
	if event.TargetURL != "https://example.test/" {
		t.Errorf("TargetURL = %q, want https://example.test/", event.TargetURL)
	}
	if event.Identity.TenantID != "tenant-42" || event.Identity.Organization != "SOC Lab" {
		t.Errorf("Identity = %+v, want allowlisted metadata", event.Identity)
	}
}

func testEvent(sessionID string) validation.Event {
	return validation.Event{
		SessionID: sessionID,
		Phishlet:  "o365",
		TargetURL: "https://example.test/",
		Identity:  validation.Identity{Username: "analyst@example.test"},
		Cookies: map[string]map[string]*database.CookieToken{
			"example.test": {"session": {Name: "session", Value: "secret-value", Path: "/", HttpOnly: true}},
		},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
