package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/s4l1hs/olta/pkg/proxy/middleware/asncloak"
	"github.com/s4l1hs/olta/pkg/proxy/middleware/jsinspect"
	"github.com/s4l1hs/olta/pkg/telemetry"
	feedsink "github.com/s4l1hs/olta/pkg/telemetry/sink/feed"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/jsonl"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/webhook"

	feedserver "github.com/s4l1hs/olta/pkg/feed"
)

// recordingSink is an in-test telemetry.Sink that keeps every event it
// receives, so assertions can be made directly against what reached a sink
// rather than against the bus or the middleware that produced the event.
type recordingSink struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (s *recordingSink) Emit(_ context.Context, event telemetry.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *recordingSink) Close() error { return nil }

func (s *recordingSink) all() []telemetry.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]telemetry.Event(nil), s.events...)
}

// webhookRecorder is an httptest server standing in for a defender's SOC
// webhook (Slack/Discord/generic). It records every request body it
// receives so the test can assert on the payload actually posted over HTTP,
// not on anything the webhook sink built internally.
type webhookRecorder struct {
	server *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
}

func newWebhookRecorder() *webhookRecorder {
	r := &webhookRecorder{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.bodies = append(r.bodies, body)
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return r
}

func (r *webhookRecorder) all() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.bodies...)
}

func (r *webhookRecorder) Close() { r.server.Close() }

// wsEndpoint converts an httptest server's http(s) URL into a ws(s) endpoint
// at the given path, mirroring the helper already used by pkg/feed's own
// tests (pkg/feed/feed_test.go's websocketEndpoint).
func wsEndpoint(serverURL, path string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + path
}

// feedEnvelope mirrors the unexported message type that
// pkg/telemetry/sink/feed wraps every event in.
type feedEnvelope struct {
	Type  string          `json:"type"`
	Event telemetry.Event `json:"event"`
}

// TestTelemetryPipeline_ReachesEverySinkWithoutLoot proves that a proxy-side
// detection - the cloaker and the JS environment inspector, the two
// middlewares HttpProxy wires an Emitter into via ConfigureCloaker and
// ConfigureJSInspect - produces an event that actually arrives at every
// configured sink through the real telemetry.Bus, and that the no-loot
// guarantee (telemetry.Event.WithDetail redacts loot-shaped keys) survives
// intact all the way through JSONL-on-disk and an HTTP webhook body.
//
// The feed sink is included: pkg/feed exposes an http.Handler
// (feed.Handler) that runs standalone under httptest.NewServer with no
// production TCP listener, so the whole publish/subscribe path is driven
// without a live production feed server.
func TestTelemetryPipeline_ReachesEverySinkWithoutLoot(t *testing.T) {
	// --- sinks -------------------------------------------------------
	jsonlPath := filepath.Join(t.TempDir(), "events.jsonl")
	jsonlSink, err := jsonl.New(jsonlPath)
	if err != nil {
		t.Fatalf("jsonl.New() error: %v", err)
	}

	webhookRec := newWebhookRecorder()
	defer webhookRec.Close()
	webhookSink, err := webhook.New(webhookRec.server.URL, webhookRec.server.Client())
	if err != nil {
		t.Fatalf("webhook.New() error: %v", err)
	}

	feedServer := httptest.NewServer(feedserver.Handler(t.TempDir()))
	defer feedServer.Close()
	feedEndpoint := wsEndpoint(feedServer.URL, "")
	feedSink := feedsink.New(feedEndpoint)

	recorder := &recordingSink{}

	bus := telemetry.NewBus(16, jsonlSink, webhookSink, feedSink, recorder)

	// --- drive the real proxy-side emitters ---------------------------
	cloaker, err := asncloak.New(asncloak.Config{
		Enabled:        true,
		Action:         asncloak.ActionBlock,
		BlockStatus:    http.StatusNotFound,
		InspectHeaders: true,
		Emitter:        bus,
	})
	if err != nil {
		t.Fatalf("asncloak.New() error: %v", err)
	}
	cloakRequest := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	cloakRequest.Header.Set("User-Agent", "curl/8.4.0")
	cloakRequest.RemoteAddr = "203.0.113.9:51234"
	if _, matched := cloaker.Evaluate(cloakRequest); !matched {
		t.Fatal("cloaker did not match a suspicious user agent")
	}

	inspector, err := jsinspect.New(jsinspect.Config{
		Enabled:  true,
		Endpoint: "/_assets/js/v.js",
		Action:   jsinspect.ActionBlock,
		Emitter:  bus,
	})
	if err != nil {
		t.Fatalf("jsinspect.New() error: %v", err)
	}
	assertionBody := `{"version":1,"webdriver":true,"headless":true,"canvas_consistent":true}`
	verifyRequest := httptest.NewRequest(http.MethodPost, "https://lure.example/_assets/js/v.js", strings.NewReader(assertionBody))
	verifyRequest.Header.Set("User-Agent", "Mozilla/5.0")
	if _, handled := inspector.HandleRequest(verifyRequest); !handled {
		t.Fatal("jsinspect did not handle the verification endpoint")
	}

	// --- the no-loot invariant, driven straight at the same bus -------
	//
	// Neither asncloak nor jsinspect ever populate a "password" or "cookie"
	// detail key, so the only way to exercise the redaction guarantee
	// end-to-end is to build an event carrying one, exactly as a future
	// stage (e.g. credential capture) would, and push it through the same
	// real bus and sinks the detections above used.
	const plaintextPassword = "hunter2-PLAINTEXT-MARKER"
	const plaintextCookie = "SESSID=abcdef123456-MARKER"
	lootEvent := telemetry.New(telemetry.StageCredential, telemetry.OutcomeCaptured, telemetry.TechniqueWebPortalCapture).
		WithDetail("password", plaintextPassword).
		WithDetail("cookie", plaintextCookie).
		WithDetail("field", "login_form")
	bus.Emit(lootEvent)

	// Bus.Emit is fire-and-forget; Close() drains the queue and blocks until
	// every sink has been called (or timed out), so asserting after Close()
	// avoids sleeping for the queue to flush.
	if err := bus.Close(); err != nil {
		t.Fatalf("bus.Close() error: %v", err)
	}
	if dropped := bus.Dropped(); dropped != 0 {
		t.Fatalf("bus dropped %d events, want 0", dropped)
	}
	if failed := bus.Failed(); failed != 0 {
		t.Fatalf("bus recorded %d sink failures, want 0", failed)
	}

	// --- assert on the recording sink ---------------------------------
	events := recorder.all()
	if len(events) != 3 {
		t.Fatalf("recordingSink received %d events, want 3", len(events))
	}
	var sawCloak, sawVerify, sawLoot bool
	for _, event := range events {
		switch event.Stage {
		case telemetry.StageCloak:
			sawCloak = true
			if !hasTechnique(event.Techniques, telemetry.TechniqueProxy) {
				t.Errorf("cloak event techniques = %v, want %v", event.Techniques, telemetry.TechniqueProxy)
			}
		case telemetry.StageVerify:
			sawVerify = true
			if !hasTechnique(event.Techniques, telemetry.TechniqueSandboxEvasion) {
				t.Errorf("verify event techniques = %v, want %v", event.Techniques, telemetry.TechniqueSandboxEvasion)
			}
		case telemetry.StageCredential:
			sawLoot = true
			if event.Detail["password"] != "[redacted]" {
				t.Errorf("recordingSink Detail[password] = %v, want [redacted]", event.Detail["password"])
			}
			if event.Detail["cookie"] != "[redacted]" {
				t.Errorf("recordingSink Detail[cookie] = %v, want [redacted]", event.Detail["cookie"])
			}
			if event.Detail["field"] != "login_form" {
				t.Errorf("recordingSink Detail[field] = %v, want login_form (non-loot keys must pass through)", event.Detail["field"])
			}
		}
	}
	if !sawCloak || !sawVerify || !sawLoot {
		t.Fatalf("recordingSink missing an expected stage: cloak=%v verify=%v credential=%v", sawCloak, sawVerify, sawLoot)
	}

	// --- assert on the JSONL sink file ---------------------------------
	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("reading jsonl file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(jsonlBytes), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("jsonl file has %d lines, want 3:\n%s", len(lines), jsonlBytes)
	}
	var jsonlSawCloak, jsonlSawVerify bool
	for _, line := range lines {
		var event telemetry.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("jsonl line is not valid JSON: %v\nline: %s", err, line)
		}
		switch event.Stage {
		case telemetry.StageCloak:
			jsonlSawCloak = hasTechnique(event.Techniques, telemetry.TechniqueProxy)
		case telemetry.StageVerify:
			jsonlSawVerify = hasTechnique(event.Techniques, telemetry.TechniqueSandboxEvasion)
		}
	}
	if !jsonlSawCloak {
		t.Error("jsonl file is missing the cloak/T1090 event")
	}
	if !jsonlSawVerify {
		t.Error("jsonl file is missing the verify/T1497 event")
	}
	if strings.Contains(string(jsonlBytes), plaintextPassword) {
		t.Fatal("jsonl file contains the plaintext password - the no-loot guarantee was violated")
	}
	if strings.Contains(string(jsonlBytes), plaintextCookie) {
		t.Fatal("jsonl file contains the plaintext cookie - the no-loot guarantee was violated")
	}

	// --- assert on the webhook sink -------------------------------------
	bodies := webhookRec.all()
	if len(bodies) != 3 {
		t.Fatalf("webhook received %d requests, want 3", len(bodies))
	}
	var webhookSawCloak, webhookSawVerify bool
	var combined strings.Builder
	for _, body := range bodies {
		if !json.Valid(body) {
			t.Fatalf("webhook body is not valid JSON: %s", body)
		}
		combined.Write(body)
		if strings.Contains(string(body), string(telemetry.TechniqueProxy)) {
			webhookSawCloak = true
		}
		if strings.Contains(string(body), string(telemetry.TechniqueSandboxEvasion)) {
			webhookSawVerify = true
		}
	}
	if !webhookSawCloak {
		t.Error("no webhook body named the cloak technique T1090")
	}
	if !webhookSawVerify {
		t.Error("no webhook body named the verify technique T1497")
	}
	if strings.Contains(combined.String(), plaintextPassword) {
		t.Fatal("a webhook body contains the plaintext password - the no-loot guarantee was violated")
	}
	if strings.Contains(combined.String(), plaintextCookie) {
		t.Fatal("a webhook body contains the plaintext cookie - the no-loot guarantee was violated")
	}

	// --- assert on the feed sink -----------------------------------------
	//
	// The feed sink dials, writes, and closes synchronously inside Emit, and
	// bus.Close() already waited for every Emit call to return - so by this
	// point the server has received all three writes on the wire. What is
	// not yet guaranteed is that the server's own goroutine has finished
	// pushing each into the hub's replay history, which happens over an
	// unbuffered channel a moment later; pkg/feed's own tests
	// (TestFeedReplaysBoundedHistory) hit the same gap and close it with a
	// short sleep rather than a synchronization primitive the package does
	// not expose, so this test follows the same established pattern.
	time.Sleep(50 * time.Millisecond)

	viewer, _, err := websocket.DefaultDialer.Dial(wsEndpoint(feedServer.URL, "/ws"), nil)
	if err != nil {
		t.Fatalf("dialing feed viewer: %v", err)
	}
	defer viewer.Close()
	if err := viewer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	var feedSawCloak, feedSawVerify bool
	feedMessages := 0
	var feedCombined strings.Builder
	for feedMessages < 3 {
		_, raw, err := viewer.ReadMessage()
		if err != nil {
			t.Fatalf("reading feed history (got %d/3 messages): %v", feedMessages, err)
		}
		feedMessages++
		feedCombined.Write(raw)
		var envelope feedEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("feed message is not a valid envelope: %v\nmessage: %s", err, raw)
		}
		if envelope.Type != "telemetry.v1" {
			t.Errorf("feed envelope type = %q, want telemetry.v1", envelope.Type)
		}
		switch envelope.Event.Stage {
		case telemetry.StageCloak:
			feedSawCloak = hasTechnique(envelope.Event.Techniques, telemetry.TechniqueProxy)
		case telemetry.StageVerify:
			feedSawVerify = hasTechnique(envelope.Event.Techniques, telemetry.TechniqueSandboxEvasion)
		}
	}
	if !feedSawCloak {
		t.Error("feed history is missing the cloak/T1090 event")
	}
	if !feedSawVerify {
		t.Error("feed history is missing the verify/T1497 event")
	}
	if strings.Contains(feedCombined.String(), plaintextPassword) {
		t.Fatal("a feed message contains the plaintext password - the no-loot guarantee was violated")
	}
	if strings.Contains(feedCombined.String(), plaintextCookie) {
		t.Fatal("a feed message contains the plaintext cookie - the no-loot guarantee was violated")
	}
}

func hasTechnique(techniques []telemetry.Technique, want telemetry.Technique) bool {
	for _, technique := range techniques {
		if technique == want {
			return true
		}
	}
	return false
}
