package e2e

import (
	"context"
	"database/sql"
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

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"

	"github.com/gorilla/websocket"

	"github.com/s4l1hs/olta/pkg/campaign/migrations"
	feedserver "github.com/s4l1hs/olta/pkg/feed"
	"github.com/s4l1hs/olta/pkg/proxy/database"
	"github.com/s4l1hs/olta/pkg/proxy/validation"
	"github.com/s4l1hs/olta/pkg/telemetry"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/campaigndb"
	feedsink "github.com/s4l1hs/olta/pkg/telemetry/sink/feed"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/jsonl"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/webhook"
)

// recordingSink is an in-test telemetry.Sink that keeps every event it
// receives, mirroring the helper pkg/proxy/core/telemetry_integration_test.go
// uses for the same purpose: asserting directly against what reached a sink
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

// webhookRecorder stands in for a defender's SOC webhook and records every
// request body it receives, so assertions run against what was actually
// posted over HTTP rather than against the sink's internal state.
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
// at the given path, mirroring pkg/proxy/core/telemetry_integration_test.go
// and pkg/feed/feed_test.go's own helper of the same name.
func wsEndpoint(serverURL, path string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + path
}

// feedEnvelope mirrors the unexported message type pkg/telemetry/sink/feed
// wraps every event in.
type feedEnvelope struct {
	Type  string          `json:"type"`
	Event telemetry.Event `json:"event"`
}

// stubValidator is a hand-rolled validation.Validator. Validator is already
// an interface at the worker boundary (see pkg/proxy/validation/http_validator.go),
// so this stub requires no production change. It exists purely to keep
// session-replay validation hermetic: the package's default HTTPValidator
// would otherwise dial the captured cookie's real target host over the
// network, which this harness must never do.
type stubValidator struct {
	status validation.Status
}

func (v stubValidator) Validate(_ context.Context, event validation.Event) validation.Result {
	return validation.Result{
		Status:     v.status,
		Identity:   event.Identity,
		HTTPStatus: http.StatusOK,
	}
}

// newMigratedCampaignDB opens a fresh temp SQLite database and applies the
// real olta-campaign migrations to it, exactly as
// pkg/telemetry/sink/campaigndb/campaigndb_test.go's newDB helper does, so
// the campaigndb sink under test writes to the same schema production code
// would.
func newMigratedCampaignDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "campaign.db")

	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	if err := migrations.Apply(raw, "sqlite3"); err != nil {
		t.Fatalf("migrations.Apply() error: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("closing migration handle: %v", err)
	}

	db, err := gorm.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("gorm.Open() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// runTelemetryFanout wires a real telemetry.Bus to all four production
// sinks - campaigndb (a migrated temp SQLite database), webhook (an
// httptest server recording bodies), jsonl (a file under t.TempDir), and
// feed (driven through feed.Handler under httptest, exactly as
// pkg/proxy/core/telemetry_integration_test.go already does) - plus an
// in-test recording sink, then drives one event per pipeline stage through
// it: a validation.Worker replaying a captured session (async worker pool
// via NewWorker/Enqueue/Close) for the replay stage, and a synthetic
// credential-capture event carrying password/cookie detail keys for the
// no-loot invariant, which telemetry.Event.WithDetail must redact before
// any sink ever sees it.
func runTelemetryFanout(t *testing.T) {
	t.Helper()

	// --- sinks ---------------------------------------------------------
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

	campaignGormDB := newMigratedCampaignDB(t)
	campaignSink := campaigndb.New(campaignGormDB)

	recorder := &recordingSink{}

	bus := telemetry.NewBus(32, campaignSink, jsonlSink, webhookSink, feedSink, recorder)
	busClosed := false
	closeBus := func() {
		if busClosed {
			return
		}
		busClosed = true
		if err := bus.Close(); err != nil {
			t.Fatalf("bus.Close() error: %v", err)
		}
	}
	defer closeBus()

	// --- replay stage: a real async validation.Worker ------------------
	//
	// The worker pool is exercised for real (NewWorker/Enqueue/Close), with
	// a stub Validator standing in for the package's default HTTP replay so
	// the queued session-cookie replay never touches the network.
	var resultsMu sync.Mutex
	var results []validation.Result
	worker, err := validation.NewWorker(validation.WorkerConfig{
		Workers:   2,
		QueueSize: 4,
		Validator: stubValidator{status: validation.StatusValid},
		Emitter:   bus,
		OnResult: func(result validation.Result) {
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("validation.NewWorker() error: %v", err)
	}
	workerClosed := false
	closeWorker := func() {
		if workerClosed {
			return
		}
		workerClosed = true
		worker.Close()
	}
	defer closeWorker()

	capturedSession := &database.Session{
		SessionId: "e2e-replay-session",
		Phishlet:  "e2e-phishlet",
		Username:  "victim@corp.example",
		Custom:    map[string]string{"organization": "Corp Example"},
		CookieTokens: map[string]map[string]*database.CookieToken{
			"corp.example": {
				"session_id": {Name: "session_id", Value: "aitm-captured-cookie-value", Path: "/", HttpOnly: true},
			},
		},
	}
	replayEvent, err := validation.NewEvent(capturedSession)
	if err != nil {
		t.Fatalf("validation.NewEvent() error: %v", err)
	}
	if err := worker.Enqueue(replayEvent); err != nil {
		t.Fatalf("worker.Enqueue() error: %v", err)
	}

	// Close() drains the queue and waits for every worker goroutine to
	// finish before returning, which is what makes it safe to assert on
	// `results` and the bus's sinks immediately afterward without sleeping.
	closeWorker()

	resultsMu.Lock()
	gotResults := len(results)
	resultsMu.Unlock()
	if gotResults != 1 {
		t.Fatalf("validation worker delivered %d results, want 1", gotResults)
	}

	// --- no-loot invariant ----------------------------------------------
	//
	// validation.Worker's own replay event never carries a raw password or
	// cookie value (see emitReplay's allowlisted detail keys), so the only
	// way to exercise the redaction guarantee end-to-end is to push an
	// event carrying one directly, exactly as a future credential-capture
	// stage would, through the same real bus and sinks already under test.
	const plaintextPassword = "hunter2-PLAINTEXT-MARKER"
	const plaintextCookie = "SESSID=abcdef123456-MARKER"
	lootEvent := telemetry.New(telemetry.StageCredential, telemetry.OutcomeCaptured, telemetry.TechniqueWebPortalCapture).
		WithDetail("password", plaintextPassword).
		WithDetail("cookie", plaintextCookie).
		WithDetail("field", "login_form")
	bus.Emit(lootEvent)

	closeBus()
	if dropped := bus.Dropped(); dropped != 0 {
		t.Fatalf("bus dropped %d events, want 0", dropped)
	}
	if failed := bus.Failed(); failed != 0 {
		t.Fatalf("bus recorded %d sink failures, want 0", failed)
	}

	const wantEvents = 2 // replay + credential

	// --- recording sink ---------------------------------------------------
	events := recorder.all()
	if len(events) != wantEvents {
		t.Fatalf("recordingSink received %d events, want %d", len(events), wantEvents)
	}
	var sawReplay, sawLoot bool
	for _, event := range events {
		switch event.Stage {
		case telemetry.StageReplay:
			sawReplay = true
			if !hasTechnique(event.Techniques, telemetry.TechniqueWebSessionCookie) {
				t.Errorf("replay event techniques = %v, want %v", event.Techniques, telemetry.TechniqueWebSessionCookie)
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
	if !sawReplay || !sawLoot {
		t.Fatalf("recordingSink missing an expected stage: replay=%v credential=%v", sawReplay, sawLoot)
	}

	// --- campaigndb sink: query the migrated SQLite table directly --------
	var rows []struct {
		Stage  string
		Detail string
	}
	if err := campaignGormDB.Table("telemetry_events").Find(&rows).Error; err != nil {
		t.Fatalf("querying telemetry_events: %v", err)
	}
	if len(rows) != wantEvents {
		t.Fatalf("telemetry_events has %d rows, want %d", len(rows), wantEvents)
	}
	var dbSawReplay, dbSawLoot bool
	var dbCombined strings.Builder
	for _, row := range rows {
		dbCombined.WriteString(row.Detail)
		switch row.Stage {
		case string(telemetry.StageReplay):
			dbSawReplay = true
		case string(telemetry.StageCredential):
			dbSawLoot = true
			var detail map[string]any
			if err := json.Unmarshal([]byte(row.Detail), &detail); err != nil {
				t.Fatalf("telemetry_events.detail is not valid JSON: %q", row.Detail)
			}
			if detail["password"] != "[redacted]" || detail["cookie"] != "[redacted]" {
				t.Fatalf("telemetry_events.detail was not redacted: %v", detail)
			}
		}
	}
	if !dbSawReplay {
		t.Error("telemetry_events is missing the replay/T1550.004 row")
	}
	if !dbSawLoot {
		t.Error("telemetry_events is missing the credential row")
	}
	if strings.Contains(dbCombined.String(), plaintextPassword) {
		t.Fatal("telemetry_events contains the plaintext password - the no-loot guarantee was violated")
	}
	if strings.Contains(dbCombined.String(), plaintextCookie) {
		t.Fatal("telemetry_events contains the plaintext cookie - the no-loot guarantee was violated")
	}

	// --- jsonl sink ---------------------------------------------------------
	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("reading jsonl file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(jsonlBytes), "\n"), "\n")
	if len(lines) != wantEvents {
		t.Fatalf("jsonl file has %d lines, want %d:\n%s", len(lines), wantEvents, jsonlBytes)
	}
	var jsonlSawReplay bool
	for _, line := range lines {
		var event telemetry.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("jsonl line is not valid JSON: %v\nline: %s", err, line)
		}
		if event.Stage == telemetry.StageReplay {
			jsonlSawReplay = hasTechnique(event.Techniques, telemetry.TechniqueWebSessionCookie)
		}
	}
	if !jsonlSawReplay {
		t.Error("jsonl file is missing the replay/T1550.004 event")
	}
	if strings.Contains(string(jsonlBytes), plaintextPassword) {
		t.Fatal("jsonl file contains the plaintext password - the no-loot guarantee was violated")
	}
	if strings.Contains(string(jsonlBytes), plaintextCookie) {
		t.Fatal("jsonl file contains the plaintext cookie - the no-loot guarantee was violated")
	}

	// --- webhook sink ---------------------------------------------------------
	bodies := webhookRec.all()
	if len(bodies) != wantEvents {
		t.Fatalf("webhook received %d requests, want %d", len(bodies), wantEvents)
	}
	var webhookSawReplay bool
	var webhookCombined strings.Builder
	for _, body := range bodies {
		if !json.Valid(body) {
			t.Fatalf("webhook body is not valid JSON: %s", body)
		}
		webhookCombined.Write(body)
		if strings.Contains(string(body), string(telemetry.TechniqueWebSessionCookie)) {
			webhookSawReplay = true
		}
	}
	if !webhookSawReplay {
		t.Error("no webhook body named the replay technique T1550.004")
	}
	if strings.Contains(webhookCombined.String(), plaintextPassword) {
		t.Fatal("a webhook body contains the plaintext password - the no-loot guarantee was violated")
	}
	if strings.Contains(webhookCombined.String(), plaintextCookie) {
		t.Fatal("a webhook body contains the plaintext cookie - the no-loot guarantee was violated")
	}

	// --- feed sink ---------------------------------------------------------
	//
	// The feed sink dials, writes, and closes synchronously inside Emit, and
	// bus.Close() already waited for every Emit call to return, so by this
	// point the server has received both writes on the wire. What is not
	// yet guaranteed is that the server's own goroutine has finished
	// pushing each into the hub's replay history, which happens over an
	// unbuffered channel a moment later; pkg/feed's own tests
	// (TestFeedReplaysBoundedHistory) hit the same gap and close it with a
	// short sleep rather than a synchronization primitive the package does
	// not expose, so this test follows the same established pattern (also
	// used by pkg/proxy/core/telemetry_integration_test.go).
	time.Sleep(50 * time.Millisecond)

	viewer, _, err := websocket.DefaultDialer.Dial(wsEndpoint(feedServer.URL, "/ws"), nil)
	if err != nil {
		t.Fatalf("dialing feed viewer: %v", err)
	}
	defer viewer.Close()
	if err := viewer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	var feedSawReplay bool
	feedMessages := 0
	var feedCombined strings.Builder
	for feedMessages < wantEvents {
		_, raw, err := viewer.ReadMessage()
		if err != nil {
			t.Fatalf("reading feed history (got %d/%d messages): %v", feedMessages, wantEvents, err)
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
		if envelope.Event.Stage == telemetry.StageReplay {
			feedSawReplay = hasTechnique(envelope.Event.Techniques, telemetry.TechniqueWebSessionCookie)
		}
	}
	if !feedSawReplay {
		t.Error("feed history is missing the replay/T1550.004 event")
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
