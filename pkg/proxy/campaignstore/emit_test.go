package campaignstore

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/s4l1hs/olta/pkg/campaign/migrations"
	sqlitedsn "github.com/s4l1hs/olta/pkg/storage/sqlite"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// newTestStore opens a temp SQLite database, applies the shared campaign
// schema, and returns a ready Store whose Close is registered on cleanup.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "olta.db")

	raw, err := sql.Open("sqlite3", sqlitedsn.ConcurrentDSN(path))
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	if err := migrations.Apply(raw, "sqlite3"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	store, err := New(path, "", false)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close(): %v", err)
		}
	})
	return store
}

// seedResult inserts a row into results with the given r_id and campaign_id,
// starting at the "Email/SMS Sent" status that every tracked transition
// builds on.
func seedResult(t *testing.T, store *Store, rid string, campaignID int64) {
	t.Helper()
	if _, err := store.db.DB().Exec(
		`INSERT INTO results (campaign_id, r_id, email, status) VALUES (?, ?, ?, ?)`,
		campaignID, rid, "authorized-test@example.com", "Email/SMS Sent",
	); err != nil {
		t.Fatalf("seed result: %v", err)
	}
}

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

func TestStageForStatusMapsEveryTrackedStatus(t *testing.T) {
	cases := []struct {
		status    string
		stage     telemetry.Stage
		outcome   telemetry.Outcome
		technique telemetry.Technique
	}{
		{"Email/SMS Opened", telemetry.StageOpen, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink},
		{"Clicked Link", telemetry.StageLure, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink},
		{"Submitted Data", telemetry.StageCredential, telemetry.OutcomeCaptured, telemetry.TechniqueWebPortalCapture},
		{"Captured Session", telemetry.StageCapture, telemetry.OutcomeCaptured, telemetry.TechniqueStealWebSessionCookie},
	}

	for _, testCase := range cases {
		stage, outcome, technique, ok := stageForStatus(testCase.status)
		if !ok {
			t.Fatalf("stageForStatus(%q) reported no mapping", testCase.status)
		}
		if stage != testCase.stage || outcome != testCase.outcome || technique != testCase.technique {
			t.Fatalf("stageForStatus(%q) = %q/%q/%q, want %q/%q/%q",
				testCase.status, stage, outcome, technique,
				testCase.stage, testCase.outcome, testCase.technique)
		}
	}

	if _, _, _, ok := stageForStatus("Email/SMS Sent"); ok {
		t.Fatal("proxy-side store must not claim the delivery stage; the campaign owns it")
	}
}

func TestUpdateResultEmitsCorrelatedEvent(t *testing.T) {
	store := newTestStore(t) // reuse the helper from feed_test.go
	emitter := &captureEmitter{}
	store.SetEmitter(emitter)

	seedResult(t, store, "rid-42", 7) // reuse or add a fixture helper

	if err := store.updateResult("rid-42", "Clicked Link", nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	event := events[0]
	if event.Stage != telemetry.StageLure {
		t.Fatalf("Stage = %q", event.Stage)
	}
	if event.RID != "rid-42" || event.CampaignID != 7 {
		t.Fatalf("correlation = %q/%d, want rid-42/7", event.RID, event.CampaignID)
	}
}

// seedSMSResult is seedResult's SMS-targeted counterpart: same fixture, but
// with sms_target set so emitStage can derive medium == "sms".
func seedSMSResult(t *testing.T, store *Store, rid string, campaignID int64) {
	t.Helper()
	if _, err := store.db.DB().Exec(
		`INSERT INTO results (campaign_id, r_id, email, status, sms_target) VALUES (?, ?, ?, ?, 1)`,
		campaignID, rid, "authorized-test@example.com", "Email/SMS Sent",
	); err != nil {
		t.Fatalf("seed sms result: %v", err)
	}
}

func TestUpdateResultEmitsEmailMedium(t *testing.T) {
	store := newTestStore(t)
	emitter := &captureEmitter{}
	store.SetEmitter(emitter)

	seedResult(t, store, "rid-medium-email", 7)

	if err := store.updateResult("rid-medium-email", "Clicked Link", nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	if got := events[0].Detail["medium"]; got != "email" {
		t.Fatalf("medium = %v, want %q", got, "email")
	}
}

func TestUpdateResultEmitsSMSMedium(t *testing.T) {
	store := newTestStore(t)
	emitter := &captureEmitter{}
	store.SetEmitter(emitter)

	seedSMSResult(t, store, "rid-medium-sms", 7)

	if err := store.updateResult("rid-medium-sms", "Clicked Link", nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	if got := events[0].Detail["medium"]; got != "sms" {
		t.Fatalf("medium = %v, want %q", got, "sms")
	}
}

func TestNilEmitterIsSafe(t *testing.T) {
	store := newTestStore(t)
	seedResult(t, store, "rid-43", 7)
	if err := store.updateResult("rid-43", "Clicked Link", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Reaching here without a panic is the assertion.
}
