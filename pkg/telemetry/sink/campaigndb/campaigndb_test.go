package campaigndb

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/s4l1hs/olta/pkg/campaign/migrations"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "telemetry.db")

	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(raw, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := gorm.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSinkPersistsEvent(t *testing.T) {
	db := newDB(t)
	sink := New(db)

	event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked, telemetry.TechniqueProxy).
		WithActor(telemetry.Actor{IP: "203.0.113.9", ASN: "AS8075", Organization: "Microsoft"}).
		WithDetail("rule", "network")

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	var row struct {
		EventID    string
		Stage      string
		Outcome    string
		Techniques string
		CampaignID int64
		Actor      string
		Detail     string
	}
	if err := db.Table("telemetry_events").Where("event_id = ?", event.ID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Stage != "cloak" || row.Outcome != "blocked" {
		t.Fatalf("stage/outcome = %q/%q", row.Stage, row.Outcome)
	}
	if row.Techniques != "T1090" {
		t.Fatalf("techniques = %q, want T1090", row.Techniques)
	}
	if row.CampaignID != 0 {
		t.Fatalf("CampaignID = %d, want 0 for an unattributed cloak event", row.CampaignID)
	}

	// Round-trip both JSON columns. Asserting only non-emptiness would let a
	// cross-wiring bug — writing detail into the actor column — pass.
	var actor telemetry.Actor
	if err := json.Unmarshal([]byte(row.Actor), &actor); err != nil {
		t.Fatalf("actor column is not valid JSON: %q", row.Actor)
	}
	if actor.IP != "203.0.113.9" || actor.ASN != "AS8075" || actor.Organization != "Microsoft" {
		t.Fatalf("actor round-trip = %+v", actor)
	}

	var detail map[string]any
	if err := json.Unmarshal([]byte(row.Detail), &detail); err != nil {
		t.Fatalf("detail column is not valid JSON: %q", row.Detail)
	}
	if detail["rule"] != "network" {
		t.Fatalf("detail round-trip = %v", detail)
	}
}

func TestSinkStoresEmptyDetailAsEmptyString(t *testing.T) {
	db := newDB(t)
	sink := New(db)

	event := telemetry.New(telemetry.StageLure, telemetry.OutcomeAllowed)
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	var row struct{ Detail string }
	if err := db.Table("telemetry_events").Where("event_id = ?", event.ID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Detail != "" {
		t.Fatalf("Detail = %q, want empty string rather than %q or null", row.Detail, "{}")
	}
}

func TestSinkPersistsMultipleTechniques(t *testing.T) {
	db := newDB(t)
	sink := New(db)

	event := telemetry.New(telemetry.StageCapture, telemetry.OutcomeCaptured,
		telemetry.TechniqueStealWebSessionCookie, telemetry.TechniqueWebSessionCookie)
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	var row struct{ Techniques string }
	if err := db.Table("telemetry_events").Where("event_id = ?", event.ID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Techniques != "T1539,T1550.004" {
		t.Fatalf("techniques = %q", row.Techniques)
	}
}
