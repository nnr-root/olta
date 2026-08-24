package resilience

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/s4l1hs/olta/pkg/campaign/migrations"
	"github.com/s4l1hs/olta/pkg/telemetry"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/campaigndb"
)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resilience.db")

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

// seed writes one event at a fixed offset from a base time.
func seed(t *testing.T, db *gorm.DB, base time.Time, offset time.Duration,
	stage telemetry.Stage, outcome telemetry.Outcome, rid string) {
	t.Helper()
	event := telemetry.New(stage, outcome).WithCampaign(1, rid)
	event.Timestamp = base.Add(offset)
	if err := campaigndb.New(db).Emit(nil, event); err != nil {
		t.Fatal(err)
	}
}

func allFeatures() Features {
	return Features{Cloaker: true, Verify: true, SessionValidator: true}
}

func TestFunnelCountsDistinctTargetsPerStage(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	seed(t, db, base, 0, telemetry.StageDelivery, telemetry.OutcomeAllowed, "a")
	seed(t, db, base, 0, telemetry.StageDelivery, telemetry.OutcomeAllowed, "b")
	seed(t, db, base, time.Minute, telemetry.StageLure, telemetry.OutcomeAllowed, "a")
	// Duplicate lure event for the same target must not double-count.
	seed(t, db, base, 2*time.Minute, telemetry.StageLure, telemetry.OutcomeAllowed, "a")
	seed(t, db, base, 3*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "a")

	report, err := Compute(db, 1, allFeatures())
	if err != nil {
		t.Fatal(err)
	}

	counts := map[telemetry.Stage]int{}
	for _, stage := range report.Funnel {
		counts[stage.Stage] = stage.Targets
	}
	if counts[telemetry.StageDelivery] != 2 {
		t.Fatalf("delivery = %d, want 2", counts[telemetry.StageDelivery])
	}
	if counts[telemetry.StageLure] != 1 {
		t.Fatalf("lure = %d, want 1 distinct target", counts[telemetry.StageLure])
	}
	if counts[telemetry.StageCapture] != 1 {
		t.Fatalf("capture = %d, want 1", counts[telemetry.StageCapture])
	}
}

// A disabled feature must report "not measured", never zero. Zero reads as
// "nothing was blocked" when the truth is "nothing was watching".
func TestDisabledStageIsNotMeasuredRatherThanZero(t *testing.T) {
	db := newDB(t)
	report, err := Compute(db, 1, Features{Cloaker: false, Verify: true, SessionValidator: true})
	if err != nil {
		t.Fatal(err)
	}

	for _, stage := range report.Funnel {
		if stage.Stage != telemetry.StageCloak {
			continue
		}
		if stage.Measured {
			t.Fatal("cloak stage reported as measured while the cloaker is disabled")
		}
		return
	}
	t.Fatal("cloak stage missing from the funnel")
}

func TestFrictionGroupsBlocksByOrganization(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked).
			WithActor(telemetry.Actor{ASN: "AS8075", Organization: "Microsoft"})
		event.Timestamp = base
		if err := campaigndb.New(db).Emit(nil, event); err != nil {
			t.Fatal(err)
		}
	}

	report, err := Compute(db, 1, allFeatures())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Friction) != 1 {
		t.Fatalf("Friction = %+v, want one entry", report.Friction)
	}
	if report.Friction[0].Organization != "Microsoft" || report.Friction[0].Count != 3 {
		t.Fatalf("Friction[0] = %+v", report.Friction[0])
	}
}

func TestRaceClassifiesAllThreeOutcomes(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	// Time-to-report is measured from delivery, so every target needs one.
	for _, rid := range []string{"fast", "slow", "silent"} {
		seed(t, db, base, 0, telemetry.StageDelivery, telemetry.OutcomeAllowed, rid)
	}

	// Target "fast" reported before the session was captured.
	seed(t, db, base, 1*time.Minute, telemetry.StageReport, telemetry.OutcomeAllowed, "fast")
	seed(t, db, base, 5*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "fast")

	// Target "slow" was captured first, then reported.
	seed(t, db, base, 2*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "slow")
	seed(t, db, base, 9*time.Minute, telemetry.StageReport, telemetry.OutcomeAllowed, "slow")

	// Target "silent" was captured and never reported.
	seed(t, db, base, 3*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "silent")

	report, err := Compute(db, 1, allFeatures())
	if err != nil {
		t.Fatal(err)
	}
	if report.Race.ReportedBeforeCapture != 1 {
		t.Fatalf("ReportedBeforeCapture = %d, want 1", report.Race.ReportedBeforeCapture)
	}
	if report.Race.ReportedAfterCapture != 1 {
		t.Fatalf("ReportedAfterCapture = %d, want 1", report.Race.ReportedAfterCapture)
	}
	if report.Race.NeverReported != 1 {
		t.Fatalf("NeverReported = %d, want 1", report.Race.NeverReported)
	}
	if report.Race.MedianTimeToReportSeconds != 300 {
		t.Fatalf("MedianTimeToReportSeconds = %d, want 300", report.Race.MedianTimeToReportSeconds)
	}
}
