package resilience

import (
	"database/sql"
	"fmt"
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

// wideWindow returns a window comfortably covering base +/- a day, for
// tests that seed unattributed events and don't care about window edges.
func wideWindow(base time.Time) Window {
	return Window{Start: base.Add(-24 * time.Hour), End: base.Add(24 * time.Hour)}
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

	report, err := Compute(db, 1, wideWindow(base), allFeatures())
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
	now := time.Now()
	window := Window{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	report, err := Compute(db, 1, window, Features{Cloaker: false, Verify: true, SessionValidator: true})
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

	report, err := Compute(db, 1, wideWindow(base), allFeatures())
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

	report, err := Compute(db, 1, wideWindow(base), allFeatures())
	if err != nil {
		t.Fatal(err)
	}
	if report.Race.Delivered != 3 {
		t.Fatalf("Delivered = %d, want 3", report.Race.Delivered)
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
	if !report.Race.HasMedianTimeToReport {
		t.Fatal("HasMedianTimeToReport = false, want true: two targets reported")
	}
}

// TestUnattributedEventsScopedToCampaignWindow is the regression test for
// B1: cloak/verify events carry campaign_id = 0 by design (they fire before
// lure validation resolves a recipient), so an earlier version of Compute
// pulled in EVERY unattributed event ever recorded on the install, from
// every campaign, with no time window. That let one campaign's report leak
// another campaign's cloaker/verify traffic the moment a second campaign
// ran on the same proxy install.
//
// This seeds: an attributed campaign-1 event inside the window, an
// attributed campaign-2 event outside the window (must never appear
// regardless of window, since it is correctly attributed to someone else),
// and two unattributed cloak events -- one inside the window, one outside
// it. Only the in-window unattributed event may appear in campaign 1's
// report.
func TestUnattributedEventsScopedToCampaignWindow(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	window := Window{Start: base, End: base.Add(time.Hour)}

	// Campaign 1's own attributed delivery, inside the window.
	seed(t, db, base, time.Minute, telemetry.StageDelivery, telemetry.OutcomeAllowed, "c1-target")

	// Campaign 2's attributed cloak event, well outside campaign 1's
	// window. It is correctly attributed to campaign 2, so it must never
	// leak into campaign 1's report no matter the window.
	outsider := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked).
		WithCampaign(2, "c2-target").
		WithActor(telemetry.Actor{ASN: "AS16509", Organization: "Amazon"})
	outsider.Timestamp = base.Add(48 * time.Hour)
	if err := campaigndb.New(db).Emit(nil, outsider); err != nil {
		t.Fatal(err)
	}

	// Unattributed cloak event inside campaign 1's window: must count.
	inWindow := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked).
		WithActor(telemetry.Actor{IP: "1.1.1.1", ASN: "AS8075", Organization: "Microsoft"})
	inWindow.Timestamp = base.Add(30 * time.Minute)
	if err := campaigndb.New(db).Emit(nil, inWindow); err != nil {
		t.Fatal(err)
	}

	// Unattributed cloak event outside campaign 1's window: must NOT count,
	// even though it too carries campaign_id = 0. This is the actual bug:
	// before the fix, this row appeared in campaign 1's report.
	outOfWindow := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked).
		WithActor(telemetry.Actor{IP: "2.2.2.2", ASN: "AS16509", Organization: "Amazon"})
	outOfWindow.Timestamp = base.Add(-48 * time.Hour)
	if err := campaigndb.New(db).Emit(nil, outOfWindow); err != nil {
		t.Fatal(err)
	}

	report, err := Compute(db, 1, window, allFeatures())
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Friction) != 1 {
		t.Fatalf("Friction = %+v, want exactly the in-window Microsoft entry", report.Friction)
	}
	if report.Friction[0].Organization != "Microsoft" {
		t.Fatalf("Friction[0].Organization = %q, want Microsoft (the in-window unattributed event)", report.Friction[0].Organization)
	}

	for _, stage := range report.Funnel {
		if stage.Stage != telemetry.StageCloak {
			continue
		}
		if stage.Targets != 1 {
			t.Fatalf("cloak targets = %d, want 1 (only the in-window unattributed event)", stage.Targets)
		}
	}

	if !report.UnattributedScoped {
		t.Fatal("UnattributedScoped = false, want true")
	}
	if report.FrictionScope == "" {
		t.Fatal("FrictionScope caption is empty, want a human-readable caveat")
	}
}

// TestFunnelCountsDistinctActorsForUnattributedStage is the regression test
// for B2: the fallback key for unattributed (no-RID) rows used to be
// timestamp+actor at nanosecond precision, which essentially never
// collides. One browser retrying 40 blocked sub-resources therefore read as
// "Cloak: 40 targets" instead of one. This fires several cloak events from
// the same actor at different timestamps and asserts they collapse to one
// target.
func TestFunnelCountsDistinctActorsForUnattributedStage(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	actor := telemetry.Actor{IP: "9.9.9.9", ASN: "AS8075", Organization: "Microsoft"}
	for i := 0; i < 5; i++ {
		event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked).WithActor(actor)
		event.Timestamp = base.Add(time.Duration(i) * time.Second)
		if err := campaigndb.New(db).Emit(nil, event); err != nil {
			t.Fatal(err)
		}
	}

	report, err := Compute(db, 1, wideWindow(base), allFeatures())
	if err != nil {
		t.Fatal(err)
	}

	for _, stage := range report.Funnel {
		if stage.Stage != telemetry.StageCloak {
			continue
		}
		if stage.Targets != 1 {
			t.Fatalf("cloak targets = %d, want 1 (five requests from one actor)", stage.Targets)
		}
		return
	}
	t.Fatal("cloak stage missing from the funnel")
}

// TestRaceClassifiesFullDeliveredPopulation is the regression test for B3:
// buildRace used to only classify RIDs present in firstCapture or
// firstReport, silently omitting delivered targets who never engaged at
// all. With 100 delivered, 10 captured (2 reported before capture, 8 never
// reported), and 90 who never engaged, the old code reported
// never_reported: 8 instead of 98.
func TestRaceClassifiesFullDeliveredPopulation(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	const delivered = 100
	const captured = 10
	const reportedBeforeCapture = 2

	for i := 0; i < delivered; i++ {
		rid := fmt.Sprintf("target-%03d", i)
		seed(t, db, base, 0, telemetry.StageDelivery, telemetry.OutcomeAllowed, rid)
	}
	for i := 0; i < captured; i++ {
		rid := fmt.Sprintf("target-%03d", i)
		seed(t, db, base, 5*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, rid)
	}
	for i := 0; i < reportedBeforeCapture; i++ {
		rid := fmt.Sprintf("target-%03d", i)
		seed(t, db, base, 1*time.Minute, telemetry.StageReport, telemetry.OutcomeAllowed, rid)
	}

	report, err := Compute(db, 1, wideWindow(base), allFeatures())
	if err != nil {
		t.Fatal(err)
	}

	if report.Race.Delivered != delivered {
		t.Fatalf("Delivered = %d, want %d", report.Race.Delivered, delivered)
	}
	if report.Race.ReportedBeforeCapture != reportedBeforeCapture {
		t.Fatalf("ReportedBeforeCapture = %d, want %d", report.Race.ReportedBeforeCapture, reportedBeforeCapture)
	}
	if report.Race.ReportedAfterCapture != 0 {
		t.Fatalf("ReportedAfterCapture = %d, want 0", report.Race.ReportedAfterCapture)
	}
	if report.Race.NeverReported != 98 {
		t.Fatalf("NeverReported = %d, want 98", report.Race.NeverReported)
	}
	sum := report.Race.ReportedBeforeCapture + report.Race.ReportedAfterCapture + report.Race.NeverReported
	if sum != report.Race.Delivered {
		t.Fatalf("buckets sum to %d, want Delivered = %d", sum, report.Race.Delivered)
	}
}

// funnelStage finds a stage's row in the funnel, failing the test if it is
// missing rather than letting callers silently skip an assertion.
func funnelStage(t *testing.T, report Report, stage telemetry.Stage) FunnelStage {
	t.Helper()
	for _, s := range report.Funnel {
		if s.Stage == stage {
			return s
		}
	}
	t.Fatalf("%s stage missing from the funnel", stage)
	return FunnelStage{}
}

// TestMeasuredUpgradesFromEventsWhenConfigStale is the regression test for
// the self-correction fix: config says the cloaker was off, but a cloak
// event exists in the report's row set. Only asncloak emits a cloak event,
// and only when the cloaker is running -- so the event is hard proof the
// config's "false" is stale, and the stage must be upgraded to measured
// rather than rendered as "Not measured" while real data sits right there.
func TestMeasuredUpgradesFromEventsWhenConfigStale(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked).
		WithActor(telemetry.Actor{IP: "3.3.3.3", ASN: "AS8075", Organization: "Microsoft"})
	event.Timestamp = base
	if err := campaigndb.New(db).Emit(nil, event); err != nil {
		t.Fatal(err)
	}

	report, err := Compute(db, 1, wideWindow(base), Features{Cloaker: false, Verify: true, SessionValidator: true})
	if err != nil {
		t.Fatal(err)
	}

	stage := funnelStage(t, report, telemetry.StageCloak)
	if !stage.Measured {
		t.Fatal("cloak stage reported as not measured despite an observed cloak event proving the feature ran")
	}
	if stage.Targets != 1 {
		t.Fatalf("cloak targets = %d, want 1", stage.Targets)
	}
	// Features must still reflect what was configured, not the upgrade.
	if report.Features.Cloaker {
		t.Fatal("Features.Cloaker was mutated by the upgrade; it must keep reporting what was configured")
	}
}

// TestMeasuredStaysFalseWhenConfigFalseAndNoEvents pins the unchanged half
// of the fix: absence of events proves nothing, so config false with no
// corroborating evidence must still render as "Not measured".
func TestMeasuredStaysFalseWhenConfigFalseAndNoEvents(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	report, err := Compute(db, 1, wideWindow(base), Features{Cloaker: false, Verify: true, SessionValidator: true})
	if err != nil {
		t.Fatal(err)
	}

	stage := funnelStage(t, report, telemetry.StageCloak)
	if stage.Measured {
		t.Fatal("cloak stage reported as measured with config false and no events to corroborate it")
	}
}

// TestMeasuredStaysTrueWhenConfigTrueAndNoEvents pins the operator-trust
// direction: config true is taken at face value even with zero matching
// events, since a feature can be enabled and simply never match anything.
// Absence must never downgrade a configured true.
func TestMeasuredStaysTrueWhenConfigTrueAndNoEvents(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	report, err := Compute(db, 1, wideWindow(base), allFeatures())
	if err != nil {
		t.Fatal(err)
	}

	stage := funnelStage(t, report, telemetry.StageCloak)
	if !stage.Measured {
		t.Fatal("cloak stage reported as not measured despite config true (absence must never downgrade)")
	}
	if stage.Targets != 0 {
		t.Fatalf("cloak targets = %d, want 0", stage.Targets)
	}
}

// TestNonOptionalStageAlwaysMeasured confirms the upgrade logic is scoped
// to the three optional stages: delivery has no on/off feature flag, so it
// must always report measured regardless of Features.
func TestNonOptionalStageAlwaysMeasured(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	report, err := Compute(db, 1, wideWindow(base), Features{Cloaker: false, Verify: false, SessionValidator: false})
	if err != nil {
		t.Fatal(err)
	}

	stage := funnelStage(t, report, telemetry.StageDelivery)
	if !stage.Measured {
		t.Fatal("delivery stage reported as not measured; delivery has no optional feature flag")
	}
}
