package retention

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

var base = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "retention.db")

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

func seedTelemetry(t *testing.T, db *gorm.DB, at time.Time, campaignID int64, rid, ip string) {
	t.Helper()
	event := telemetry.New(telemetry.StageCapture, telemetry.OutcomeCaptured,
		telemetry.TechniqueStealWebSessionCookie).
		WithCampaign(campaignID, rid).
		WithActor(telemetry.Actor{IP: ip, Organization: "Example ISP", ASN: "AS64500"})
	event.Timestamp = at
	if err := campaigndb.New(db).Emit(nil, event); err != nil {
		t.Fatal(err)
	}
}

func countTelemetry(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var count int64
	if err := db.Table("telemetry_events").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

func TestPruneTelemetryRemovesOnlyOldRows(t *testing.T) {
	db := newDB(t)
	seedTelemetry(t, db, base.Add(-90*24*time.Hour), 1, "old-a", "198.51.100.1")
	seedTelemetry(t, db, base.Add(-89*24*time.Hour), 1, "old-b", "198.51.100.2")
	seedTelemetry(t, db, base.Add(-10*24*time.Hour), 1, "recent", "198.51.100.3")

	summary, err := PruneTelemetry(db, base.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	if summary.TelemetryEvents != 2 {
		t.Errorf("pruned %d rows, want 2", summary.TelemetryEvents)
	}
	if got := countTelemetry(t, db); got != 1 {
		t.Errorf("%d rows remain, want 1", got)
	}
}

func TestPruneTelemetryRequiresACutoff(t *testing.T) {
	db := newDB(t)
	if _, err := PruneTelemetry(db, time.Time{}); err == nil {
		t.Fatal("PruneTelemetry accepted a zero cutoff; that would delete everything before now")
	}
}

func TestPruneTelemetryOnAnEmptyTableIsANoop(t *testing.T) {
	db := newDB(t)
	summary, err := PruneTelemetry(db, base)
	if err != nil {
		t.Fatal(err)
	}
	if summary.TelemetryEvents != 0 {
		t.Errorf("pruned %d rows from an empty table", summary.TelemetryEvents)
	}
}

func TestCutoffFor(t *testing.T) {
	cutoff, enabled := CutoffFor(base, 30)
	if !enabled {
		t.Fatal("CutoffFor(30) reported retention disabled")
	}
	if want := base.AddDate(0, 0, -30); !cutoff.Equal(want) {
		t.Errorf("cutoff = %v, want %v", cutoff, want)
	}

	// Zero and negative both mean "keep everything", which is the default
	// and the behavior before this package existed.
	for _, days := range []int{0, -1} {
		if _, enabled := CutoffFor(base, days); enabled {
			t.Errorf("CutoffFor(%d) enabled retention; a non-positive period must keep everything", days)
		}
	}
}

// seedCampaignData writes one campaign's worth of rows across every table a
// purge touches, for the given owner.
func seedCampaignData(t *testing.T, db *gorm.DB, campaignID, userID int64, email string) {
	t.Helper()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO results (campaign_id, user_id, r_id, email, first_name, last_name, position,
			department, role, company, manager_name, status, ip, latitude, longitude, send_date,
			reported, modified_date, notes, tag, session_status)
			VALUES (?, ?, ?, ?, 'Ada', 'Lovelace', 'Analyst', 'Finance', 'Staff', 'Acme',
			'Grace Hopper', 'Captured Session', '203.0.113.9', 51.5, -0.12, ?, 0, ?,
			'called Ada, she confirmed', 'high-value', 'triaged')`,
			[]any{campaignID, userID, "rid" + email, email, base, base}},
		{`INSERT INTO events (campaign_id, email, time, message, details)
			VALUES (?, ?, ?, 'Submitted Data', '{"payload":{"username":["ada@acme.example"]}}')`,
			[]any{campaignID, email, base}},
		{`INSERT INTO mail_logs (campaign_id, user_id, send_date, send_attempt, r_id, processing, target)
			VALUES (?, ?, ?, 0, ?, 0, ?)`,
			[]any{campaignID, userID, base, "rid" + email, email}},
		{`INSERT INTO sms_logs (campaign_id, user_id, send_date, send_attempt, r_id, processing, target)
			VALUES (?, ?, ?, 0, ?, 0, ?)`,
			[]any{campaignID, userID, base, "rid" + email, "+15550000001"}},
	}
	for _, statement := range statements {
		if err := db.Exec(statement.query, statement.args...).Error; err != nil {
			t.Fatal(err)
		}
	}
	seedTelemetry(t, db, base, campaignID, "rid"+email, "203.0.113.9")
}

func TestPurgeCampaignRemovesPersonalData(t *testing.T) {
	db := newDB(t)
	seedCampaignData(t, db, 1, 1, "ada@acme.example")

	summary, err := PurgeCampaign(db, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Results != 1 || summary.Events != 1 || summary.MailLogs != 1 ||
		summary.SMSLogs != 1 || summary.TelemetryEvents != 1 {
		t.Errorf("summary = %+v, want one row touched in each table", summary)
	}
	if summary.Scope == "" {
		t.Error("Scope is empty; an irreversible operation must state what it did")
	}

	var email, firstName, ip, notes string
	row := db.Raw(`SELECT email, first_name, ip, notes FROM results WHERE campaign_id = 1`).Row()
	if err := row.Scan(&email, &firstName, &ip, &notes); err != nil {
		t.Fatal(err)
	}
	if email != anonymizedEmail || firstName != "" || ip != "" || notes != "" {
		t.Errorf("result still carries personal data: email=%q first_name=%q ip=%q notes=%q",
			email, firstName, ip, notes)
	}

	var eventEmail, details, message string
	row = db.Raw(`SELECT email, details, message FROM events WHERE campaign_id = 1`).Row()
	if err := row.Scan(&eventEmail, &details, &message); err != nil {
		t.Fatal(err)
	}
	if eventEmail != anonymizedEmail || details != "" {
		t.Errorf("event still carries personal data: email=%q details=%q", eventEmail, details)
	}
	if message != "Submitted Data" {
		t.Errorf("event message = %q, want it kept: the campaign timeline is built from it", message)
	}

	var target string
	if err := db.Raw(`SELECT target FROM mail_logs WHERE campaign_id = 1`).Row().Scan(&target); err != nil {
		t.Fatal(err)
	}
	if target != anonymizedEmail {
		t.Errorf("mail log target = %q", target)
	}
	if err := db.Raw(`SELECT target FROM sms_logs WHERE campaign_id = 1`).Row().Scan(&target); err != nil {
		t.Fatal(err)
	}
	if target != anonymizedEmail {
		t.Errorf("sms log target = %q, want the phone number cleared", target)
	}

	var actor string
	if err := db.Raw(`SELECT actor FROM telemetry_events WHERE campaign_id = 1`).Row().Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != "{}" {
		t.Errorf("telemetry actor = %q, want the client IP cleared", actor)
	}
}

// TestPurgeKeepsTheEngagementShape is the property that makes a purge usable
// rather than a delete: the resilience report has to still work afterwards,
// or an operator will simply never run it.
func TestPurgeKeepsTheEngagementShape(t *testing.T) {
	db := newDB(t)
	seedCampaignData(t, db, 1, 1, "ada@acme.example")

	if _, err := PurgeCampaign(db, 1, 1); err != nil {
		t.Fatal(err)
	}

	var rid, status, sessionStatus, tag string
	var reported bool
	row := db.Raw(`SELECT r_id, status, session_status, tag, reported FROM results WHERE campaign_id = 1`).Row()
	if err := row.Scan(&rid, &status, &sessionStatus, &tag, &reported); err != nil {
		t.Fatal(err)
	}
	if rid == "" || status != "Captured Session" || sessionStatus != "triaged" || tag != "high-value" {
		t.Errorf("purge destroyed the engagement's shape: rid=%q status=%q session_status=%q tag=%q",
			rid, status, sessionStatus, tag)
	}

	var stage, outcome, telemetryRID string
	row = db.Raw(`SELECT stage, outcome, rid FROM telemetry_events WHERE campaign_id = 1`).Row()
	if err := row.Scan(&stage, &outcome, &telemetryRID); err != nil {
		t.Fatal(err)
	}
	if stage != string(telemetry.StageCapture) || outcome != string(telemetry.OutcomeCaptured) || telemetryRID == "" {
		t.Errorf("purge damaged telemetry the report needs: stage=%q outcome=%q rid=%q",
			stage, outcome, telemetryRID)
	}
}

// TestPurgeIsScopedToOneCampaign covers the blast radius. An install runs
// many engagements against many clients; a purge reaching another campaign's
// data would be a data-loss incident.
func TestPurgeIsScopedToOneCampaign(t *testing.T) {
	db := newDB(t)
	seedCampaignData(t, db, 1, 1, "ada@acme.example")
	seedCampaignData(t, db, 2, 1, "grace@other.example")

	if _, err := PurgeCampaign(db, 1, 1); err != nil {
		t.Fatal(err)
	}

	var email string
	if err := db.Raw(`SELECT email FROM results WHERE campaign_id = 2`).Row().Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "grace@other.example" {
		t.Errorf("another campaign's data was purged: email = %q", email)
	}
}

// TestPurgeIsScopedToTheOwner mirrors every other campaign operation: a
// caller can only purge a campaign they own.
func TestPurgeIsScopedToTheOwner(t *testing.T) {
	db := newDB(t)
	seedCampaignData(t, db, 1, 1, "ada@acme.example")

	summary, err := PurgeCampaign(db, 1, 999)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Results != 0 {
		t.Errorf("purged %d results for a campaign owned by someone else", summary.Results)
	}

	var email string
	if err := db.Raw(`SELECT email FROM results WHERE campaign_id = 1`).Row().Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "ada@acme.example" {
		t.Errorf("another user's data was purged: email = %q", email)
	}
}

// TestPurgeLeavesUnattributedTelemetryAlone covers the shared rows.
// Unattributed cloak and verify events belong to no campaign and are folded
// into every report whose window covers them, so clearing them as part of one
// campaign's purge would silently degrade another campaign's report.
func TestPurgeLeavesUnattributedTelemetryAlone(t *testing.T) {
	db := newDB(t)
	seedCampaignData(t, db, 1, 1, "ada@acme.example")

	unattributed := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked, telemetry.TechniqueProxy).
		WithActor(telemetry.Actor{IP: "198.51.100.50", Organization: "Scanner Inc", ASN: "AS64501"})
	unattributed.Timestamp = base
	if err := campaigndb.New(db).Emit(nil, unattributed); err != nil {
		t.Fatal(err)
	}

	if _, err := PurgeCampaign(db, 1, 1); err != nil {
		t.Fatal(err)
	}

	var actor string
	row := db.Raw(`SELECT actor FROM telemetry_events WHERE campaign_id = 0`).Row()
	if err := row.Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor == "{}" {
		t.Error("purge cleared an unattributed telemetry row shared with other campaigns' reports")
	}
}

func TestPurgeRejectsAnInvalidCampaign(t *testing.T) {
	db := newDB(t)
	if _, err := PurgeCampaign(db, 0, 1); err == nil {
		t.Fatal("PurgeCampaign accepted campaign id 0")
	}
}

// TestPurgeIsIdempotent covers running it twice, which an operator working
// through a checklist will do.
func TestPurgeIsIdempotent(t *testing.T) {
	db := newDB(t)
	seedCampaignData(t, db, 1, 1, "ada@acme.example")

	if _, err := PurgeCampaign(db, 1, 1); err != nil {
		t.Fatal(err)
	}
	second, err := PurgeCampaign(db, 1, 1)
	if err != nil {
		t.Fatalf("second purge failed: %v", err)
	}
	if second.Results != 1 {
		t.Errorf("second purge touched %d results, want the same row again (a no-op update)", second.Results)
	}

	var email string
	if err := db.Raw(`SELECT email FROM results WHERE campaign_id = 1`).Row().Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != anonymizedEmail {
		t.Errorf("email = %q after two purges", email)
	}
}
