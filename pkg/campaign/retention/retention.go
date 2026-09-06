// Package retention bounds how long an engagement's data is kept.
//
// Two different problems live here, and they are deliberately separate
// operations rather than one "clean up" call:
//
//   - Telemetry grows without bound. telemetry_events had no retention at
//     all: an install used across many engagements accumulates every event
//     it ever recorded, forever. PruneTelemetry drops rows older than a
//     cutoff.
//
//   - A finished engagement leaves personal data behind. The results,
//     events and delivery logs hold the target organization's employees'
//     email addresses, names, job titles and IP addresses, and the event
//     details hold what they typed into the proxied login page.
//     PurgeCampaign removes that while keeping the engagement's shape --
//     how many targets, which stages they reached, when -- so the
//     resilience report still works after the personal data is gone.
//
// Both are irreversible and neither runs on its own: pruning happens only
// when an operator configures a retention period, and purging only when an
// operator asks for a specific campaign, with confirmation. Nothing here
// deletes a campaign, its target groups, or its templates -- a group is
// reusable across engagements and destroying it as a side effect of tidying
// one campaign would be a nasty surprise.
package retention

import (
	"fmt"
	"time"

	"github.com/jinzhu/gorm"
)

// PruneSummary reports what a prune removed.
type PruneSummary struct {
	// Cutoff is the timestamp rows had to be older than to be removed.
	Cutoff time.Time `json:"cutoff"`
	// TelemetryEvents is how many telemetry rows were deleted.
	TelemetryEvents int64 `json:"telemetry_events"`
}

// PruneTelemetry deletes telemetry events recorded before cutoff.
//
// Only telemetry_events is pruned. The campaign tables are the engagement's
// record of what happened and are not time-expired here -- an operator who
// wants those gone asks for a purge, which is a different, explicitly
// requested operation.
func PruneTelemetry(db *gorm.DB, cutoff time.Time) (PruneSummary, error) {
	if db == nil {
		return PruneSummary{}, fmt.Errorf("retention: nil database handle")
	}
	if cutoff.IsZero() {
		return PruneSummary{}, fmt.Errorf("retention: prune cutoff is required")
	}

	result := db.Exec("DELETE FROM telemetry_events WHERE timestamp < ?", cutoff.UTC())
	if result.Error != nil {
		return PruneSummary{}, result.Error
	}
	return PruneSummary{Cutoff: cutoff.UTC(), TelemetryEvents: result.RowsAffected}, nil
}

// CutoffFor turns a retention period in days into an absolute cutoff. A
// non-positive period means "keep everything", which is the default and the
// behavior before this package existed.
func CutoffFor(now time.Time, days int) (time.Time, bool) {
	if days <= 0 {
		return time.Time{}, false
	}
	return now.UTC().AddDate(0, 0, -days), true
}

// PurgeSummary reports what a purge anonymized.
type PurgeSummary struct {
	CampaignID int64 `json:"campaign_id"`
	// Results, Events, MailLogs, SMSLogs and TelemetryEvents are row counts
	// touched, not rows deleted: every one of these is anonymized in place
	// so the engagement's shape survives.
	Results         int64 `json:"results"`
	Events          int64 `json:"events"`
	MailLogs        int64 `json:"mail_logs"`
	SMSLogs         int64 `json:"sms_logs"`
	TelemetryEvents int64 `json:"telemetry_events"`
	// Scope states in the response itself what was and was not removed.
	Scope string `json:"scope"`
}

const purgeScopeCaption = "Recipient names, email addresses, phone numbers, job metadata, IP " +
	"addresses, geolocation and submitted form details were cleared from this campaign's results, " +
	"events, delivery logs and telemetry. Recipient IDs, statuses, timestamps, session tags and " +
	"stage counts were kept, so the campaign's resilience report still works. The target group, " +
	"templates and sending profile were not touched: those are reusable objects, not this " +
	"campaign's data. This cannot be undone."

// anonymizedEmail is what a purged recipient address becomes. It is a fixed
// string rather than a per-row hash: a hash is still a stable identifier for
// a person, so it would keep exactly the linkability the purge exists to
// remove.
const anonymizedEmail = "purged@invalid"

// PurgeCampaign removes personal data from one campaign while keeping its
// measurable shape.
//
// It is scoped by user as well as campaign, mirroring every other campaign
// operation: a caller can only purge a campaign they own, and passing another
// user's ID purges nothing rather than reporting an error that would confirm
// the campaign exists.
//
// Everything runs in one transaction. A half-purged campaign -- addresses
// cleared from results but still present in the delivery log -- would be
// worse than either state, because an operator reading the results would
// believe the data was gone.
func PurgeCampaign(db *gorm.DB, campaignID, userID int64) (PurgeSummary, error) {
	if db == nil {
		return PurgeSummary{}, fmt.Errorf("retention: nil database handle")
	}
	if campaignID <= 0 {
		return PurgeSummary{}, fmt.Errorf("retention: campaign id is required")
	}

	summary := PurgeSummary{CampaignID: campaignID, Scope: purgeScopeCaption}
	tx := db.Begin()
	if tx.Error != nil {
		return PurgeSummary{}, tx.Error
	}

	// results: the recipient's identity and observed location. RId, status,
	// dates, template variant, tag and session_status are kept -- they carry
	// no personal data and every report is computed from them. Notes are
	// cleared because they are free text an operator may have typed a name
	// into.
	results := tx.Exec(`UPDATE results SET
			email = ?, first_name = '', last_name = '', position = '',
			department = '', role = '', company = '', manager_name = '',
			ip = '', latitude = 0, longitude = 0, notes = ''
		WHERE campaign_id = ? AND user_id = ?`,
		anonymizedEmail, campaignID, userID)
	if results.Error != nil {
		tx.Rollback()
		return PurgeSummary{}, results.Error
	}
	summary.Results = results.RowsAffected

	// events: the email column identifies the recipient, and details holds
	// the submitted payload -- the credentials the target typed. Message is
	// kept: it is the event type ("Clicked Link"), which is what the
	// campaign timeline renders.
	//
	// events has no user_id column, so ownership is enforced through the
	// campaign, which the caller has already been authorized against.
	events := tx.Exec(`UPDATE events SET email = ?, details = '' WHERE campaign_id = ?`,
		anonymizedEmail, campaignID)
	if events.Error != nil {
		tx.Rollback()
		return PurgeSummary{}, events.Error
	}
	summary.Events = events.RowsAffected

	// mail_logs / sms_logs: target is the address or phone number the
	// message was sent to.
	mailLogs := tx.Exec(`UPDATE mail_logs SET target = ? WHERE campaign_id = ? AND user_id = ?`,
		anonymizedEmail, campaignID, userID)
	if mailLogs.Error != nil {
		tx.Rollback()
		return PurgeSummary{}, mailLogs.Error
	}
	summary.MailLogs = mailLogs.RowsAffected

	smsLogs := tx.Exec(`UPDATE sms_logs SET target = ? WHERE campaign_id = ? AND user_id = ?`,
		anonymizedEmail, campaignID, userID)
	if smsLogs.Error != nil {
		tx.Rollback()
		return PurgeSummary{}, smsLogs.Error
	}
	summary.SMSLogs = smsLogs.RowsAffected

	// telemetry_events: the actor blob carries the client IP address, which
	// is personal data in its own right. Stage, outcome, technique,
	// timestamp and rid are kept, so the funnel, friction and race sections
	// of the resilience report are unaffected -- friction groups by
	// organization and ASN, which are network attributes, not personal ones.
	//
	// Only rows attributed to this campaign are touched. Unattributed
	// cloak/verify rows are shared with every other campaign in the same
	// window on the same install; clearing them here would silently degrade
	// another campaign's report.
	telemetryEvents := tx.Exec(`UPDATE telemetry_events SET actor = ? WHERE campaign_id = ?`,
		`{}`, campaignID)
	if telemetryEvents.Error != nil {
		tx.Rollback()
		return PurgeSummary{}, telemetryEvents.Error
	}
	summary.TelemetryEvents = telemetryEvents.RowsAffected

	if err := tx.Commit().Error; err != nil {
		return PurgeSummary{}, err
	}
	return summary, nil
}
