// Package resilience computes the per-campaign purple-team report from the
// telemetry event stream.
package resilience

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Features records which optional proxy capabilities were enabled for the
// engagement. A stage whose feature was off is reported as unmeasured, never
// as zero: zero reads as "nothing was blocked" when the truth is "nothing
// was watching".
type Features struct {
	Cloaker          bool `json:"cloaker"`
	Verify           bool `json:"verify"`
	SessionValidator bool `json:"session_validator"`
}

// FunnelStage is one step of the kill chain.
type FunnelStage struct {
	Stage      telemetry.Stage       `json:"stage"`
	Techniques []telemetry.Technique `json:"techniques,omitempty"`
	Targets    int                   `json:"targets"`
	Measured   bool                  `json:"measured"`
}

// FrictionEntry counts cloaker enforcement grouped by network owner. A high
// count from a security vendor's ASN is evidence the target's stack
// detonated the link.
type FrictionEntry struct {
	Organization string `json:"organization"`
	ASN          string `json:"asn"`
	Count        int    `json:"count"`
}

// RaceSummary answers whether the human layer beat the attacker.
type RaceSummary struct {
	// Delivered is the denominator: every RID with a delivery event. The
	// three buckets below always sum to this so the report never implies a
	// smaller population than the one actually engaged.
	Delivered                 int   `json:"delivered"`
	ReportedBeforeCapture     int   `json:"reported_before_capture"`
	ReportedAfterCapture      int   `json:"reported_after_capture"`
	NeverReported             int   `json:"never_reported"`
	MedianTimeToReportSeconds int64 `json:"median_time_to_report_seconds"`
	// HasMedianTimeToReport distinguishes "no target has reported yet" from
	// a genuine zero-second median: both would otherwise render as 0.
	HasMedianTimeToReport bool `json:"has_median_time_to_report"`
}

// Window bounds the unattributed (campaign_id = 0) cloak and verify events
// folded into a campaign's report. Attributed rows need no bound: they are
// already scoped by campaign_id. Cloak/verify events fire before lure
// validation establishes a recipient, so they can never be attributed to a
// campaign directly -- the window is the only correlation available, and it
// is an approximation, not a guarantee: two campaigns running concurrently
// on the same proxy install can still share a window.
type Window struct {
	Start time.Time
	End   time.Time
}

// Report is the full per-campaign resilience view.
type Report struct {
	CampaignID int64           `json:"campaign_id"`
	Features   Features        `json:"features"`
	Funnel     []FunnelStage   `json:"funnel"`
	Friction   []FrictionEntry `json:"friction"`
	Race       RaceSummary     `json:"race"`
	// UnattributedScoped is true when the unattributed cloak/verify events
	// folded into Funnel and Friction were bounded to the campaign window.
	// FrictionScope is the human-readable caveat the dashboard must render
	// alongside Defensive Friction: a time window narrows unattributed
	// traffic to the campaign's active period, but it cannot prove the
	// traffic came from this campaign rather than another one running on
	// the same install at the same time.
	UnattributedScoped bool   `json:"unattributed_scoped"`
	FrictionScope      string `json:"friction_scope"`
}

const frictionScopeCaption = "Cloak and verify counts include unattributed proxy traffic " +
	"(no recipient was resolved yet) recorded during this campaign's time window. " +
	"They may include traffic from other campaigns running concurrently on the same install."

// funnelOrder is the kill chain in sequence, with the technique each stage
// emulates. It mirrors the mapping table in the design spec.
var funnelOrder = []struct {
	stage      telemetry.Stage
	techniques []telemetry.Technique
}{
	{telemetry.StageDelivery, []telemetry.Technique{telemetry.TechniqueSpearphishingLink}},
	{telemetry.StageOpen, []telemetry.Technique{telemetry.TechniqueSpearphishingLink}},
	{telemetry.StageLure, []telemetry.Technique{telemetry.TechniqueSpearphishingLink}},
	{telemetry.StageCloak, []telemetry.Technique{telemetry.TechniqueProxy}},
	{telemetry.StageVerify, []telemetry.Technique{telemetry.TechniqueSandboxEvasion}},
	{telemetry.StageCredential, []telemetry.Technique{telemetry.TechniqueWebPortalCapture}},
	{telemetry.StageCapture, []telemetry.Technique{telemetry.TechniqueStealWebSessionCookie}},
	{telemetry.StageReplay, []telemetry.Technique{telemetry.TechniqueWebSessionCookie}},
}

// eventRow's field names are chosen to match gorm's default snake_case
// conversion of the telemetry_events columns, with one deliberate
// exception: gorm's naming strategy treats "ID" as a common initialism and
// converts the bare field name "RID" to db column "r_id", not the actual
// column "rid". The explicit tag overrides that.
type eventRow struct {
	Stage      string
	Outcome    string
	RID        string `gorm:"column:rid"`
	Timestamp  time.Time
	Actor      string
	CampaignID int64
}

// Compute builds the report for one campaign.
//
// Cloak and verify events are unattributed by design (they fire before lure
// validation establishes a recipient), so they cannot be filtered by
// campaign_id. Instead they are bounded to window, the campaign's active
// period, which the caller derives from the campaign row. resilience stays
// a pure query layer over telemetry_events: it does not query the
// campaigns table itself. Every other stage is already campaign-scoped and
// left unbounded by time.
func Compute(db *gorm.DB, campaignID int64, window Window, enabled Features) (Report, error) {
	report := Report{
		CampaignID:         campaignID,
		Features:           enabled,
		UnattributedScoped: true,
		FrictionScope:      frictionScopeCaption,
	}

	var rows []eventRow
	query := db.Table("telemetry_events").
		Select("stage, outcome, rid, timestamp, actor, campaign_id").
		Where("campaign_id = ? OR (campaign_id = 0 AND timestamp >= ? AND timestamp <= ?)",
			campaignID, window.Start, window.End)
	if err := query.Scan(&rows).Error; err != nil {
		return Report{}, err
	}

	report.Funnel = buildFunnel(rows, enabled)
	report.Friction = buildFriction(rows)
	report.Race = buildRace(rows)
	return report, nil
}

// measured decides a stage's configured measured-state from Features alone.
// It is the floor, not the final word: buildFunnel upgrades a stale false
// to true when the row set itself proves the feature ran. It can never
// upgrade a false when there is no such proof, and it never downgrades a
// true -- an enabled feature can legitimately see zero matching events.
func measured(stage telemetry.Stage, enabled Features) bool {
	switch stage {
	case telemetry.StageCloak:
		return enabled.Cloaker
	case telemetry.StageVerify:
		return enabled.Verify
	case telemetry.StageReplay:
		return enabled.SessionValidator
	default:
		return true
	}
}

func buildFunnel(rows []eventRow, enabled Features) []FunnelStage {
	distinct := make(map[telemetry.Stage]map[string]bool, len(funnelOrder))
	for _, row := range rows {
		stage := telemetry.Stage(row.Stage)
		if distinct[stage] == nil {
			distinct[stage] = make(map[string]bool)
		}
		// Cloak and verify events have no RID, so they are keyed on actor
		// identity instead. Keying on timestamp (as an earlier version of
		// this function did) is wrong: nanosecond precision means it
		// essentially never collides, so one browser retrying 40 blocked
		// sub-resources reads as 40 distinct targets instead of one.
		key := row.RID
		if key == "" {
			key = actorIdentity(row.Actor)
		}
		distinct[stage][key] = true
	}

	funnel := make([]FunnelStage, 0, len(funnelOrder))
	for _, entry := range funnelOrder {
		stageMeasured := measured(entry.stage, enabled)
		// Self-correction: config false is only a claim, and it can go
		// stale in either direction relative to how olta-proxy was
		// actually launched. But one or more events for this stage is
		// hard proof the feature ran -- asncloak only emits a cloak
		// event when the cloaker matched a request, jsinspect only
		// emits verify when browser verification is on, and the
		// validation worker only emits replay when the session
		// validator is on. So a stale false self-corrects to true on
		// that evidence. Absence proves nothing (an enabled feature can
		// simply never match), so a configured true is never
		// downgraded, and a false with no events stays false.
		if !stageMeasured && len(distinct[entry.stage]) > 0 {
			stageMeasured = true
		}
		funnel = append(funnel, FunnelStage{
			Stage:      entry.stage,
			Techniques: entry.techniques,
			Targets:    len(distinct[entry.stage]),
			Measured:   stageMeasured,
		})
	}
	return funnel
}

// actorIdentity derives a stable key for an unattributed (no-RID) event's
// source, so repeated requests from one actor count as one target rather
// than one per request. IP is the most specific signal available; when it
// is absent, ASN+Organization narrows to the same network; when even those
// are absent, the raw actor JSON is used so identical unknown actors still
// collapse together while distinct unknown actors do not collide with each
// other by chance.
func actorIdentity(actorJSON string) string {
	if actorJSON == "" {
		return ""
	}
	var actor telemetry.Actor
	if err := json.Unmarshal([]byte(actorJSON), &actor); err != nil {
		return actorJSON
	}
	if actor.IP != "" {
		return "ip:" + actor.IP
	}
	if actor.ASN != "" || actor.Organization != "" {
		return "asn:" + actor.ASN + "|org:" + actor.Organization
	}
	return actorJSON
}

func buildFriction(rows []eventRow) []FrictionEntry {
	type key struct{ organization, asn string }
	counts := make(map[key]int)

	for _, row := range rows {
		if telemetry.Stage(row.Stage) != telemetry.StageCloak {
			continue
		}
		if row.Outcome != string(telemetry.OutcomeBlocked) && row.Outcome != string(telemetry.OutcomeRedirected) {
			continue
		}
		var actor telemetry.Actor
		if row.Actor != "" {
			if err := json.Unmarshal([]byte(row.Actor), &actor); err != nil {
				continue
			}
		}
		if actor.Organization == "" && actor.ASN == "" {
			continue
		}
		counts[key{actor.Organization, actor.ASN}]++
	}

	entries := make([]FrictionEntry, 0, len(counts))
	for k, count := range counts {
		entries = append(entries, FrictionEntry{Organization: k.organization, ASN: k.asn, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Organization < entries[j].Organization
	})
	return entries
}

func buildRace(rows []eventRow) RaceSummary {
	firstReport := make(map[string]time.Time)
	firstCapture := make(map[string]time.Time)
	firstDelivery := make(map[string]time.Time)

	for _, row := range rows {
		if row.RID == "" {
			continue
		}
		switch telemetry.Stage(row.Stage) {
		case telemetry.StageDelivery:
			if seen, ok := firstDelivery[row.RID]; !ok || row.Timestamp.Before(seen) {
				firstDelivery[row.RID] = row.Timestamp
			}
		case telemetry.StageReport:
			if seen, ok := firstReport[row.RID]; !ok || row.Timestamp.Before(seen) {
				firstReport[row.RID] = row.Timestamp
			}
		case telemetry.StageCapture:
			if seen, ok := firstCapture[row.RID]; !ok || row.Timestamp.Before(seen) {
				firstCapture[row.RID] = row.Timestamp
			}
		}
	}

	var summary RaceSummary
	// Delivered is the denominator for the whole race: every RID that ever
	// received a delivery event belongs in exactly one bucket below. An
	// earlier version of this function only classified RIDs that appeared
	// in firstCapture or firstReport, silently dropping targets who were
	// delivered to but never engaged at all -- with 100 delivered and only
	// 10 captured, that undercounted "never reported" by the 90 who never
	// showed up in either map, understating the true human-detection
	// failure rate.
	summary.Delivered = len(firstDelivery)
	durations := make([]int64, 0, len(firstReport))

	for rid := range firstDelivery {
		reported, wasReported := firstReport[rid]
		captured, wasCaptured := firstCapture[rid]
		switch {
		case !wasReported:
			summary.NeverReported++
		case !wasCaptured || reported.Before(captured):
			summary.ReportedBeforeCapture++
		default:
			summary.ReportedAfterCapture++
		}
	}

	// Time-to-report runs from delivery: a defender's clock starts when the
	// mail lands, not when the victim happens to click. A target with no
	// delivery event contributes no duration rather than a misleading zero.
	for rid, reported := range firstReport {
		delivered, ok := firstDelivery[rid]
		if !ok {
			continue
		}
		durations = append(durations, int64(reported.Sub(delivered).Seconds()))
	}
	summary.MedianTimeToReportSeconds = median(durations)
	// A nil/empty durations slice and a genuine zero-second median both
	// resolve to 0 from median(); HasMedianTimeToReport is how the caller
	// tells them apart instead of treating 0 as falsy.
	summary.HasMedianTimeToReport = len(durations) > 0
	return summary
}

func median(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}
