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
	ReportedBeforeCapture     int   `json:"reported_before_capture"`
	ReportedAfterCapture      int   `json:"reported_after_capture"`
	NeverReported             int   `json:"never_reported"`
	MedianTimeToReportSeconds int64 `json:"median_time_to_report_seconds"`
}

// Report is the full per-campaign resilience view.
type Report struct {
	CampaignID int64           `json:"campaign_id"`
	Features   Features        `json:"features"`
	Funnel     []FunnelStage   `json:"funnel"`
	Friction   []FrictionEntry `json:"friction"`
	Race       RaceSummary     `json:"race"`
}

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
// Cloak events are unattributed by design (they fire before lure
// validation), so they are read across the whole table rather than filtered
// by campaign. Every other stage is campaign-scoped.
func Compute(db *gorm.DB, campaignID int64, enabled Features) (Report, error) {
	report := Report{CampaignID: campaignID, Features: enabled}

	var rows []eventRow
	query := db.Table("telemetry_events").
		Select("stage, outcome, rid, timestamp, actor, campaign_id").
		Where("campaign_id = ? OR campaign_id = 0", campaignID)
	if err := query.Scan(&rows).Error; err != nil {
		return Report{}, err
	}

	report.Funnel = buildFunnel(rows, enabled)
	report.Friction = buildFriction(rows)
	report.Race = buildRace(rows)
	return report, nil
}

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
		// Cloak and verify events have no RID, so each row counts once.
		key := row.RID
		if key == "" {
			key = row.Timestamp.Format(time.RFC3339Nano) + row.Actor
		}
		distinct[stage][key] = true
	}

	funnel := make([]FunnelStage, 0, len(funnelOrder))
	for _, entry := range funnelOrder {
		funnel = append(funnel, FunnelStage{
			Stage:      entry.stage,
			Techniques: entry.techniques,
			Targets:    len(distinct[entry.stage]),
			Measured:   measured(entry.stage, enabled),
		})
	}
	return funnel
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
	durations := make([]int64, 0, len(firstReport))

	for rid, captured := range firstCapture {
		reported, ok := firstReport[rid]
		switch {
		case !ok:
			summary.NeverReported++
		case reported.Before(captured):
			summary.ReportedBeforeCapture++
		default:
			summary.ReportedAfterCapture++
		}
	}
	// Targets who reported without ever being captured also count as wins.
	for rid, reported := range firstReport {
		if _, captured := firstCapture[rid]; !captured {
			summary.ReportedBeforeCapture++
			_ = reported
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
