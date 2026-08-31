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

// PasskeyDefense quantifies how much of the attack a client's passkey /
// WebAuthn rollout stopped. WebAuthn's origin binding is what defeats AiTM
// proxying by design: when a target has a passkey available and the
// proxied page cannot complete that ceremony, that is the security control
// working, not a measurement gap. This is deliberately measurement only --
// nothing in jsinspect or here suppresses, downgrades, or interferes with a
// WebAuthn ceremony.
//
// Honesty requirements this type exists to enforce (see pkg/proxy/middleware/jsinspect
// and telemetry.StageWebAuthn):
//
//   - The denominator is RanScriptTargets: clients whose browser executed
//     the injected verification script, NOT the campaign's full target
//     list. A target who never opened a proxied page cannot be measured
//     here, and every count below is a subset of RanScriptTargets, never a
//     fraction of the whole campaign.
//   - Measured is false whenever browser verification (-enable-js-inspect)
//     was off for the engagement (self-corrected to true if events prove
//     it actually ran, exactly like the funnel's optional stages). A
//     report consumer must render "not measured" in that case, never 0%:
//     zero would read as "no passkeys were available" when the truth is
//     "nothing was watching for them".
//   - Every field here is a raw count, deliberately: this package does not
//     compute a percentage, because a percentage over a zero or trivially
//     small RanScriptTargets is misleading on its face. A report consumer
//     should compute (and caveat) a rate itself, and only once
//     RanScriptTargets is large enough to say anything.
type PasskeyDefense struct {
	Measured bool `json:"measured"`

	// RanScriptTargets is the denominator for every field below: distinct
	// clients that produced at least one StageWebAuthn observation (i.e.
	// the injected script ran and was not itself flagged as automation --
	// see jsinspect.HandleRequest, which only emits StageWebAuthn on the
	// non-suspicious path).
	RanScriptTargets int `json:"ran_script_targets"`

	// PlatformAuthenticatorAvailable is how many of RanScriptTargets
	// reported PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
	// === true at least once: a passkey-capable authenticator (Touch ID,
	// Windows Hello, a security key, etc.) was available to the browser.
	PlatformAuthenticatorAvailable int `json:"platform_authenticator_available"`

	// CeremonyInitiated is how many of RanScriptTargets had a WebAuthn
	// ceremony (navigator.credentials.get/create called with a publicKey
	// option) observed starting on the page. Observed only: jsinspect's
	// wrapper always lets the original call proceed untouched and returns
	// its result unmodified.
	CeremonyInitiated int `json:"ceremony_initiated"`

	// PushedToWeakerFactor is how many clients that showed passkey
	// capability (PlatformAuthenticatorAvailable or CeremonyInitiated)
	// nonetheless went on to reach credential submission or session
	// capture -- i.e. were pushed to, or fell back to, a weaker factor
	// despite a stronger one being available. The gap between
	// PlatformAuthenticatorAvailable and PushedToWeakerFactor is
	// informally the rollout's save: the CISO-facing finding this type
	// exists to produce.
	//
	// Correlation across stages is approximate: StageWebAuthn fires before
	// lure validation resolves a recipient (no RID), while credential and
	// capture events are RID-attributed, so this links them by client IP
	// address instead -- the one signal both carry. Two distinct clients
	// sharing an IP (e.g. behind the same NAT) would count as one.
	PushedToWeakerFactor int `json:"pushed_to_weaker_factor"`

	// CorrelationReliable is false when this campaign's own row set shows
	// the IP-based join above actually colliding: two or more distinct
	// RIDs attributed to events sharing one client IP address. That is
	// direct evidence of the corporate-NAT scenario described above, not a
	// hypothetical -- an office of targets sharing one egress IP produces
	// exactly this signature. True means no such collision was observed in
	// this campaign's data; it is evidence the join held here, not proof
	// it always will. It carries no meaning when Measured is false (no
	// correlation was attempted), so it is always true in that case --
	// never render it as a finding for an unmeasured metric.
	CorrelationReliable bool `json:"correlation_reliable"`

	// Scope is the human-readable caveat that must travel with every count
	// above wherever this report is rendered, following the same pattern
	// as Report.FrictionScope. It states, in language a non-engineer can
	// act on, that RanScriptTargets is only the clients whose browser ran
	// the injected script (not the full campaign target list), and that
	// PushedToWeakerFactor links pre-lure and post-lure events by client
	// IP address, so clients sharing an egress IP -- a corporate NAT --
	// may be counted as one. When CorrelationReliable is false, Scope
	// upgrades to say plainly that this campaign's data shows that
	// collision actually happening. Scope is empty when Measured is
	// false: an unmeasured metric gets no caveat about a measurement it
	// never took.
	Scope string `json:"scope"`
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
	// Passkey is the passkey/WebAuthn defense measure -- see PasskeyDefense's
	// doc comment for the denominator and "not measured" rules that govern
	// how a consumer must render it.
	Passkey PasskeyDefense `json:"passkey"`
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

// passkeyScopeCaption is PasskeyDefense.Scope's default text: it holds
// regardless of whether this campaign's data happens to show a correlation
// collision, so passkeyScopeUnreliableCaption below builds on it rather
// than restating it.
const passkeyScopeCaption = "These counts only cover clients whose browser ran the injected " +
	"verification script -- not every target in the campaign. Pushed-to-weaker-factor links each " +
	"client's pre-lure passkey check to its post-lure credential or session-capture activity by " +
	"client IP address, so clients sharing an egress IP (for example, employees behind the same " +
	"corporate NAT) may be counted as a single client."

// passkeyScopeUnreliableCaption is used in place of passkeyScopeCaption when
// CorrelationReliable is false: the campaign's own data shows the IP-based
// join actually colliding, so the caveat says so plainly instead of only
// warning about the possibility.
const passkeyScopeUnreliableCaption = passkeyScopeCaption + " This campaign's own data shows that " +
	"collision happening: more than one target was observed behind the same IP address, so treat " +
	"pushed-to-weaker-factor as an upper bound on distinct people affected, not an exact count."

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
	// Detail is only read by buildPasskeyDefense today, which needs the
	// capability/ceremony booleans jsinspect attaches to StageWebAuthn
	// rows. Every other stage's Detail is fetched but unused, which is
	// harmless: it is the same column already indexed by nothing but
	// primary key, and the row set here is already bounded to one
	// campaign's window.
	Detail string
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
		Select("stage, outcome, rid, timestamp, actor, campaign_id, detail").
		Where("campaign_id = ? OR (campaign_id = 0 AND timestamp >= ? AND timestamp <= ?)",
			campaignID, window.Start, window.End)
	if err := query.Scan(&rows).Error; err != nil {
		return Report{}, err
	}

	report.Funnel = buildFunnel(rows, enabled)
	report.Friction = buildFriction(rows)
	report.Race = buildRace(rows)
	report.Passkey = buildPasskeyDefense(rows, enabled)
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

// buildPasskeyDefense computes PasskeyDefense from the same row set as the
// funnel and friction sections. See PasskeyDefense's doc comment for the
// denominator, the "not measured" rule, and why this deliberately never
// computes a percentage.
func buildPasskeyDefense(rows []eventRow, enabled Features) PasskeyDefense {
	type client struct {
		platformAvailable bool
		ceremony          bool
	}
	byClient := make(map[string]*client)

	for _, row := range rows {
		if telemetry.Stage(row.Stage) != telemetry.StageWebAuthn {
			continue
		}
		key := passkeyClientKey(row)
		c := byClient[key]
		if c == nil {
			c = &client{}
			byClient[key] = c
		}
		detail := parseDetail(row.Detail)
		if detailBool(detail, "platform_authenticator_available") {
			c.platformAvailable = true
		}
		if detailBool(detail, "webauthn_ceremony_observed") {
			c.ceremony = true
		}
	}

	// Self-correction, exactly like measured() for the funnel's optional
	// stages: config false is only a claim and can go stale, but one or
	// more StageWebAuthn rows is hard proof jsinspect actually ran.
	// Absence proves nothing, so a configured true is never downgraded.
	webauthnMeasured := enabled.Verify
	if !webauthnMeasured && len(byClient) > 0 {
		webauthnMeasured = true
	}

	defense := PasskeyDefense{Measured: webauthnMeasured}
	if !webauthnMeasured {
		// Not measured: every count stays zero, and Measured=false is the
		// signal a report consumer must render as "not measured" rather
		// than treating these zeros as "no passkeys were available".
		// CorrelationReliable stays at its non-alarming default (no
		// correlation was attempted, so there is nothing to distrust) and
		// Scope stays empty: a caveat about a measurement must not appear
		// next to a metric that reports it never took one.
		defense.CorrelationReliable = true
		return defense
	}
	defense.RanScriptTargets = len(byClient)

	// reachedWeakerFactor keys by the same client identity as byClient
	// (IP-first, see passkeyClientKey) so a client observed with passkey
	// capability can be linked to a later credential/capture event even
	// though StageWebAuthn fires before lure validation assigns an RID.
	reachedWeakerFactor := make(map[string]bool)
	for _, row := range rows {
		stage := telemetry.Stage(row.Stage)
		if stage != telemetry.StageCredential && stage != telemetry.StageCapture {
			continue
		}
		if ip := actorIP(row.Actor); ip != "" {
			reachedWeakerFactor["ip:"+ip] = true
		}
	}

	for key, c := range byClient {
		if c.platformAvailable {
			defense.PlatformAuthenticatorAvailable++
		}
		if c.ceremony {
			defense.CeremonyInitiated++
		}
		if (c.platformAvailable || c.ceremony) && reachedWeakerFactor[key] {
			defense.PushedToWeakerFactor++
		}
	}

	defense.CorrelationReliable = correlationReliable(rows)
	if defense.CorrelationReliable {
		defense.Scope = passkeyScopeCaption
	} else {
		defense.Scope = passkeyScopeUnreliableCaption
	}
	return defense
}

// correlationReliable checks the same row set buildPasskeyDefense already
// has in memory for direct evidence that its IP-based correlation is
// unsafe for this campaign: two or more distinct RIDs whose events share a
// single client IP address. Every RID-attributed stage that also carries
// an actor IP (open, lure, credential, capture -- see their emitters in
// pkg/campaign/models/result.go and pkg/proxy/campaignstore/store.go)
// contributes, not only credential/capture, because the question is
// whether this IP is known to belong to more than one person at all, which
// is exactly what PushedToWeakerFactor's join assumes is false. No new
// query: this reuses rows, which Compute already selected once.
func correlationReliable(rows []eventRow) bool {
	ridsByIP := make(map[string]map[string]bool)
	for _, row := range rows {
		if row.RID == "" {
			continue
		}
		ip := actorIP(row.Actor)
		if ip == "" {
			continue
		}
		if ridsByIP[ip] == nil {
			ridsByIP[ip] = make(map[string]bool)
		}
		ridsByIP[ip][row.RID] = true
	}
	for _, rids := range ridsByIP {
		if len(rids) > 1 {
			return false
		}
	}
	return true
}

// passkeyClientKey identifies the client a StageWebAuthn row belongs to.
// It prefers actor IP specifically (rather than actorIdentity's RID-first
// key) because IP is the only signal shared with the later, RID-attributed
// credential/capture events buildPasskeyDefense correlates against.
func passkeyClientKey(row eventRow) string {
	if ip := actorIP(row.Actor); ip != "" {
		return "ip:" + ip
	}
	return actorIdentity(row.Actor)
}

// actorIP extracts the actor's IP address from its stored JSON, or "" when
// unavailable or unparseable.
func actorIP(actorJSON string) string {
	if actorJSON == "" {
		return ""
	}
	var actor telemetry.Actor
	if err := json.Unmarshal([]byte(actorJSON), &actor); err != nil {
		return ""
	}
	return actor.IP
}

// parseDetail decodes a telemetry_events.detail JSON blob. An empty or
// unparseable value returns nil, which detailBool treats as "false" for
// every key -- consistent with WithDetail's guarantee that every stored
// value is already a plain JSON scalar.
func parseDetail(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		return nil
	}
	return detail
}

// detailBool reads a boolean detail field, defaulting to false for a
// missing key or a value that (should never happen, but) isn't a JSON bool.
func detailBool(detail map[string]any, key string) bool {
	value, ok := detail[key].(bool)
	return ok && value
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
