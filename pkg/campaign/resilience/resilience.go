// Package resilience computes the per-campaign purple-team report from the
// telemetry event stream.
package resilience

import (
	"encoding/json"
	"sort"
	"strings"
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

// FeaturesSource records where a report's Features actually came from. The
// distinction is load-bearing, not cosmetic: Features drives the
// measured/unmeasured split, which is the single claim this report is most
// careful about, and a hand-maintained configuration value can silently
// disagree with how the proxy was really launched.
type FeaturesSource string

const (
	// FeaturesSourceProxy means the posture was read from the proxy's own
	// StageInitialization telemetry -- what the process was actually
	// launched with, not what someone wrote in a config file.
	FeaturesSourceProxy FeaturesSource = "proxy"

	// FeaturesSourceConfiguration means no initialization event covering
	// this campaign was found, so the caller's configured values were used.
	// That happens with a proxy predating startup telemetry, or one whose
	// events never reached this database.
	FeaturesSourceConfiguration FeaturesSource = "configuration"
)

// Detail keys on a StageInitialization event that carry the proxy's
// measurement posture. They are written by cmd/olta-proxy's
// buildStartupEvent; changing either side without the other silently
// returns the report to trusting configuration.
const (
	detailKeyCloakerEnabled          = "cloaker_enabled"
	detailKeyJSInspectEnabled        = "js_inspect_enabled"
	detailKeySessionValidatorEnabled = "session_validator_enabled"
)

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

	// CorrelationMethod says how PushedToWeakerFactor's join was actually
	// performed for this campaign, which decides how much the number can be
	// trusted. CorrelationRecipient is exact. CorrelationIP is the older
	// approximation that conflates clients sharing an egress IP.
	// CorrelationMixed means both were needed, so the count is exact for
	// some clients and approximate for others.
	CorrelationMethod CorrelationMethod `json:"correlation_method,omitempty"`

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

// CorrelationMethod names how PasskeyDefense linked a client's pre-lure
// passkey observation to its post-lure credential or capture activity.
type CorrelationMethod string

const (
	// CorrelationRecipient means every observation named a recipient, so the
	// join is exact and no two people can be conflated.
	CorrelationRecipient CorrelationMethod = "recipient"
	// CorrelationIP means no observation named a recipient and the join fell
	// back to client IP address, which counts clients sharing an egress IP
	// as one.
	CorrelationIP CorrelationMethod = "ip"
	// CorrelationMixed means both were used: some clients joined exactly,
	// others by IP.
	CorrelationMixed CorrelationMethod = "mixed"
)

// TokenLifetime measures how long captured session tokens stayed usable, from
// the repeated replay attempts the session validator makes against each
// captured session.
//
// This is the number a defender acts on: it is the window during which a
// stolen session was live, and the only direct evidence of whether revocation
// actually happened rather than being assumed. It is also the one measure here
// that is inherently incomplete, so its shape follows the incompleteness
// rather than hiding it:
//
//   - Sessions still valid at their last check are *censored* observations:
//     the token outlived the measurement, so its true lifetime is unknown and
//     only a lower bound is available. They are counted separately and
//     excluded from the median, which would otherwise be dragged down by
//     every session that simply had not been watched long enough.
//   - MedianTimeToRevocationSeconds is computed only over sessions actually
//     observed being refused. It answers "when revocation happened, how long
//     did it take", not "how long do tokens last".
//   - BlockedOnFirstAttempt is the strongest single signal in here: the
//     validator replays from the proxy's own network, not the victim's, so a
//     session refused on the very first attempt is direct evidence that the
//     target's controls -- conditional access, impossible-travel, device
//     binding -- rejected a stolen session outright.
type TokenLifetime struct {
	Measured bool `json:"measured"`

	// Sessions is the denominator: distinct captured sessions with at least
	// one replay attempt. It is not the campaign's capture count, since a
	// session with no usable cookie domain is never queued for validation.
	Sessions int `json:"sessions"`

	// StillValidAtLastCheck counts sessions whose most recent attempt still
	// succeeded -- censored observations, whose true lifetime is unknown.
	StillValidAtLastCheck int `json:"still_valid_at_last_check"`

	// Revoked counts sessions observed being refused after having worked.
	Revoked int `json:"revoked"`

	// BlockedOnFirstAttempt counts sessions refused on the very first
	// replay, before any recheck. These never worked for the attacker at
	// all.
	BlockedOnFirstAttempt int `json:"blocked_on_first_attempt"`

	// LongestObservedValidSeconds is the largest age at which any session
	// was still accepted. It is a lower bound on the worst case, never the
	// worst case itself.
	LongestObservedValidSeconds int64 `json:"longest_observed_valid_seconds"`

	// MedianTimeToRevocationSeconds covers only the Revoked population. As
	// elsewhere in this package, the separate boolean distinguishes "no
	// session was observed being revoked" from a genuine zero.
	MedianTimeToRevocationSeconds int64 `json:"median_time_to_revocation_seconds"`
	HasMedianTimeToRevocation     bool  `json:"has_median_time_to_revocation"`

	// Scope is the caveat that must travel with every count above.
	Scope string `json:"scope,omitempty"`
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

// Scope bounds the unattributed (campaign_id = 0) cloak, verify and webauthn
// events folded into a campaign's report. Attributed rows need no bound:
// they are already scoped by campaign_id. Those three stages fire before
// lure validation establishes a recipient, so they can never carry one.
//
// Two dimensions bound them, and the difference between having one and
// having both is the difference between an approximation and a fact:
//
//   - Start/End is the campaign's active period. On its own it is only an
//     approximation, because two campaigns running concurrently on one
//     install share a window and therefore share each other's unattributed
//     traffic.
//
//   - Hosts is the campaign's own phishing hostname(s). Events carry the
//     hostname they were serving (see telemetry.Event.Host), so campaigns
//     on different hostnames no longer contaminate each other regardless of
//     overlap in time. Campaigns sharing one hostname fall back to the
//     window alone, which is honest: nothing in the data distinguishes them.
//
// Hosts may be empty, in which case only the window applies and the report
// says so. Entries must be normalized with telemetry.NormalizeHost.
type Scope struct {
	Start time.Time
	End   time.Time
	Hosts []string
}

// Report is the full per-campaign resilience view.
type Report struct {
	CampaignID int64    `json:"campaign_id"`
	Features   Features `json:"features"`
	// FeaturesSource says whether Features was read from the proxy's own
	// startup telemetry or fell back to the caller's configuration, and
	// FeaturesScope is the caveat to render when it fell back. A reader
	// deciding what "not measured" means for this campaign needs to know
	// which of the two they are looking at.
	FeaturesSource FeaturesSource  `json:"features_source"`
	FeaturesScope  string          `json:"features_scope,omitempty"`
	Funnel         []FunnelStage   `json:"funnel"`
	Friction       []FrictionEntry `json:"friction"`
	Race           RaceSummary     `json:"race"`
	// Passkey is the passkey/WebAuthn defense measure -- see PasskeyDefense's
	// doc comment for the denominator and "not measured" rules that govern
	// how a consumer must render it.
	Passkey PasskeyDefense `json:"passkey"`
	// Tokens measures how long captured sessions stayed usable. See
	// TokenLifetime for the censoring rules a consumer must respect.
	Tokens TokenLifetime `json:"tokens"`
	// UnattributedScoped is true when the unattributed cloak/verify events
	// folded into Funnel and Friction were bounded to the campaign window.
	// FrictionScope is the human-readable caveat the dashboard must render
	// alongside Defensive Friction: a time window narrows unattributed
	// traffic to the campaign's active period, but it cannot prove the
	// traffic came from this campaign rather than another one running on
	// the same install at the same time.
	UnattributedScoped bool `json:"unattributed_scoped"`
	// UnattributedHostScoped is true when those events were additionally
	// narrowed to the campaign's own phishing hostnames, which turns the
	// time-window approximation into an actual separation between campaigns
	// running concurrently on one install.
	UnattributedHostScoped bool   `json:"unattributed_host_scoped"`
	FrictionScope          string `json:"friction_scope"`
}

// featuresScopeCaption travels with a report whose posture could not be read
// from the proxy. It names the failure mode plainly rather than implying the
// measured/unmeasured split is authoritative.
const featuresScopeCaption = "No proxy startup record was found for this campaign's time range, " +
	"so measured/not-measured below reflects the campaign service's configured telemetry settings " +
	"rather than the flags olta-proxy was actually launched with. If the two disagree, this report " +
	"does too."

const frictionScopeCaption = "Cloak and verify counts include unattributed proxy traffic " +
	"(no recipient was resolved yet) recorded during this campaign's time window. " +
	"They may include traffic from other campaigns running concurrently on the same install."

// frictionScopeHostCaption replaces the caption above once the unattributed
// events have also been narrowed to the campaign's own hostnames. The claim
// is genuinely stronger, so the caveat is genuinely smaller -- but it is not
// absent: events recorded before hostnames were stamped carry none and are
// still admitted on the time window alone.
const frictionScopeHostCaption = "Cloak and verify counts include unattributed proxy traffic " +
	"(no recipient was resolved yet) served on this campaign's own phishing hostnames during its " +
	"time window, so traffic for campaigns running on other hostnames is excluded. Events recorded " +
	"before hostnames were captured carry none and are still included on the time window alone; " +
	"campaigns sharing a hostname cannot be separated at all."

// passkeyScopeCaption is PasskeyDefense.Scope's default text: it holds
// regardless of whether this campaign's data happens to show a correlation
// collision, so passkeyScopeUnreliableCaption below builds on it rather
// than restating it.
const passkeyScopeCaption = "These counts only cover clients whose browser ran the injected " +
	"verification script -- not every target in the campaign. Pushed-to-weaker-factor links each " +
	"client's pre-lure passkey check to its post-lure credential or session-capture activity by " +
	"client IP address, so clients sharing an egress IP (for example, employees behind the same " +
	"corporate NAT) may be counted as a single client."

// passkeyScopeExactCaption replaces passkeyScopeCaption when every passkey
// observation named a recipient. The denominator caveat still holds -- these
// counts only cover clients whose browser ran the script -- but the
// shared-IP conflation warning does not apply at all, and repeating it would
// understate a number that is actually exact.
const passkeyScopeExactCaption = "These counts only cover clients whose browser ran the injected " +
	"verification script -- not every target in the campaign. Each client's pre-lure passkey check " +
	"is linked to its own post-lure credential or session-capture activity by recipient ID, so " +
	"clients sharing an egress IP are not conflated."

// passkeyScopeMixedCaption covers a campaign where some observations named a
// recipient and some did not, which is what an upgrade mid-engagement, or a
// target who reached the proxy without a valid lure, produces.
const passkeyScopeMixedCaption = "These counts only cover clients whose browser ran the injected " +
	"verification script -- not every target in the campaign. Some clients were linked to their own " +
	"later activity by recipient ID, which is exact; the rest were linked by client IP address, so " +
	"those may count clients sharing an egress IP (for example, employees behind the same corporate " +
	"NAT) as a single client."

// passkeyScopeUnreliableSuffix is appended to the mixed caption when the
// campaign's own rows show the IP-based half actually colliding.
const passkeyScopeUnreliableSuffix = "This campaign's own data shows that collision happening: more " +
	"than one target was observed behind the same IP address, so treat pushed-to-weaker-factor as an " +
	"upper bound on distinct people affected, not an exact count."

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
	// Host is selected so the scoping decision is visible in the row set
	// itself, and so a future consumer can group by hostname without
	// another query.
	Host string
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
func Compute(db *gorm.DB, campaignID int64, scope Scope, configured Features) (Report, error) {
	enabled, source, err := resolveFeatures(db, scope, configured)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		CampaignID:             campaignID,
		Features:               enabled,
		FeaturesSource:         source,
		UnattributedScoped:     true,
		UnattributedHostScoped: len(scope.Hosts) > 0,
		FrictionScope:          frictionScopeCaption,
	}
	if len(scope.Hosts) > 0 {
		report.FrictionScope = frictionScopeHostCaption
	}
	if source == FeaturesSourceConfiguration {
		report.FeaturesScope = featuresScopeCaption
	}

	var rows []eventRow
	query := db.Table("telemetry_events").
		Select("stage, outcome, rid, timestamp, actor, campaign_id, detail, host")
	if len(scope.Hosts) == 0 {
		query = query.Where("campaign_id = ? OR (campaign_id = 0 AND timestamp >= ? AND timestamp <= ?)",
			campaignID, scope.Start, scope.End)
	} else {
		// An unattributed row is this campaign's when it was served on one
		// of the campaign's own hostnames. Rows with no hostname are kept
		// rather than dropped: every event recorded before host stamping
		// existed has a null host, and excluding them would silently erase
		// the history of any campaign that ran before the upgrade. The
		// caption says as much.
		query = query.Where(
			"campaign_id = ? OR (campaign_id = 0 AND timestamp >= ? AND timestamp <= ? AND (host IN (?) OR host IS NULL OR host = ''))",
			campaignID, scope.Start, scope.End, scope.Hosts)
	}
	if err := query.Scan(&rows).Error; err != nil {
		return Report{}, err
	}

	report.Funnel = buildFunnel(rows, enabled)
	report.Friction = buildFriction(rows)
	report.Race = buildRace(rows)
	report.Passkey = buildPasskeyDefense(rows, enabled)
	report.Tokens = buildTokenLifetime(rows, enabled)
	return report, nil
}

// resolveFeatures determines the measurement posture actually in effect for
// a campaign, preferring the proxy's own StageInitialization telemetry over
// the caller's configuration.
//
// Why this exists: Features drives the measured/unmeasured split, and the
// caller's value comes from a "telemetry" block in the campaign service's
// config.json that an operator has to keep in step, by hand, with the flags
// olta-proxy was launched with. When those disagree the report does not
// merely lose detail -- it makes a false claim, reporting "not measured" for
// a control that ran, or "measured, saw nothing" for one that was never on.
// That is exactly the distinction this package exists to protect. The proxy
// already records what it really started with (cmd/olta-proxy's
// buildStartupEvent), so the report reads that instead.
//
// Which events count: a long-running proxy emits its initialization event
// once at startup, typically long before any given campaign launches, so
// bounding this to the campaign window alone would almost always find
// nothing. Instead it takes the last initialization event *before* the
// window -- the posture in effect when the campaign launched -- together
// with every initialization event *inside* the window, which is how a
// restart mid-campaign shows up.
//
// How several events combine: by OR, never by last-one-wins. If any proxy
// serving during the window had the cloaker on, cloak events for that proxy
// can exist in the row set, and reporting them as unmeasured would hide real
// data. This mirrors the rule buildFunnel already applies, which upgrades a
// stage to measured on proof and never downgrades it.
//
// Falling back is not a failure: a proxy predating startup telemetry, or one
// whose events never reached this database, leaves nothing to read and the
// configured values are used, with the source recorded so the reader knows.
func resolveFeatures(db *gorm.DB, scope Scope, configured Features) (Features, FeaturesSource, error) {
	var priorRows []eventRow
	prior := db.Table("telemetry_events").
		Select("stage, detail, timestamp").
		Where("stage = ? AND timestamp < ?", string(telemetry.StageInitialization), scope.Start).
		Order("timestamp desc").
		Limit(1)
	if err := prior.Scan(&priorRows).Error; err != nil {
		return Features{}, "", err
	}

	var windowRows []eventRow
	within := db.Table("telemetry_events").
		Select("stage, detail, timestamp").
		Where("stage = ? AND timestamp >= ? AND timestamp <= ?",
			string(telemetry.StageInitialization), scope.Start, scope.End)
	if err := within.Scan(&windowRows).Error; err != nil {
		return Features{}, "", err
	}

	rows := append(priorRows, windowRows...)
	if len(rows) == 0 {
		return configured, FeaturesSourceConfiguration, nil
	}

	var observed Features
	for _, row := range rows {
		detail := parseDetail(row.Detail)
		observed.Cloaker = observed.Cloaker || detailBool(detail, detailKeyCloakerEnabled)
		observed.Verify = observed.Verify || detailBool(detail, detailKeyJSInspectEnabled)
		observed.SessionValidator = observed.SessionValidator || detailBool(detail, detailKeySessionValidatorEnabled)
	}
	return observed, FeaturesSourceProxy, nil
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

	// reachedWeakerFactor keys by the same client identities passkeyClientKey
	// produces, so a client observed with passkey capability links to its own
	// later credential/capture event. Each row contributes both keys it can:
	// a recipient-keyed webauthn client matches on the recipient, and a
	// legacy IP-keyed one still matches on the IP.
	reachedWeakerFactor := make(map[string]bool)
	for _, row := range rows {
		stage := telemetry.Stage(row.Stage)
		if stage != telemetry.StageCredential && stage != telemetry.StageCapture {
			continue
		}
		if row.RID != "" {
			reachedWeakerFactor["rid:"+row.RID] = true
		}
		if ip := actorIP(row.Actor); ip != "" {
			reachedWeakerFactor["ip:"+ip] = true
		}
	}

	recipientKeyed, ipKeyed := 0, 0
	for key, c := range byClient {
		if strings.HasPrefix(key, "rid:") {
			recipientKeyed++
		} else {
			ipKeyed++
		}
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

	// How the correlation was actually done decides both the method reported
	// and how much of a caveat the counts need. Recipient-keyed clients are
	// joined exactly and carry no conflation risk at all; IP-keyed ones are
	// the old approximation and still do.
	switch {
	case ipKeyed == 0 && recipientKeyed > 0:
		defense.CorrelationMethod = CorrelationRecipient
		defense.CorrelationReliable = true
		defense.Scope = passkeyScopeExactCaption
	case recipientKeyed == 0:
		defense.CorrelationMethod = CorrelationIP
		defense.CorrelationReliable = correlationReliable(rows)
		defense.Scope = passkeyScopeCaption
		if !defense.CorrelationReliable {
			defense.Scope = passkeyScopeUnreliableCaption
		}
	default:
		defense.CorrelationMethod = CorrelationMixed
		defense.CorrelationReliable = correlationReliable(rows)
		defense.Scope = passkeyScopeMixedCaption
		if !defense.CorrelationReliable {
			defense.Scope = passkeyScopeMixedCaption + " " + passkeyScopeUnreliableSuffix
		}
	}
	return defense
}

const tokenLifetimeScopeCaption = "Token lifetime is measured by replaying each captured session " +
	"from the proxy's own network. Sessions still valid at their last check had not been observed " +
	"expiring, so their true lifetime is longer than shown and they are excluded from the median " +
	"time to revocation, which covers only sessions actually seen being refused. A proxy restarted " +
	"mid-engagement loses pending rechecks, which truncates a session's observed lifetime rather " +
	"than extending it."

// buildTokenLifetime folds the replay attempts for each captured session into
// one observation per session. Attempts are grouped by the session_reference
// detail -- a truncated digest of the session ID (see
// validation.baseResult), never the session ID itself -- because a replay
// event carries no RID: the validator works from the captured session, which
// the proxy holds independently of any recipient.
func buildTokenLifetime(rows []eventRow, enabled Features) TokenLifetime {
	type observation struct {
		lastValidAge   int64
		firstBlockedAt int64
		sawValid       bool
		sawBlocked     bool
		blockedFirst   bool
	}
	bySession := make(map[string]*observation)

	for _, row := range rows {
		if telemetry.Stage(row.Stage) != telemetry.StageReplay {
			continue
		}
		detail := parseDetail(row.Detail)
		reference := detailString(detail, "session_reference")
		if reference == "" {
			continue
		}
		obs := bySession[reference]
		if obs == nil {
			obs = &observation{}
			bySession[reference] = obs
		}
		age := detailInt(detail, "age_seconds")
		attempt := detailInt(detail, "attempt")

		switch telemetry.Outcome(row.Outcome) {
		case telemetry.OutcomeAllowed:
			obs.sawValid = true
			if age > obs.lastValidAge {
				obs.lastValidAge = age
			}
		case telemetry.OutcomeBlocked:
			// The first refusal is the one that dates the revocation; a
			// later attempt cannot happen anyway, since the schedule stops
			// there.
			if !obs.sawBlocked || age < obs.firstBlockedAt {
				obs.firstBlockedAt = age
			}
			obs.sawBlocked = true
			// attempt is 1-based, and defaults to 0 for an event emitted
			// before it existed -- which was always a single first attempt.
			if attempt <= 1 {
				obs.blockedFirst = true
			}
		}
	}

	// Self-correction, exactly like the funnel's optional stages: a stale
	// configured false is corrected by rows that prove the validator ran, and
	// a configured true is never downgraded by their absence.
	measured := enabled.SessionValidator
	if !measured && len(bySession) > 0 {
		measured = true
	}

	lifetime := TokenLifetime{Measured: measured}
	if !measured {
		return lifetime
	}

	lifetime.Sessions = len(bySession)
	revocations := make([]int64, 0, len(bySession))
	for _, obs := range bySession {
		switch {
		case obs.sawBlocked && obs.blockedFirst && !obs.sawValid:
			lifetime.BlockedOnFirstAttempt++
		case obs.sawBlocked:
			lifetime.Revoked++
			revocations = append(revocations, obs.firstBlockedAt)
		case obs.sawValid:
			lifetime.StillValidAtLastCheck++
		}
		if obs.sawValid && obs.lastValidAge > lifetime.LongestObservedValidSeconds {
			lifetime.LongestObservedValidSeconds = obs.lastValidAge
		}
	}
	lifetime.MedianTimeToRevocationSeconds = median(revocations)
	lifetime.HasMedianTimeToRevocation = len(revocations) > 0
	if lifetime.Sessions > 0 {
		lifetime.Scope = tokenLifetimeScopeCaption
	}
	return lifetime
}

// detailString reads a string detail field, defaulting to "" for a missing
// key or a non-string value.
func detailString(detail map[string]any, key string) string {
	value, _ := detail[key].(string)
	return value
}

// detailInt reads a numeric detail field. Details round-trip through JSON, so
// every number arrives as a float64 regardless of the Go type that was
// stored.
func detailInt(detail map[string]any, key string) int64 {
	switch value := detail[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	default:
		return 0
	}
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
//
// A recipient ID is preferred when the row carries one: jsinspect now hands
// the injected script the session's recipient ID and the script reports it
// back, so the observation names an actual target. That is an exact
// identity, and it is what removes the shared-egress-IP conflation the
// IP-based fallback below suffers from.
//
// Falling back to the actor IP covers rows produced before that existed, and
// rows for a page that carried no session at all -- a target who reached the
// proxy without a valid lure. Those keep the old, approximate behavior, and
// the report says which of the two it used through
// PasskeyDefense.CorrelationMethod.
func passkeyClientKey(row eventRow) string {
	if row.RID != "" {
		return "rid:" + row.RID
	}
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
