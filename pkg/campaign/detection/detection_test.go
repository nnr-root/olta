package detection

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/s4l1hs/olta/pkg/campaign/migrations"
	"github.com/s4l1hs/olta/pkg/telemetry"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/campaigndb"
	"gopkg.in/yaml.v2"
)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "detection.db")

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

var base = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func seedAttributed(t *testing.T, db *gorm.DB, offset time.Duration, stage telemetry.Stage,
	outcome telemetry.Outcome, rid string, techniques ...telemetry.Technique) {
	t.Helper()
	event := telemetry.New(stage, outcome, techniques...).WithCampaign(1, rid)
	event.Timestamp = base.Add(offset)
	if err := campaigndb.New(db).Emit(nil, event); err != nil {
		t.Fatal(err)
	}
}

func seedCloak(t *testing.T, db *gorm.DB, offset time.Duration, host, organization, asn string) {
	t.Helper()
	event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked, telemetry.TechniqueProxy).
		WithHost(host).
		WithActor(telemetry.Actor{IP: "198.51.100.10", Organization: organization, ASN: asn})
	event.Timestamp = base.Add(offset)
	if err := campaigndb.New(db).Emit(nil, event); err != nil {
		t.Fatal(err)
	}
}

func testInput() Input {
	return Input{
		CampaignID:      1,
		CampaignName:    "Q3 Finance Test",
		Hostnames:       []string{"login.acme-corp.example"},
		SenderAddresses: []string{"payroll@acme-corp.example"},
		Subjects:        []string{"Payroll update required", "Action needed: payroll"},
	}
}

func wideScope() Scope {
	return Scope{Start: base.Add(-24 * time.Hour), End: base.Add(24 * time.Hour),
		Hosts: []string{"login.acme-corp.example"}}
}

func ruleByLogSource(t *testing.T, pack Pack, logSource string) Rule {
	t.Helper()
	for _, rule := range pack.Rules {
		if rule.LogSource == logSource {
			return rule
		}
	}
	t.Fatalf("no rule for logsource %q in %d rules", logSource, len(pack.Rules))
	return Rule{}
}

func TestBuildCollectsIndicators(t *testing.T) {
	db := newDB(t)
	seedAttributed(t, db, time.Minute, telemetry.StageDelivery, telemetry.OutcomeAllowed, "a",
		telemetry.TechniqueSpearphishingLink)
	seedAttributed(t, db, 5*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "a",
		telemetry.TechniqueStealWebSessionCookie)
	seedCloak(t, db, 2*time.Minute, "login.acme-corp.example", "Palo Alto Networks", "AS54538")
	seedCloak(t, db, 3*time.Minute, "login.acme-corp.example", "Palo Alto Networks", "AS54538")

	pack, err := Build(db, testInput(), wideScope())
	if err != nil {
		t.Fatal(err)
	}

	indicators := pack.Indicators
	if len(indicators.Hostnames) != 1 || indicators.Hostnames[0] != "login.acme-corp.example" {
		t.Errorf("Hostnames = %v", indicators.Hostnames)
	}
	if len(indicators.Techniques) != 3 {
		t.Errorf("Techniques = %v, want the three exercised across delivery, capture and cloak", indicators.Techniques)
	}
	if len(indicators.CloakedNetworks) != 1 || indicators.CloakedNetworks[0].Count != 2 {
		t.Errorf("CloakedNetworks = %+v, want one network with two hits", indicators.CloakedNetworks)
	}
	if !indicators.FirstSeen.Equal(base.Add(time.Minute)) {
		t.Errorf("FirstSeen = %v, want the earliest event", indicators.FirstSeen)
	}
	if !indicators.LastSeen.Equal(base.Add(5 * time.Minute)) {
		t.Errorf("LastSeen = %v, want the latest event", indicators.LastSeen)
	}
	if pack.Scope == "" {
		t.Error("Scope is empty; the pack must say what it is and is not")
	}
}

// TestBuildLearnsHostnamesFromEvents covers a lure served on a hostname the
// stored campaign URL never named -- a redirect chain or a second lure domain
// would otherwise be missing from the content a defender deploys.
func TestBuildLearnsHostnamesFromEvents(t *testing.T) {
	db := newDB(t)
	seedCloak(t, db, time.Minute, "sso.acme-corp.example", "Example Scanner", "AS64500")

	scope := wideScope()
	scope.Hosts = []string{"login.acme-corp.example", "sso.acme-corp.example"}

	pack, err := Build(db, testInput(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Indicators.Hostnames) != 2 {
		t.Fatalf("Hostnames = %v, want both the configured and the observed hostname", pack.Indicators.Hostnames)
	}
	rule := ruleByLogSource(t, pack, "dns_query")
	if !strings.Contains(rule.Sigma, "sso.acme-corp.example") {
		t.Errorf("generated rule omits the observed hostname:\n%s", rule.Sigma)
	}
}

// TestNoVictimAttributesBecomeIndicators is the privacy invariant. The
// telemetry stream is full of the client's own employees' addresses and user
// agents; a pack that turned those into "indicators" would hand a defender a
// blocklist of their own staff.
func TestNoVictimAttributesBecomeIndicators(t *testing.T) {
	db := newDB(t)
	event := telemetry.New(telemetry.StageCredential, telemetry.OutcomeCaptured,
		telemetry.TechniqueWebPortalCapture).
		WithCampaign(1, "target-a").
		WithActor(telemetry.Actor{IP: "10.20.30.40", UserAgent: "Mozilla/5.0 (Victim Browser)"})
	event.Timestamp = base.Add(time.Minute)
	if err := campaigndb.New(db).Emit(nil, event); err != nil {
		t.Fatal(err)
	}

	pack, err := Build(db, testInput(), wideScope())
	if err != nil {
		t.Fatal(err)
	}

	bundle := pack.SigmaBundle()
	for _, victimValue := range []string{"10.20.30.40", "Victim Browser", "target-a"} {
		if strings.Contains(bundle, victimValue) {
			t.Errorf("bundle contains victim-side value %q:\n%s", victimValue, bundle)
		}
	}
}

func TestGeneratedRulesAreValidYAML(t *testing.T) {
	db := newDB(t)
	seedAttributed(t, db, time.Minute, telemetry.StageDelivery, telemetry.OutcomeAllowed, "a",
		telemetry.TechniqueSpearphishingLink)

	pack, err := Build(db, testInput(), wideScope())
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Rules) != 3 {
		t.Fatalf("got %d rules, want 3 (dns, proxy, mail)", len(pack.Rules))
	}

	for _, rule := range pack.Rules {
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(rule.Sigma), &parsed); err != nil {
			t.Fatalf("rule %q is not valid YAML: %v\n%s", rule.Title, err, rule.Sigma)
		}
		for _, required := range []string{"title", "id", "logsource", "detection", "level"} {
			if _, present := parsed[required]; !present {
				t.Errorf("rule %q is missing the required %q field", rule.Title, required)
			}
		}
		detection, _ := parsed["detection"].(map[any]any)
		if detection["condition"] == nil {
			t.Errorf("rule %q has no detection condition", rule.Title)
		}
		if len(rule.Requires) == 0 {
			t.Errorf("rule %q does not say which logsource it needs", rule.Title)
		}
	}
}

// TestRuleIDsAreStableAcrossRuns is what makes the pack usable in a
// defender's rule management: regenerating it must update the same rules
// rather than look like a fresh set.
func TestRuleIDsAreStableAcrossRuns(t *testing.T) {
	db := newDB(t)
	seedAttributed(t, db, time.Minute, telemetry.StageDelivery, telemetry.OutcomeAllowed, "a")

	first, err := Build(db, testInput(), wideScope())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(db, testInput(), wideScope())
	if err != nil {
		t.Fatal(err)
	}

	if len(first.Rules) != len(second.Rules) {
		t.Fatalf("rule counts differ: %d vs %d", len(first.Rules), len(second.Rules))
	}
	for i := range first.Rules {
		if first.Rules[i].ID != second.Rules[i].ID {
			t.Errorf("rule %d ID changed between runs: %q vs %q", i, first.Rules[i].ID, second.Rules[i].ID)
		}
	}
}

// TestRuleIDsDifferPerCampaign is the other half: two campaigns must not
// produce colliding rule IDs, or deploying the second pack overwrites the
// first.
func TestRuleIDsDifferPerCampaign(t *testing.T) {
	db := newDB(t)
	seedAttributed(t, db, time.Minute, telemetry.StageDelivery, telemetry.OutcomeAllowed, "a")

	first, err := Build(db, testInput(), wideScope())
	if err != nil {
		t.Fatal(err)
	}
	otherInput := testInput()
	otherInput.CampaignID = 2
	second, err := Build(db, otherInput, wideScope())
	if err != nil {
		t.Fatal(err)
	}

	for i := range first.Rules {
		if first.Rules[i].ID == second.Rules[i].ID {
			t.Errorf("rule %d has the same ID for two campaigns: %q", i, first.Rules[i].ID)
		}
	}
}

func TestRuleIDsAreWellFormedUUIDs(t *testing.T) {
	id := deterministicUUID(42, "dns")
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Fatalf("id = %q, want five hyphen-separated groups", id)
	}
	for i, want := range []int{8, 4, 4, 4, 12} {
		if len(parts[i]) != want {
			t.Errorf("group %d has %d characters, want %d: %q", i, len(parts[i]), want, id)
		}
	}
	if parts[2][0] != '4' {
		t.Errorf("version nibble = %q, want 4: %q", parts[2][0], id)
	}
	if !strings.ContainsRune("89ab", rune(parts[3][0])) {
		t.Errorf("variant nibble = %q, want one of 8/9/a/b: %q", parts[3][0], id)
	}
}

// TestNoRulesWithoutIndicators is the safety rule that matters most: a Sigma
// selection with an empty value list matches everything, so a campaign with
// nothing to match on must produce no rule rather than one that alerts on all
// traffic.
func TestNoRulesWithoutIndicators(t *testing.T) {
	db := newDB(t)

	pack, err := Build(db, Input{CampaignID: 1}, Scope{Start: base, End: base.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Rules) != 0 {
		t.Fatalf("got %d rules for a campaign with no indicators; an empty selection matches everything", len(pack.Rules))
	}
}

// TestMailRuleOmittedWithoutMailIndicators covers the partial case: hostnames
// but no sender or subject still produces the network rules and no mail rule.
func TestMailRuleOmittedWithoutMailIndicators(t *testing.T) {
	db := newDB(t)
	input := testInput()
	input.SenderAddresses = nil
	input.Subjects = nil

	pack, err := Build(db, input, wideScope())
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Rules) != 2 {
		t.Fatalf("got %d rules, want 2 (dns and proxy only)", len(pack.Rules))
	}
	for _, rule := range pack.Rules {
		if strings.Contains(rule.LogSource, "mail") {
			t.Errorf("mail rule generated with no sender or subject: %+v", rule)
		}
	}
}

// TestFalsePositivesNameTheEngagement keeps an analyst from chasing the test
// itself as an incident.
func TestFalsePositivesNameTheEngagement(t *testing.T) {
	db := newDB(t)
	pack, err := Build(db, testInput(), wideScope())
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range pack.Rules {
		if !strings.Contains(rule.Sigma, "authorized Olta engagement") {
			t.Errorf("rule %q does not list the engagement itself as a false positive:\n%s", rule.Title, rule.Sigma)
		}
	}
}

func TestSigmaBundleIsMultiDocument(t *testing.T) {
	db := newDB(t)
	seedAttributed(t, db, time.Minute, telemetry.StageDelivery, telemetry.OutcomeAllowed, "a")

	pack, err := Build(db, testInput(), wideScope())
	if err != nil {
		t.Fatal(err)
	}
	bundle := pack.SigmaBundle()

	if got := strings.Count(bundle, "\n---\n"); got != len(pack.Rules) {
		t.Errorf("bundle has %d document separators, want %d", got, len(pack.Rules))
	}
	if !strings.HasPrefix(bundle, "# Olta detection pack") {
		t.Errorf("bundle has no header comment:\n%s", bundle[:min(200, len(bundle))])
	}
	for _, line := range strings.Split(bundle, "\n") {
		if strings.HasPrefix(line, "#") && len(line) > 90 {
			t.Errorf("header comment line is not wrapped (%d chars): %q", len(line), line)
		}
	}
}

func TestSigmaTagsUseAttackPrefix(t *testing.T) {
	tags := sigmaTags([]telemetry.Technique{telemetry.TechniqueSpearphishingLink, telemetry.TechniqueProxy})
	want := []string{"attack.t1566.002", "attack.t1090"}
	if len(tags) != len(want) {
		t.Fatalf("tags = %v, want %v", tags, want)
	}
	for i := range tags {
		if tags[i] != want[i] {
			t.Errorf("tag %d = %q, want %q", i, tags[i], want[i])
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
