// Package detection turns what an engagement actually observed into
// detection content a defender can deploy.
//
// The resilience report answers "where did our defenses hold". This answers
// the question a debrief always ends on: "so how do we catch this next
// time?". Everything here is derived from the engagement's own telemetry and
// campaign configuration -- it is a record of what this test did, not threat
// intelligence about a real adversary, and the pack says so in its own Scope
// caption rather than leaving a reader to assume otherwise.
//
// Two deliberate limits:
//
//   - Victim-side attributes are never indicators. The IP addresses and user
//     agents in the telemetry stream belong to the client's own employees;
//     turning them into "indicators of compromise" would hand a defender a
//     blocklist of their own staff. Only operator-controlled infrastructure
//     -- the phishing hostnames, the sending addresses, the subjects --
//     becomes an indicator.
//
//   - Nothing here claims a rule will fire. A generated rule names the
//     logsource and fields it needs; whether the client actually collects
//     that logsource is exactly the gap a purple-team engagement exists to
//     find, and pretending otherwise would be the same "measured/not
//     measured" dishonesty the resilience report is careful to avoid.
package detection

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Scope bounds which telemetry rows contribute, mirroring
// resilience.Scope: attributed rows come from the campaign, unattributed
// ones from the campaign's window and hostnames.
type Scope struct {
	Start time.Time
	End   time.Time
	Hosts []string
}

// Input carries the campaign-side facts this package does not read for
// itself. Like resilience, this stays a query layer over telemetry_events
// and does not touch the campaigns table.
type Input struct {
	CampaignID   int64
	CampaignName string
	// Hostnames the campaign's lure URL points at.
	Hostnames []string
	// SenderAddresses is the envelope/from address the campaign sent from.
	SenderAddresses []string
	// Subjects is the campaign's template subject lines, including every
	// A/B variant, since a defender's mail rule has to match whichever one
	// a given recipient received.
	Subjects []string
}

// Network is a network the cloaker turned away during the engagement.
type Network struct {
	Organization string `json:"organization,omitempty"`
	ASN          string `json:"asn,omitempty"`
	Count        int    `json:"count"`
}

// Indicators are the operator-controlled artifacts of this engagement.
type Indicators struct {
	Hostnames       []string              `json:"hostnames"`
	SenderAddresses []string              `json:"sender_addresses,omitempty"`
	Subjects        []string              `json:"subjects,omitempty"`
	Techniques      []telemetry.Technique `json:"techniques,omitempty"`
	// CloakedNetworks are the networks the proxy's cloaker turned away.
	// These are not indicators of the attack -- they are usually the
	// client's own scanning and security infrastructure, and they are
	// included because "our sandbox reached the lure and was filtered" is a
	// finding a defender needs, not something to block.
	CloakedNetworks []Network `json:"cloaked_networks,omitempty"`
	// FirstSeen and LastSeen bound the observed activity, so a defender
	// hunting historically knows which period to search.
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// Rule is one generated Sigma rule.
type Rule struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	LogSource string   `json:"logsource"`
	Requires  []string `json:"requires"`
	// Sigma is the rendered rule document.
	Sigma string `json:"sigma"`
}

// Pack is the full detection bundle for one campaign.
type Pack struct {
	CampaignID  int64      `json:"campaign_id"`
	GeneratedAt time.Time  `json:"generated_at"`
	Indicators  Indicators `json:"indicators"`
	Rules       []Rule     `json:"rules"`
	// Scope is the caveat that must travel with the pack wherever it is
	// rendered or exported.
	Scope string `json:"scope"`
}

const scopeCaption = "This pack is derived from one authorized Olta engagement: the hostnames, " +
	"sender addresses and subjects below are the operator's own test infrastructure, not " +
	"indicators of a real adversary, and they stop being useful once the engagement ends. " +
	"Client-side addresses and user agents are deliberately excluded -- they belong to the target " +
	"organization's own people. A rule firing depends on the named logsource actually being " +
	"collected; this pack cannot tell you whether it is, which is itself worth checking."

// eventRow mirrors the columns Build reads. The rid column is named
// explicitly for the same reason resilience does it: gorm converts the field
// name "RID" to "r_id", not "rid".
type eventRow struct {
	Stage      string
	Outcome    string
	Timestamp  time.Time
	Actor      string
	Host       string
	Techniques string
	RID        string `gorm:"column:rid"`
}

// Build assembles the pack for one campaign.
func Build(db *gorm.DB, input Input, scope Scope) (Pack, error) {
	var rows []eventRow
	query := db.Table("telemetry_events").
		Select("stage, outcome, timestamp, actor, host, techniques, rid")
	if len(scope.Hosts) == 0 {
		query = query.Where("campaign_id = ? OR (campaign_id = 0 AND timestamp >= ? AND timestamp <= ?)",
			input.CampaignID, scope.Start, scope.End)
	} else {
		query = query.Where(
			"campaign_id = ? OR (campaign_id = 0 AND timestamp >= ? AND timestamp <= ? AND (host IN (?) OR host IS NULL OR host = ''))",
			input.CampaignID, scope.Start, scope.End, scope.Hosts)
	}
	if err := query.Scan(&rows).Error; err != nil {
		return Pack{}, err
	}

	pack := Pack{
		CampaignID:  input.CampaignID,
		GeneratedAt: time.Now().UTC(),
		Indicators:  buildIndicators(input, rows),
		Scope:       scopeCaption,
	}
	pack.Rules = buildRules(input, pack.Indicators)
	return pack, nil
}

func buildIndicators(input Input, rows []eventRow) Indicators {
	indicators := Indicators{
		Hostnames:       normalizedSet(input.Hostnames),
		SenderAddresses: normalizedSet(input.SenderAddresses),
		Subjects:        trimmedSet(input.Subjects),
	}

	hostnames := make(map[string]bool, len(indicators.Hostnames))
	for _, host := range indicators.Hostnames {
		hostnames[host] = true
	}
	techniques := make(map[string]bool)
	cloaked := make(map[Network]int)

	for _, row := range rows {
		if indicators.FirstSeen.IsZero() || row.Timestamp.Before(indicators.FirstSeen) {
			indicators.FirstSeen = row.Timestamp.UTC()
		}
		if row.Timestamp.After(indicators.LastSeen) {
			indicators.LastSeen = row.Timestamp.UTC()
		}
		// A hostname the engagement actually served on belongs in the pack
		// even when the campaign's stored URL did not name it -- a redirect
		// chain or a second lure domain would otherwise be missing from the
		// content a defender deploys.
		if host := telemetry.NormalizeHost(row.Host); host != "" && !hostnames[host] {
			hostnames[host] = true
			indicators.Hostnames = append(indicators.Hostnames, host)
		}
		for _, technique := range strings.Split(row.Techniques, ",") {
			technique = strings.TrimSpace(technique)
			if technique != "" {
				techniques[technique] = true
			}
		}
		if telemetry.Stage(row.Stage) == telemetry.StageCloak {
			var actor telemetry.Actor
			if row.Actor != "" && json.Unmarshal([]byte(row.Actor), &actor) == nil {
				if actor.Organization != "" || actor.ASN != "" {
					cloaked[Network{Organization: actor.Organization, ASN: actor.ASN}]++
				}
			}
		}
	}

	sort.Strings(indicators.Hostnames)
	indicators.Techniques = sortedTechniques(techniques)
	indicators.CloakedNetworks = sortedNetworks(cloaked)
	return indicators
}

func sortedTechniques(set map[string]bool) []telemetry.Technique {
	if len(set) == 0 {
		return nil
	}
	out := make([]telemetry.Technique, 0, len(set))
	for technique := range set {
		out = append(out, telemetry.Technique(technique))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedNetworks(counts map[Network]int) []Network {
	if len(counts) == 0 {
		return nil
	}
	out := make([]Network, 0, len(counts))
	for network, count := range counts {
		network.Count = count
		out = append(out, network)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Organization < out[j].Organization
	})
	return out
}

func normalizedSet(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func trimmedSet(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
