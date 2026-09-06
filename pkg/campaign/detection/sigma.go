package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/s4l1hs/olta/pkg/telemetry"
	"gopkg.in/yaml.v2"
)

// sigmaRule is the Sigma document structure. Field order here is the order
// yaml.v2 emits, and it follows the order the Sigma specification presents
// them, so a generated rule reads like a hand-written one.
type sigmaRule struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id"`
	Status         string         `yaml:"status"`
	Description    string         `yaml:"description"`
	Author         string         `yaml:"author"`
	Date           string         `yaml:"date"`
	Tags           []string       `yaml:"tags,omitempty"`
	LogSource      sigmaLogSource `yaml:"logsource"`
	Detection      yaml.MapSlice  `yaml:"detection"`
	FalsePositives []string       `yaml:"falsepositives"`
	Level          string         `yaml:"level"`
	Fields         []string       `yaml:"fields,omitempty"`
}

type sigmaLogSource struct {
	Category string `yaml:"category,omitempty"`
	Product  string `yaml:"product,omitempty"`
	Service  string `yaml:"service,omitempty"`
}

// buildRules generates one rule per detection opportunity the engagement
// actually produced. A rule is emitted only when the indicator it matches on
// exists: a rule with an empty selection matches everything, which is far
// worse than no rule at all.
func buildRules(input Input, indicators Indicators) []Rule {
	var rules []Rule

	if len(indicators.Hostnames) > 0 {
		rules = append(rules,
			hostnameRule(input, indicators, "dns", "DNS lookup", sigmaLogSource{Category: "dns_query"},
				"query", []string{"QueryName"},
				"DNS resolution of the phishing hostname used in this engagement. This is the "+
					"earliest point the activity is visible: it fires before any content is served, "+
					"and it fires even when the connection itself is TLS-encrypted end to end."),
			hostnameRule(input, indicators, "proxy", "Web proxy request", sigmaLogSource{Category: "proxy"},
				"c-uri-host", []string{"c-uri", "src_ip", "c-useragent"},
				"Web proxy request to the phishing hostname used in this engagement. Unlike the DNS "+
					"rule, this names the client that made the request, so it identifies which users "+
					"reached the lure."),
		)
	}

	if len(indicators.SenderAddresses) > 0 || len(indicators.Subjects) > 0 {
		rules = append(rules, mailRule(input, indicators))
	}

	return rules
}

// hostnameRule builds a rule matching a set of hostnames on one field of one
// logsource.
func hostnameRule(input Input, indicators Indicators, key, label string, logSource sigmaLogSource,
	field string, fields []string, description string) Rule {
	title := "Olta engagement: " + label + " for phishing hostname"
	if input.CampaignName != "" {
		title += " (" + input.CampaignName + ")"
	}

	detection := yaml.MapSlice{
		{Key: "selection", Value: yaml.MapSlice{
			{Key: field, Value: append([]string(nil), indicators.Hostnames...)},
		}},
		{Key: "condition", Value: "selection"},
	}

	rule := sigmaRule{
		Title:          truncateTitle(title),
		ID:             deterministicUUID(input.CampaignID, key),
		Status:         "experimental",
		Description:    description + " " + generatedNote(input),
		Author:         "Olta",
		Date:           indicators.FirstSeen.Format("2006/01/02"),
		Tags:           sigmaTags(indicators.Techniques),
		LogSource:      logSource,
		Detection:      detection,
		FalsePositives: falsePositives(),
		Level:          "medium",
		Fields:         fields,
	}
	return renderRule(rule, logSourceName(logSource), requirementsFor(logSource, field, fields))
}

// mailRule matches the campaign's own messages at the mail layer. Sender and
// subject are combined with AND when both are known, because either alone is
// broad: a subject line like "Payroll update" matches legitimate mail, and a
// sender address matches every message from that domain.
func mailRule(input Input, indicators Indicators) Rule {
	title := "Olta engagement: phishing message delivered to a mailbox"
	if input.CampaignName != "" {
		title += " (" + input.CampaignName + ")"
	}

	selection := yaml.MapSlice{}
	conditions := make([]string, 0, 2)
	if len(indicators.SenderAddresses) > 0 {
		selection = append(selection, yaml.MapItem{
			Key:   "sender",
			Value: append([]string(nil), indicators.SenderAddresses...),
		})
		conditions = append(conditions, "sender")
	}
	if len(indicators.Subjects) > 0 {
		selection = append(selection, yaml.MapItem{
			Key:   "subject",
			Value: append([]string(nil), indicators.Subjects...),
		})
		conditions = append(conditions, "subject")
	}

	description := "Delivery of this engagement's phishing message. Matching on " +
		strings.Join(conditions, " and ") +
		" tells you whether the message reached mailboxes at all, which is the question mail " +
		"filtering is measured on -- a campaign that was fully filtered produces no matches here " +
		"and no lure traffic either, and the two together are what distinguish 'blocked' from " +
		"'nobody clicked'. " + generatedNote(input)

	rule := sigmaRule{
		Title:       truncateTitle(title),
		ID:          deterministicUUID(input.CampaignID, "mail"),
		Status:      "experimental",
		Description: description,
		Author:      "Olta",
		Date:        indicators.FirstSeen.Format("2006/01/02"),
		Tags:        sigmaTags(indicators.Techniques),
		LogSource:   sigmaLogSource{Category: "mail", Service: "delivery"},
		Detection: yaml.MapSlice{
			{Key: "selection", Value: selection},
			{Key: "condition", Value: "selection"},
		},
		FalsePositives: falsePositives(),
		Level:          "medium",
		Fields:         []string{"recipient", "sender", "subject"},
	}
	return renderRule(rule, "mail/delivery", []string{"Mail delivery logs with sender and subject fields"})
}

func renderRule(rule sigmaRule, logSourceName string, requires []string) Rule {
	encoded, err := yaml.Marshal(rule)
	if err != nil {
		// yaml.Marshal fails only on unsupported types; every field here is
		// a string, a string slice or a MapSlice of those. Returning the
		// error would force every caller to handle an impossible case, so
		// the rule body carries the failure instead of vanishing silently.
		return Rule{
			ID:        rule.ID,
			Title:     rule.Title,
			LogSource: logSourceName,
			Requires:  requires,
			Sigma:     "# rule could not be rendered: " + err.Error() + "\n",
		}
	}
	return Rule{
		ID:        rule.ID,
		Title:     rule.Title,
		LogSource: logSourceName,
		Requires:  requires,
		Sigma:     string(encoded),
	}
}

func logSourceName(logSource sigmaLogSource) string {
	parts := make([]string, 0, 3)
	for _, part := range []string{logSource.Product, logSource.Category, logSource.Service} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "/")
}

func requirementsFor(logSource sigmaLogSource, field string, fields []string) []string {
	requirement := "A " + logSourceName(logSource) + " logsource carrying the " + field + " field"
	if len(fields) > 0 {
		requirement += " (plus " + strings.Join(fields, ", ") + " to be actionable)"
	}
	return []string{requirement}
}

// sigmaTags renders ATT&CK techniques in Sigma's own tag form: lowercase,
// dots preserved, prefixed with "attack.".
func sigmaTags(techniques []telemetry.Technique) []string {
	if len(techniques) == 0 {
		return nil
	}
	tags := make([]string, 0, len(techniques))
	for _, technique := range techniques {
		tags = append(tags, "attack."+strings.ToLower(string(technique)))
	}
	return tags
}

// falsePositives states the one that always applies. A rule generated from a
// test's own infrastructure will match that test, and an analyst who does not
// know that will chase it as an incident.
func falsePositives() []string {
	return []string{
		"The authorized Olta engagement this rule was generated from",
		"Retesting or re-running the same campaign against the same infrastructure",
	}
}

func generatedNote(input Input) string {
	note := "Generated by Olta from an authorized engagement"
	if input.CampaignName != "" {
		note += " (" + input.CampaignName + ")"
	}
	return note + "; the indicators are the operator's own test infrastructure, not a real adversary's."
}

// truncateTitle keeps titles within the 256-character limit the Sigma
// specification sets, cutting the campaign name rather than emitting a rule a
// validator rejects.
func truncateTitle(title string) string {
	const maxTitle = 256
	if len(title) <= maxTitle {
		return title
	}
	return title[:maxTitle-1] + "…"
}

// deterministicUUID derives a stable rule ID from the campaign and rule key.
//
// Sigma requires a UUID, and rule IDs are how a defender's rule management
// tracks a rule across updates -- so regenerating a campaign's pack has to
// produce the same IDs rather than a fresh set that looks like new rules.
// That rules out random generation. The value is a SHA-256 of the seed
// rendered in UUID form with the version and variant nibbles set, so it is a
// well-formed UUID that is a function of its input.
func deterministicUUID(campaignID int64, key string) string {
	seed := "olta:detection:" + key + ":" + itoa(campaignID)
	digest := sha256Sum(seed)

	// Version 4 and the RFC 4122 variant, so validators that check the
	// nibbles accept it.
	digest[6] = (digest[6] & 0x0f) | 0x40
	digest[8] = (digest[8] & 0x3f) | 0x80

	hexed := hexEncode(digest[:16])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
}

// SigmaBundle renders every rule in the pack as one multi-document YAML
// stream, which is the form Sigma tooling ingests a rule set in.
func (p Pack) SigmaBundle() string {
	var builder strings.Builder
	builder.WriteString("# Olta detection pack for campaign ")
	builder.WriteString(itoa(p.CampaignID))
	builder.WriteString("\n# Generated ")
	builder.WriteString(p.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	builder.WriteString("\n#\n")
	for _, line := range wrapComment(p.Scope, 76) {
		builder.WriteString("# ")
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	for _, rule := range p.Rules {
		builder.WriteString("---\n")
		builder.WriteString(rule.Sigma)
	}
	return builder.String()
}

// wrapComment breaks the scope caption into comment-width lines so the
// bundle's header stays readable in an editor rather than running off the
// side as one very long line.
func wrapComment(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	lines := make([]string, 0, len(words)/8+1)
	current := words[0]
	for _, word := range words[1:] {
		if len(current)+1+len(word) > width {
			lines = append(lines, current)
			current = word
			continue
		}
		current += " " + word
	}
	return append(lines, current)
}

func sha256Sum(value string) [32]byte { return sha256.Sum256([]byte(value)) }

func hexEncode(value []byte) string { return hex.EncodeToString(value) }

func itoa(value int64) string { return strconv.FormatInt(value, 10) }
