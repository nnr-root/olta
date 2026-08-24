// Package telemetry defines the ATT&CK-tagged event stream shared by the
// Olta proxy, campaign, and feed services.
//
// An Event records that something happened during an engagement: which
// kill-chain stage, what the outcome was, which ATT&CK technique it
// emulates, and who the actor was. An Event never carries captured
// credentials, cookies, or tokens. Captured material stays in the campaign
// database behind pkg/campaign/secrets. This separation is what makes the
// stream safe to forward to a defender's SOC, and it is enforced by
// TestEventCarriesNoLoot.
package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Stage identifies a point in the engagement kill chain.
type Stage string

const (
	StageDelivery   Stage = "delivery"
	StageOpen       Stage = "open"
	StageLure       Stage = "lure"
	StageCloak      Stage = "cloak"
	StageVerify     Stage = "verify"
	StageCredential Stage = "credential"
	StageCapture    Stage = "capture"
	StageReplay     Stage = "replay"
	StageReport     Stage = "report"
)

// Outcome describes how a stage resolved.
type Outcome string

const (
	OutcomeAllowed    Outcome = "allowed"
	OutcomeBlocked    Outcome = "blocked"
	OutcomeRedirected Outcome = "redirected"
	OutcomeCaptured   Outcome = "captured"
	OutcomeFailed     Outcome = "failed"
)

// Technique is a MITRE ATT&CK technique identifier.
type Technique string

const (
	TechniqueSpearphishingLink     Technique = "T1566.002"
	TechniqueProxy                 Technique = "T1090"
	TechniqueSandboxEvasion        Technique = "T1497"
	TechniqueWebPortalCapture      Technique = "T1056.003"
	TechniqueStealWebSessionCookie Technique = "T1539"
	TechniqueWebSessionCookie      Technique = "T1550.004"
)

// Actor describes the request source. Every field is non-sensitive by
// construction: these are network and client attributes, never credentials.
type Actor struct {
	IP            string `json:"ip,omitempty"`
	ASN           string `json:"asn,omitempty"`
	Organization  string `json:"organization,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	Country       string `json:"country,omitempty"`
	ClientProfile string `json:"client_profile,omitempty"`
}

// Event is one tagged observation. CampaignID and RID are optional: cloak
// and verify events fire before lure validation establishes a recipient
// identity, so they carry neither.
type Event struct {
	ID         string         `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	Stage      Stage          `json:"stage"`
	Outcome    Outcome        `json:"outcome"`
	Techniques []Technique    `json:"techniques,omitempty"`
	CampaignID int64          `json:"campaign_id,omitempty"`
	RID        string         `json:"rid,omitempty"`
	Actor      Actor          `json:"actor"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// New builds an event with a fresh identity and the current UTC time.
func New(stage Stage, outcome Outcome, techniques ...Technique) Event {
	return Event{
		ID:         newID(),
		Timestamp:  time.Now().UTC(),
		Stage:      stage,
		Outcome:    outcome,
		Techniques: append([]Technique(nil), techniques...),
	}
}

// WithCampaign attaches recipient correlation.
func (e Event) WithCampaign(campaignID int64, rid string) Event {
	e.CampaignID = campaignID
	e.RID = rid
	return e
}

// WithActor attaches request-source attributes.
func (e Event) WithActor(actor Actor) Event {
	e.Actor = actor
	return e
}

// WithDetail attaches one stage-specific scalar attribute.
//
// Only scalars are accepted. Composite values — maps, slices, structs,
// pointers — are replaced with a type marker, because no key-name check can
// make them safe:
//
//   - A type implementing json.Marshaler can collapse a secret into an
//     unkeyed JSON scalar, leaving nothing for a key-based rule to match.
//     A struct{User, Pass string} whose MarshalJSON emits "user:secret"
//     under the innocuous key "identity" defeats key matching entirely.
//   - A map with non-string keys marshals to keys like "1", which match no
//     rule at all.
//
// Both were demonstrated against an earlier traversal-based implementation.
// Rejecting composites removes the traversal, and with it the whole class.
// Callers destructure instead, which forces a decision about every field
// that reaches telemetry — exactly the decision this package exists to make
// deliberate.
//
// Detail is a map, so a plain value-receiver copy would share it with every
// event derived from the same base. Two goroutines extending one populated
// base event would then write the same map concurrently, which is a fatal
// runtime error rather than a recoverable one. The map is therefore copied
// on every call, making the builder genuinely value-semantic.
func (e Event) WithDetail(key string, value any) Event {
	detail := make(map[string]any, len(e.Detail)+1)
	for k, v := range e.Detail {
		detail[k] = v
	}
	detail[key] = vetDetail(key, value)
	e.Detail = detail
	return e
}

// vetDetail redacts by key, then admits only scalars.
func vetDetail(key string, value any) any {
	if isLootKey(key) {
		return redacted
	}
	switch value.(type) {
	case nil, string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return value
	default:
		return fmt.Sprintf("[unsupported %T]", value)
	}
}

// lootTokens match a whole underscore-delimited segment of a key, so
// "auth_token" and "x_auth" redact while "author" and "authorized_by" do
// not. Bare substring matching over-redacted exactly that way, silently
// destroying legitimate telemetry.
//
// "signature" is deliberately absent from this set, for the same reason
// "session" is: as a segment it would also catch legitimate compounds like
// "signature_algo" and "signature_scheme". A bare "signature" key still
// redacts, via lootExactKeys below.
var lootTokens = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pass": true,
	"secret": true, "token": true, "cookie": true, "cookies": true,
	"credential": true, "credentials": true, "auth": true,
	"authorization": true, "bearer": true, "otp": true, "mfa": true,
	"pin": true, "passcode": true,
}

// lootExactKeys match only the whole normalized key, never a segment of a
// compound key. Unlike "auth" or "token", "signature" shows up in
// legitimate compound telemetry keys, so it belongs here rather than in
// lootTokens.
var lootExactKeys = map[string]bool{
	"signature": true,
}

// lootPhrases match anywhere in the key. These are compounds unambiguous
// enough that a false positive is not a realistic worry.
var lootPhrases = []string{
	"apikey", "api_key", "privatekey", "private_key",
	"access_token", "refresh_token", "session_id", "set_cookie",
}

const redacted = "[redacted]"

// isLootKey reports whether a detail key names something that must never be
// recorded. It is a backstop, not the primary defense: the primary defense
// is that WithDetail admits only scalars, so there is nothing to traverse
// and nowhere for a secret to hide.
func isLootKey(key string) bool {
	normalized := normalizeKey(key)
	if lootExactKeys[normalized] {
		return true
	}
	for _, phrase := range lootPhrases {
		if strings.Contains(normalized, phrase) {
			return true
		}
	}
	for _, token := range strings.Split(normalized, "_") {
		if lootTokens[token] {
			return true
		}
	}
	return false
}

func normalizeKey(key string) string {
	lowered := make([]byte, 0, len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z':
			lowered = append(lowered, c+('a'-'A'))
		case c == '-' || c == ' ':
			lowered = append(lowered, '_')
		default:
			lowered = append(lowered, c)
		}
	}
	return string(lowered)
}

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("telemetry: secure random id generation failed: %v", err))
	}
	return hex.EncodeToString(buffer)
}
