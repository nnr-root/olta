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

// WithDetail attaches one stage-specific attribute.
//
// Callers must never pass captured credentials, cookies, or tokens. Values
// are redacted on the way in rather than trusted: see redactValue.
func (e Event) WithDetail(key string, value any) Event {
	if e.Detail == nil {
		e.Detail = make(map[string]any, 4)
	}
	e.Detail[key] = redactValue(key, value)
	return e
}

// lootKeys are detail keys whose values are replaced with a marker. The
// event still records that the thing existed, which is all the stream needs.
var lootKeys = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"tokens": true, "cookie": true, "cookies": true, "credential": true,
	"credentials": true, "api_key": true, "apikey": true, "authorization": true,
	"session": true, "body_tokens": true, "http_tokens": true,
}

const redacted = "[redacted]"

// redactValue strips loot by key name, recursing into maps and slices so a
// nested secret cannot ride along inside a composite value.
func redactValue(key string, value any) any {
	if lootKeys[normalizeKey(key)] {
		return redacted
	}
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = redactValue(k, v)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = redactValue(k, v)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			out[i] = redactValue(key, v)
		}
		return out
	default:
		return value
	}
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
