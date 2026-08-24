package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewPopulatesIdentityAndTimestamp(t *testing.T) {
	event := New(StageCapture, OutcomeCaptured, TechniqueStealWebSessionCookie)
	if len(event.ID) != 32 {
		t.Fatalf("ID = %q, want 32 hex characters", event.ID)
	}
	if event.Timestamp.IsZero() {
		t.Fatal("Timestamp is zero")
	}
	if event.Stage != StageCapture || event.Outcome != OutcomeCaptured {
		t.Fatalf("stage/outcome = %q/%q", event.Stage, event.Outcome)
	}
	if len(event.Techniques) != 1 || event.Techniques[0] != TechniqueStealWebSessionCookie {
		t.Fatalf("Techniques = %v", event.Techniques)
	}
}

func TestNewGeneratesDistinctIDs(t *testing.T) {
	first := New(StageLure, OutcomeAllowed)
	second := New(StageLure, OutcomeAllowed)
	if first.ID == second.ID {
		t.Fatalf("duplicate ID %q", first.ID)
	}
}

func TestBuildersAreChainable(t *testing.T) {
	event := New(StageCloak, OutcomeBlocked, TechniqueProxy).
		WithCampaign(7, "abc123").
		WithActor(Actor{IP: "203.0.113.9", ASN: "AS8075", Organization: "Microsoft"}).
		WithDetail("rule", "network")

	if event.CampaignID != 7 || event.RID != "abc123" {
		t.Fatalf("campaign/rid = %d/%q", event.CampaignID, event.RID)
	}
	if event.Actor.ASN != "AS8075" {
		t.Fatalf("Actor.ASN = %q", event.Actor.ASN)
	}
	if event.Detail["rule"] != "network" {
		t.Fatalf("Detail = %v", event.Detail)
	}
}

// TestEventCarriesNoLoot is the load-bearing invariant of this package.
// An Event records the fact of a capture, never its contents. Do not delete
// or weaken this test: it is what allows telling a client that the telemetry
// stream is safe to forward to their SOC.
func TestEventCarriesNoLoot(t *testing.T) {
	const (
		password = "hunter2-SUPER-SECRET"
		cookie   = "ESTSAUTHPERSISTENT=AQABAAAAAAD-SECRET-TOKEN"
		apiKey   = "b4d1dea0000000000000000000000000"
	)

	// Every builder that accepts caller-supplied data is exercised here.
	// A new builder MUST be added to this list when it is introduced.
	events := []Event{
		New(StageCredential, OutcomeCaptured, TechniqueWebPortalCapture).
			WithCampaign(1, "rid-1").
			WithActor(Actor{IP: "203.0.113.5", UserAgent: "Mozilla/5.0"}).
			WithDetail("password", password),

		New(StageCapture, OutcomeCaptured, TechniqueStealWebSessionCookie).
			WithDetail("cookie", cookie).
			WithDetail("nested", map[string]string{"token": cookie}),

		New(StageReplay, OutcomeAllowed, TechniqueWebSessionCookie).
			WithDetail("Authorization", apiKey).
			WithDetail("api_key", apiKey),
	}

	for index, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("event %d: %v", index, err)
		}
		for _, secret := range []string{password, cookie, apiKey} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("event %d leaked %q into %s", index, secret, encoded)
			}
		}
	}
}
