package telemetry

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

// TestEventCarriesNoLootAcrossValueShapes covers the bypasses a type-switch
// allowlist misses. Each case is a shape a proxy handler plausibly produces.
// These are regression tests for real leaks, not hypotheticals.
func TestEventCarriesNoLootAcrossValueShapes(t *testing.T) {
	const secret = "AQABAAAAAAD-SUPER-SECRET-VALUE"

	type credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	cases := []struct {
		name  string
		key   string
		value any
	}{
		// A named type over map[string][]string. A type switch never matches
		// a named type against its underlying type, so http.Header was the
		// original bypass.
		{"http.Header", "request_headers", http.Header{"Authorization": {secret}}},
		{"url.Values", "form", url.Values{"password": {secret}}},

		// Underlying map type that is not one of the switch's exact cases.
		{"map of string slice", "headers", map[string][]string{"cookie": {secret}}},

		// []map[string]any is not []any.
		{"slice of maps", "fields", []map[string]any{{"password": secret}}},

		// A struct never matched at all.
		{"struct", "identity", credentials{Username: "victim", Password: secret}},
		{"pointer to struct", "identity_ptr", &credentials{Password: secret}},

		// Key spellings that exact-equality matching missed.
		{"hyphenated key", "Set-Cookie", secret},
		{"suffixed key", "session_id", secret},
		{"prefixed key", "x_auth_token", secret},
		{"short spelling", "pwd", secret},
		{"bearer", "bearer", secret},
		{"otp", "otp_code", secret},

		// Loot nested under a wholly innocuous outer key.
		{"innocuous outer key", "payload", map[string]any{"nested": map[string]any{"token": secret}}},
		{"innocuous outer, struct inner", "context", credentials{Password: secret}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			event := New(StageCapture, OutcomeCaptured).WithDetail(testCase.key, testCase.value)
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("leaked %q into %s", secret, encoded)
			}
		})
	}
}

// TestWithDetailRejectsComposites pins the primary defense. Composites are
// not traversed and sanitized — they are refused outright, because no
// key-based rule can see inside them. Both cases below defeated an earlier
// traversal-based implementation.
func TestWithDetailRejectsComposites(t *testing.T) {
	const secret = "STRUCT-SECRET-XYZ"

	// A custom marshaller collapses a keyed secret into an unkeyed scalar,
	// leaving nothing for a key rule to match.
	marshaller := sneaky{User: "victim", Pass: secret}

	cases := []struct {
		name  string
		key   string
		value any
	}{
		{"json.Marshaler", "identity", marshaller},
		{"pointer to marshaler", "identity_ptr", &marshaller},
		{"non-string map keys", "codes", map[int]string{1: secret}},
		{"header", "request_headers", http.Header{"Authorization": {secret}}},
		{"form", "form", url.Values{"password": {secret}}},
		{"slice of maps", "fields", []map[string]any{{"password": secret}}},
		{"nested map", "payload", map[string]any{"token": secret}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			event := New(StageCapture, OutcomeCaptured).WithDetail(testCase.key, testCase.value)

			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("leaked %q into %s", secret, encoded)
			}

			stored, ok := event.Detail[testCase.key].(string)
			if !ok || !strings.HasPrefix(stored, "[") {
				t.Fatalf("composite was not replaced with a marker: %#v", event.Detail[testCase.key])
			}
		})
	}
}

// sneaky collapses its fields into a bare JSON string with no key, which is
// how a json.Marshaler defeats key-name redaction.
type sneaky struct {
	User string
	Pass string
}

func (s sneaky) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.User + ":" + s.Pass)
}

// TestWithDetailDoesNotOverRedact guards the other direction. Substring
// matching redacted "author", "session_count", and "private_ip", silently
// destroying legitimate telemetry. Token matching must not.
func TestWithDetailDoesNotOverRedact(t *testing.T) {
	cases := map[string]any{
		"author":         "jane-doe",
		"authorized_by":  "soc-team",
		"session_count":  42,
		"session_length": 900,
		"private_ip":     "10.0.0.4",
		"tokenizer":      "wordpiece",
		"signature_algo": "ES256",
	}

	for key, value := range cases {
		t.Run(key, func(t *testing.T) {
			event := New(StageVerify, OutcomeAllowed).WithDetail(key, value)
			if event.Detail[key] == redacted {
				t.Fatalf("over-redacted %q, which is not loot", key)
			}
		})
	}
}

// TestWithDetailRedactsLootKeys pins the backstop across spellings.
func TestWithDetailRedactsLootKeys(t *testing.T) {
	for _, key := range []string{
		"password", "Passwd", "pwd", "secret", "api_key", "apikey",
		"Authorization", "x_auth_token", "bearer", "otp_code", "mfa",
		"Set-Cookie", "session_id", "access_token", "refresh_token",
		"private_key", "signature", "pin",
	} {
		t.Run(key, func(t *testing.T) {
			event := New(StageCredential, OutcomeCaptured).WithDetail(key, "SECRET-VALUE")
			if event.Detail[key] != redacted {
				t.Fatalf("%q was not redacted: %v", key, event.Detail[key])
			}
		})
	}
}

// TestWithDetailDoesNotShareDetailMap pins the copy-on-write contract.
// Without it, every event derived from a populated base shares one map, and
// two goroutines extending that base write it concurrently — a fatal runtime
// error that kills the process, not a recoverable request failure.
func TestWithDetailDoesNotShareDetailMap(t *testing.T) {
	base := New(StageLure, OutcomeAllowed).WithDetail("stage", "lure")

	first := base.WithDetail("branch", "one")
	second := base.WithDetail("branch", "two")

	if first.Detail["branch"] != "one" || second.Detail["branch"] != "two" {
		t.Fatalf("branches share a map: first=%v second=%v", first.Detail, second.Detail)
	}
	if _, present := base.Detail["branch"]; present {
		t.Fatalf("base was mutated by a derived event: %v", base.Detail)
	}
}

// Run with -race. Before copy-on-write this failed as a data race, and in
// production as "fatal error: concurrent map writes".
func TestWithDetailIsRaceSafeFromSharedBase(t *testing.T) {
	base := New(StageCapture, OutcomeCaptured).WithDetail("stage", "capture")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = base.WithDetail("worker", n)
		}(i)
	}
	wg.Wait()
}
