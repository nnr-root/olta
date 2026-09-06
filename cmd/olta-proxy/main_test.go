package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// recordingSink is a minimal telemetry.Sink that keeps every event it
// receives, so assertions can be made against exactly what buildStartupEvent
// produced and what actually reached the bus -- not against internals.
type recordingSink struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (s *recordingSink) Emit(_ context.Context, event telemetry.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *recordingSink) Close() error { return nil }

func (s *recordingSink) all() []telemetry.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]telemetry.Event(nil), s.events...)
}

// representativeConfig is a startupTelemetryConfig populated the way a real
// operator invocation might be: cloaker and js-inspect on, a non-default
// rate limit, and -- critically -- every field that can carry a secret set
// to a realistic, distinctly-shaped secret value.
func representativeConfig() startupTelemetryConfig {
	return startupTelemetryConfig{
		Version:                  "1.0.0-Alpha",
		DeveloperMode:            false,
		ProxyHeaderTrustEnabled:  true,
		ClientProfile:            "Chrome",
		RateLimitMax:             30,
		RateLimitWindow:          time.Minute,
		CloakerEnabled:           true,
		CloakerAction:            "block",
		CloakerBlockStatus:       404,
		IPSyncEnabled:            true,
		IPSyncInterval:           12 * time.Hour,
		JSInspectEnabled:         true,
		JSInspectEndpoint:        "/_assets/js/v.js",
		SessionValidatorEnabled:  true,
		FeedEnabled:              true,
		SecretsEncryptionEnabled: true,
		SIEMConfigured:           true,
		SIEMSchema:               "ecs",
		Turnstile:                "0x4AAAAAAA_publickeyXYZ:0x4AAAAAAA_SECRETprivatekeyDONOTLEAK",
		WebhookURL:               "https://hooks.slack.com/services/T000/B000/SUPERSECRETBEARERTOKEN123",
		CampaignDBDriver:         "mysql",
		CampaignDBTLSCA:          "/opt/olta/certs/mysql-ca.pem",
	}
}

func TestBuildStartupEvent_Shape(t *testing.T) {
	event := buildStartupEvent(representativeConfig())

	if event.Stage != telemetry.StageInitialization {
		t.Errorf("Stage = %q, want %q", event.Stage, telemetry.StageInitialization)
	}
	if event.Outcome != telemetry.OutcomeAllowed {
		t.Errorf("Outcome = %q, want %q", event.Outcome, telemetry.OutcomeAllowed)
	}
	if len(event.Techniques) != 0 {
		t.Errorf("Techniques = %v, want none: process configuration is not adversary behavior", event.Techniques)
	}
	if event.CampaignID != 0 {
		t.Errorf("CampaignID = %d, want 0 (unattributed, like cloak/verify events)", event.CampaignID)
	}
	if event.RID != "" {
		t.Errorf("RID = %q, want empty", event.RID)
	}

	want := map[string]any{
		"version":                       "1.0.0-Alpha",
		"developer_mode":                false,
		"proxy_header_trust_enabled":    true,
		"client_profile":                "Chrome",
		"rate_limit_max":                int64(30),
		"rate_limit_window_seconds":     int64(60),
		"cloaker_enabled":               true,
		"cloaker_action":                "block",
		"cloaker_block_status":          int64(404),
		"ip_sync_enabled":               true,
		"ip_sync_interval_seconds":      int64(12 * time.Hour / time.Second),
		"js_inspect_enabled":            true,
		"js_inspect_endpoint":           "/_assets/js/v.js",
		"session_validator_enabled":     true,
		"feed_enabled":                  true,
		"secrets_encryption_enabled":    true,
		"siem_configured":               true,
		"siem_schema":                   "ecs",
		"turnstile_enabled":             true,
		"webhook_configured":            true,
		"campaign_db_driver":            "mysql",
		"campaign_db_tls_ca_configured": true,
	}
	if len(event.Detail) != len(want) {
		t.Fatalf("Detail has %d keys, want %d: %+v", len(event.Detail), len(want), event.Detail)
	}
	for key, wantValue := range want {
		got, ok := event.Detail[key]
		if !ok {
			t.Errorf("Detail[%q] missing", key)
			continue
		}
		if got != wantValue {
			t.Errorf("Detail[%q] = %v (%T), want %v (%T)", key, got, got, wantValue, wantValue)
		}
	}
}

// TestBuildStartupEvent_ReportsEncryptionDisabled pins the honest half of
// the encryption posture. A missing OLTA_MASTER_KEY is exactly the case an
// engagement report needs to be able to state, so the detail has to be
// present and false -- not absent, which would be indistinguishable from an
// older proxy that never reported it at all.
func TestBuildStartupEvent_ReportsEncryptionDisabled(t *testing.T) {
	cfg := representativeConfig()
	cfg.SecretsEncryptionEnabled = false
	event := buildStartupEvent(cfg)
	got, ok := event.Detail["secrets_encryption_enabled"]
	if !ok {
		t.Fatal(`Detail["secrets_encryption_enabled"] missing; an unset master key must be reported, not omitted`)
	}
	if got != false {
		t.Errorf(`Detail["secrets_encryption_enabled"] = %v, want false`, got)
	}
}

// TestSIEMSchemaForTelemetry pins that a schema is never reported for a sink
// that does not exist: a report showing "ocsf" for a proxy with no SIEM
// destination would describe a delivery path that was never configured.
func TestSIEMSchemaForTelemetry(t *testing.T) {
	if got := siemSchemaForTelemetry(false, "ocsf"); got != "" {
		t.Errorf("siemSchemaForTelemetry(false, ...) = %q, want empty", got)
	}
	if got := siemSchemaForTelemetry(true, "  OCSF "); got != "ocsf" {
		t.Errorf("siemSchemaForTelemetry(true, ...) = %q, want the normalized schema", got)
	}
}

// TestBuildStartupEvent_DefaultDriverIsSqlite3 covers the empty -g-driver
// case, which cmd/olta-proxy's own help text documents as meaning the
// embedded sqlite3 default.
func TestBuildStartupEvent_DefaultDriverIsSqlite3(t *testing.T) {
	cfg := representativeConfig()
	cfg.CampaignDBDriver = ""
	event := buildStartupEvent(cfg)
	if got := event.Detail["campaign_db_driver"]; got != "sqlite3" {
		t.Errorf(`Detail["campaign_db_driver"] = %v, want "sqlite3" for an empty -g-driver`, got)
	}
}

// TestBuildStartupEvent_NoSecretValue is the hazard test: turnstile,
// webhook-url, and the campaign DB DSN all carry secrets that telemetry's
// key-based redaction backstop does not catch for these particular flag
// names, and this event fans out to every sink including the webhook sink
// itself. buildStartupEvent must reduce every one of them to a presence
// boolean before the event is ever built, never passing the raw secret
// through -- checked here against the actual marshalled JSON, which is
// exactly the byte stream every sink (including the webhook sink) receives.
func TestBuildStartupEvent_NoSecretValue(t *testing.T) {
	cfg := representativeConfig()
	event := buildStartupEvent(cfg)

	marshalled, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	body := string(marshalled)

	secrets := []string{
		cfg.Turnstile,
		"SECRETprivatekeyDONOTLEAK",
		cfg.WebhookURL,
		"SUPERSECRETBEARERTOKEN123",
		"hooks.slack.com",
	}
	for _, secret := range secrets {
		if strings.Contains(body, secret) {
			t.Errorf("marshalled event contains secret value %q\nevent JSON: %s", secret, body)
		}
	}
}

// TestStartupEvent_EmittedOnce drives buildStartupEvent through a real
// telemetry.Bus and asserts exactly one event reaches the sink, with the
// stage the resilience report keys off of.
func TestStartupEvent_EmittedOnce(t *testing.T) {
	sink := &recordingSink{}
	bus := telemetry.NewBus(8, sink)

	bus.Emit(buildStartupEvent(representativeConfig()))

	if err := bus.Close(); err != nil {
		t.Fatalf("bus.Close() error: %v", err)
	}
	if dropped := bus.Dropped(); dropped != 0 {
		t.Fatalf("bus dropped %d events, want 0", dropped)
	}

	events := sink.all()
	if len(events) != 1 {
		t.Fatalf("sink received %d events, want exactly 1: %+v", len(events), events)
	}
	if events[0].Stage != telemetry.StageInitialization {
		t.Errorf("Stage = %q, want %q", events[0].Stage, telemetry.StageInitialization)
	}
}

func TestParseRecheckSchedule(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []time.Duration
	}{
		{"default", "5m,30m,2h,8h,24h", []time.Duration{5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 8 * time.Hour, 24 * time.Hour}},
		{"single", "1h", []time.Duration{time.Hour}},
		{"spaces", " 5m , 1h ", []time.Duration{5 * time.Minute, time.Hour}},
		{"trailing comma", "5m,", []time.Duration{5 * time.Minute}},
		{"empty disables rechecks", "", nil},
		{"whitespace disables rechecks", "   ", nil},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := parseRecheckSchedule(testCase.value)
			if err != nil {
				t.Fatalf("parseRecheckSchedule(%q) returned error: %v", testCase.value, err)
			}
			if len(got) != len(testCase.want) {
				t.Fatalf("parseRecheckSchedule(%q) = %v, want %v", testCase.value, got, testCase.want)
			}
			for i := range got {
				if got[i] != testCase.want[i] {
					t.Errorf("delay %d = %v, want %v", i, got[i], testCase.want[i])
				}
			}
		})
	}
}

// TestParseRecheckScheduleRejectsBadValues keeps a typo from silently
// disabling the measurement instead of failing at startup.
func TestParseRecheckScheduleRejectsBadValues(t *testing.T) {
	for _, value := range []string{"5", "5minutes", "0s", "-1h", "5m,nonsense"} {
		if _, err := parseRecheckSchedule(value); err == nil {
			t.Errorf("parseRecheckSchedule(%q) accepted an invalid schedule", value)
		}
	}
}
