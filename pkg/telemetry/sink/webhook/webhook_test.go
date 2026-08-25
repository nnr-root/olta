package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

func TestSinkPostsEvent(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	event := telemetry.New(telemetry.StageReplay, telemetry.OutcomeAllowed, telemetry.TechniqueWebSessionCookie).
		WithCampaign(3, "rid-9")
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	if body == "" {
		t.Fatal("webhook received an empty body")
	}
	if !json.Valid([]byte(body)) {
		t.Fatalf("webhook body is not valid JSON: %s", body)
	}
	if !strings.Contains(body, "T1550.004") {
		t.Fatalf("payload omitted the ATT&CK technique: %s", body)
	}
}

func TestSinkRejectsNonAbsoluteURL(t *testing.T) {
	if _, err := New("/relative/path", nil); err == nil {
		t.Fatal("New() accepted a relative URL")
	}
}

// TestFormatPayloadOmitsSecretsAcrossProviders restores the coverage that
// TestPayloadFormattingOmitsSessionSecrets provided before this package
// replaced pkg/proxy/validation's dispatcher (see
// git show 6676652:pkg/proxy/validation/validation_test.go). That deleted
// test looped over all three provider dialects; TestSinkCarriesNoLoot only
// exercises the generic path with one value, leaving slackPayload and
// discordPayload — the two builders that restructure Detail into a
// different JSON shape — untested. This test closes that gap.
func TestFormatPayloadOmitsSecretsAcrossProviders(t *testing.T) {
	const (
		cookieValue   = "ESTSAUTHPERSISTENT=AQABAAAAAAD-SECRET-SESSION-TOKEN"
		bearerValue   = "Bearer sk-live-secret-abc123xyz"
		passwordValue = "Sup3rSecretPassw0rd!23"
	)

	event := telemetry.New(telemetry.StageCapture, telemetry.OutcomeCaptured, telemetry.TechniqueWebSessionCookie).
		WithCampaign(42, "rid-victim-7").
		WithActor(telemetry.Actor{Organization: "SOC Lab", ASN: "AS64500"}).
		WithDetail("cookie", cookieValue).
		WithDetail("bearer_token", bearerValue).
		WithDetail("password", passwordValue)

	for _, provider := range []Provider{ProviderGeneric, ProviderSlack, ProviderDiscord} {
		t.Run(string(provider), func(t *testing.T) {
			payload, err := FormatPayload(provider, event)
			if err != nil {
				t.Fatalf("FormatPayload() error = %v", err)
			}
			if !json.Valid(payload) {
				t.Fatalf("payload is not valid JSON: %s", payload)
			}
			text := string(payload)

			// (b) the payload must actually carry the non-secret content
			// that belongs there — otherwise an empty or near-empty
			// payload would trivially pass the absence checks below.
			for _, want := range []string{
				string(telemetry.StageCapture),
				string(telemetry.OutcomeCaptured),
				string(telemetry.TechniqueWebSessionCookie),
			} {
				if !strings.Contains(text, want) {
					t.Errorf("payload missing expected content %q: %s", want, text)
				}
			}

			// (c) no secret value may appear, in any provider's shape.
			for _, secret := range []string{cookieValue, bearerValue, passwordValue} {
				if strings.Contains(text, secret) {
					t.Errorf("payload leaked secret %q: %s", secret, text)
				}
			}
		})
	}
}

func TestSinkCarriesNoLoot(t *testing.T) {
	const cookie = "ESTSAUTHPERSISTENT=AQABAAAAAAD-SECRET-TOKEN"

	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	event := telemetry.New(telemetry.StageCapture, telemetry.OutcomeCaptured).WithDetail("cookie", cookie)
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, cookie) {
		t.Fatalf("webhook leaked a captured cookie: %s", body)
	}
}
