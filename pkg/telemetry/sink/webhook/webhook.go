// Package webhook posts sanitized telemetry events to a configured Discord,
// Slack, or generic JSON webhook.
//
// It is deliberately generic over telemetry.Event rather than any one
// stage's result type. That is what lets a single -webhook-url receive
// every stage in the engagement kill chain — delivery through report — and
// not just session validation, which is all the package it replaced could
// do.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Provider identifies the webhook payload dialect.
type Provider string

const (
	ProviderGeneric Provider = "generic"
	ProviderSlack   Provider = "slack"
	ProviderDiscord Provider = "discord"
)

// Sink posts telemetry events to a configured webhook. It satisfies
// telemetry.Sink.
type Sink struct {
	endpoint *url.URL
	provider Provider
	client   *http.Client
}

// New validates a webhook URL and auto-detects Slack and Discord. Other
// HTTP(S) endpoints receive the generic JSON schema.
func New(rawURL string, client *http.Client) (*Sink, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || !endpoint.IsAbs() || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Hostname() == "" {
		return nil, fmt.Errorf("webhook URL must be an absolute HTTP(S) URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Sink{
		endpoint: endpoint,
		provider: DetectProvider(endpoint),
		client:   client,
	}, nil
}

// DetectProvider determines the payload format from the webhook hostname.
func DetectProvider(endpoint *url.URL) Provider {
	if endpoint == nil {
		return ProviderGeneric
	}
	host := strings.ToLower(endpoint.Hostname())
	path := strings.ToLower(endpoint.Path)
	switch {
	case (host == "hooks.slack.com" || strings.HasSuffix(host, ".hooks.slack.com")) && strings.HasPrefix(path, "/services/"):
		return ProviderSlack
	case (host == "discord.com" || host == "discordapp.com" || strings.HasSuffix(host, ".discord.com")) && strings.Contains(path, "/api/webhooks/"):
		return ProviderDiscord
	default:
		return ProviderGeneric
	}
}

// Provider returns the detected webhook payload dialect.
func (sink *Sink) Provider() Provider {
	if sink == nil {
		return ProviderGeneric
	}
	return sink.provider
}

// Emit posts one event to the configured webhook.
func (s *Sink) Emit(ctx context.Context, event telemetry.Event) error {
	return s.post(ctx, s.payload(event))
}

// Close is a no-op: the HTTP client is shared and owned by the caller.
func (s *Sink) Close() error { return nil }

// payload renders the provider-specific JSON body for event. FormatPayload
// can only fail on an unsupported provider (DetectProvider never returns
// one) or a json.Marshal failure (unreachable: telemetry.Event's Detail
// admits only redacted scalars), so a failure here falls back to a minimal
// payload rather than silently dropping the event.
func (s *Sink) payload(event telemetry.Event) []byte {
	data, err := FormatPayload(s.provider, event)
	if err != nil {
		data, _ = json.Marshal(struct {
			Event string `json:"event"`
			Stage string `json:"stage"`
		}{Event: "olta_telemetry", Stage: string(event.Stage)})
	}
	return data
}

func (s *Sink) post(ctx context.Context, payload []byte) error {
	if s == nil || s.endpoint == nil {
		return fmt.Errorf("webhook sink is not configured")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Olta-Telemetry/1.0")
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("dispatch webhook: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}

// FormatPayload produces the provider-specific JSON payload for event. The
// event's Detail carries only what telemetry.WithDetail already vetted, so
// no loot can reach the payload here.
func FormatPayload(provider Provider, event telemetry.Event) ([]byte, error) {
	switch provider {
	case ProviderSlack:
		return json.Marshal(slackPayload(event))
	case ProviderDiscord:
		return json.Marshal(discordPayload(event))
	case ProviderGeneric:
		return json.Marshal(struct {
			Event string          `json:"event"`
			Data  telemetry.Event `json:"data"`
		}{Event: "olta_telemetry", Data: event})
	default:
		return nil, fmt.Errorf("unsupported webhook provider %q", provider)
	}
}

func slackPayload(event telemetry.Event) interface{} {
	fields := []map[string]interface{}{
		{"type": "mrkdwn", "text": "*Stage*\n" + escapeSlack(displayValue(string(event.Stage)))},
		{"type": "mrkdwn", "text": "*Outcome*\n" + escapeSlack(displayValue(string(event.Outcome)))},
		{"type": "mrkdwn", "text": "*Techniques*\n" + escapeSlack(displayValue(joinTechniques(event.Techniques)))},
	}
	if event.RID != "" {
		fields = append(fields, map[string]interface{}{"type": "mrkdwn", "text": "*RID*\n" + escapeSlack(event.RID)})
	}
	if event.CampaignID != 0 {
		fields = append(fields, map[string]interface{}{"type": "mrkdwn", "text": "*Campaign*\n" + strconv.FormatInt(event.CampaignID, 10)})
	}
	if event.Actor.Organization != "" {
		fields = append(fields, map[string]interface{}{"type": "mrkdwn", "text": "*Organization*\n" + escapeSlack(event.Actor.Organization)})
	}
	return map[string]interface{}{
		"text": "Olta telemetry: " + string(event.Stage) + " (" + string(event.Outcome) + ")",
		"blocks": []interface{}{
			map[string]interface{}{"type": "header", "text": map[string]string{"type": "plain_text", "text": "Olta Telemetry"}},
			map[string]interface{}{"type": "section", "fields": fields},
			map[string]interface{}{"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": "Event `" + event.ID + "` • " + event.Timestamp.UTC().Format(time.RFC3339)}}},
		},
	}
}

func discordPayload(event telemetry.Event) interface{} {
	fields := []map[string]interface{}{
		{"name": "Stage", "value": displayValue(string(event.Stage)), "inline": true},
		{"name": "Outcome", "value": displayValue(string(event.Outcome)), "inline": true},
		{"name": "Techniques", "value": displayValue(joinTechniques(event.Techniques)), "inline": true},
	}
	if event.RID != "" {
		fields = append(fields, map[string]interface{}{"name": "RID", "value": event.RID, "inline": true})
	}
	if event.CampaignID != 0 {
		fields = append(fields, map[string]interface{}{"name": "Campaign", "value": strconv.FormatInt(event.CampaignID, 10), "inline": true})
	}
	if event.Actor.Organization != "" {
		fields = append(fields, map[string]interface{}{"name": "Organization", "value": event.Actor.Organization, "inline": true})
	}
	return map[string]interface{}{
		"username": "Olta Telemetry",
		"embeds": []interface{}{map[string]interface{}{
			"title":     "Olta Telemetry: " + string(event.Stage),
			"color":     outcomeColor(event.Outcome),
			"timestamp": event.Timestamp.UTC().Format(time.RFC3339),
			"fields":    fields,
			"footer":    map[string]string{"text": "Event " + event.ID},
		}},
	}
}

// outcomeColor mirrors purple-team framing, not a defender's: allowed and
// captured are adversary successes (green), blocked is defensive friction
// (red), failed is amber, and anything else is neutral gray.
func outcomeColor(outcome telemetry.Outcome) int {
	switch outcome {
	case telemetry.OutcomeAllowed, telemetry.OutcomeCaptured:
		return 0x2ECC71
	case telemetry.OutcomeBlocked:
		return 0xE74C3C
	case telemetry.OutcomeFailed:
		return 0xF39C12
	default:
		return 0x95A5A6
	}
}

func joinTechniques(techniques []telemetry.Technique) string {
	if len(techniques) == 0 {
		return ""
	}
	parts := make([]string, len(techniques))
	for i, technique := range techniques {
		parts[i] = string(technique)
	}
	return strings.Join(parts, ", ")
}

func displayValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func escapeSlack(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	return strings.ReplaceAll(value, ">", "&gt;")
}
