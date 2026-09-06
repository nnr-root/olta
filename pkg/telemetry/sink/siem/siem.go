package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Transport identifies how the document is delivered, which differs between
// platforms only in envelope and authorization header -- the same shape the
// webhook sink's provider dialects take.
type Transport string

const (
	// TransportSplunkHEC posts to Splunk's HTTP Event Collector, which wraps
	// the document in an {"event": ...} envelope and authorizes with
	// "Authorization: Splunk <token>".
	TransportSplunkHEC Transport = "splunk_hec"
	// TransportElastic posts the document as-is to an Elasticsearch or
	// OpenSearch document endpoint, authorizing with whatever scheme the
	// token names (typically "ApiKey <id>:<key>").
	TransportElastic Transport = "elastic"
)

// Config describes one SIEM destination.
type Config struct {
	// Endpoint is the full URL to post to: a HEC collector
	// (https://splunk.example:8088/services/collector/event) or a document
	// endpoint (https://elastic.example:9200/olta-telemetry/_doc).
	Endpoint string
	// Transport selects the envelope and authorization scheme.
	Transport Transport
	// Schema selects the document format.
	Schema Schema
	// Token authorizes the request. It is required: both destinations
	// authenticate every write, and an unauthenticated sink would fail on
	// every event rather than at startup, which is a much worse way to find
	// out.
	Token string
	// AuthScheme overrides the authorization scheme for TransportElastic
	// (default "ApiKey"). Ignored for HEC, which is always "Splunk".
	AuthScheme string
	// SourceType is Splunk's sourcetype for the event. Ignored by Elastic.
	SourceType string
	// Client is optional; a 10-second-timeout client is used when nil,
	// matching the webhook sink.
	Client *http.Client
}

// Sink delivers telemetry events to a SIEM. It satisfies telemetry.Sink.
type Sink struct {
	config   Config
	endpoint *url.URL
	client   *http.Client
}

// New validates a destination and returns a sink for it.
func New(config Config) (*Sink, error) {
	endpoint, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || !endpoint.IsAbs() || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Hostname() == "" {
		return nil, fmt.Errorf("siem endpoint must be an absolute HTTP(S) URL")
	}
	switch config.Transport {
	case TransportSplunkHEC, TransportElastic:
	case "":
		return nil, fmt.Errorf("siem transport is required (%q or %q)", TransportSplunkHEC, TransportElastic)
	default:
		return nil, fmt.Errorf("unsupported siem transport %q", config.Transport)
	}
	switch config.Schema {
	case SchemaECS, SchemaOCSF:
	case "":
		return nil, fmt.Errorf("siem schema is required (%q or %q)", SchemaECS, SchemaOCSF)
	default:
		return nil, fmt.Errorf("unsupported siem schema %q", config.Schema)
	}
	if strings.TrimSpace(config.Token) == "" {
		return nil, fmt.Errorf("siem token is required")
	}
	if config.AuthScheme == "" {
		config.AuthScheme = "ApiKey"
	}
	if config.SourceType == "" {
		config.SourceType = "olta:telemetry"
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Sink{config: config, endpoint: endpoint, client: client}, nil
}

// Emit posts one event.
func (s *Sink) Emit(ctx context.Context, event telemetry.Event) error {
	if s == nil || s.endpoint == nil {
		return fmt.Errorf("siem sink is not configured")
	}
	payload, err := s.payload(event)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build siem request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Olta-Telemetry/1.0")
	request.Header.Set("Authorization", s.authorization())

	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("dispatch siem event: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("siem endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}

// Close is a no-op: the HTTP client is shared and owned by the caller.
func (s *Sink) Close() error { return nil }

// Schema returns the configured document format.
func (s *Sink) Schema() Schema {
	if s == nil {
		return ""
	}
	return s.config.Schema
}

// Transport returns the configured delivery dialect.
func (s *Sink) Transport() Transport {
	if s == nil {
		return ""
	}
	return s.config.Transport
}

func (s *Sink) authorization() string {
	if s.config.Transport == TransportSplunkHEC {
		return "Splunk " + s.config.Token
	}
	return s.config.AuthScheme + " " + s.config.Token
}

// payload renders the request body: the schema document, wrapped in the
// transport's envelope where it needs one.
func (s *Sink) payload(event telemetry.Event) ([]byte, error) {
	document, err := Document(s.config.Schema, event)
	if err != nil {
		return nil, err
	}
	if s.config.Transport != TransportSplunkHEC {
		return json.Marshal(document)
	}
	// HEC's own envelope. time is seconds with a fractional part, which is
	// what HEC expects; sending the document without this wrapper is
	// accepted by some versions and silently mis-timestamped by others.
	return json.Marshal(map[string]any{
		"time":       float64(event.Timestamp.UTC().UnixMilli()) / 1000,
		"sourcetype": s.config.SourceType,
		"source":     "olta",
		"event":      document,
	})
}
