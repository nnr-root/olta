package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

func sampleEvent() telemetry.Event {
	event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked, telemetry.TechniqueProxy).
		WithCampaign(7, "recipient-1").
		WithHost("login.example.com").
		WithActor(telemetry.Actor{
			IP:            "198.51.100.10",
			ASN:           "AS15169",
			Organization:  "Google LLC",
			UserAgent:     "Mozilla/5.0",
			Country:       "US",
			ClientProfile: "Chrome",
		}).
		WithDetail("rule", "network")
	event.ID = "0123456789abcdef0123456789abcdef"
	event.InstanceID = "fedcba9876543210fedcba9876543210"
	event.Timestamp = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	return event
}

func TestECSDocumentShape(t *testing.T) {
	document, err := Document(SchemaECS, sampleEvent())
	if err != nil {
		t.Fatal(err)
	}

	eventSection, _ := document["event"].(map[string]any)
	if eventSection["action"] != "cloak" {
		t.Errorf("event.action = %v, want cloak", eventSection["action"])
	}
	if eventSection["dataset"] != "olta.telemetry" {
		t.Errorf("event.dataset = %v", eventSection["dataset"])
	}
	// ECS's outcome describes the observed action's own result, not whether
	// the defender did well: a blocked proxy attempt is a failure.
	if eventSection["outcome"] != "failure" {
		t.Errorf("event.outcome = %v, want failure for a blocked event", eventSection["outcome"])
	}

	threat, _ := document["threat"].(map[string]any)
	technique, _ := threat["technique"].(map[string]any)
	ids, _ := technique["id"].([]string)
	if len(ids) != 1 || ids[0] != string(telemetry.TechniqueProxy) {
		t.Errorf("threat.technique.id = %v, want [%s]", ids, telemetry.TechniqueProxy)
	}

	source, _ := document["source"].(map[string]any)
	if source["ip"] != "198.51.100.10" {
		t.Errorf("source.ip = %v", source["ip"])
	}
	autonomousSystem, _ := source["as"].(map[string]any)
	if autonomousSystem["number"] != int64(15169) {
		t.Errorf("source.as.number = %v, want 15169 parsed from the AS-prefixed display form", autonomousSystem["number"])
	}

	urlSection, _ := document["url"].(map[string]any)
	if urlSection["domain"] != "login.example.com" {
		t.Errorf("url.domain = %v", urlSection["domain"])
	}
}

// TestECSKeepsOltaOutcomeVerbatim is the honesty check on the mapping. ECS's
// outcome vocabulary collapses Olta's five outcomes onto three, so the
// original has to survive somewhere or the translation loses information a
// purple-team reader needs -- "blocked" and "failed" are very different
// findings and both become "failure".
func TestECSKeepsOltaOutcomeVerbatim(t *testing.T) {
	for _, outcome := range []telemetry.Outcome{
		telemetry.OutcomeAllowed, telemetry.OutcomeBlocked, telemetry.OutcomeRedirected,
		telemetry.OutcomeCaptured, telemetry.OutcomeFailed,
	} {
		event := sampleEvent()
		event.Outcome = outcome
		document, err := Document(SchemaECS, event)
		if err != nil {
			t.Fatal(err)
		}
		olta, _ := document["olta"].(map[string]any)
		if olta["outcome"] != string(outcome) {
			t.Errorf("olta.outcome = %v, want %q preserved verbatim", olta["outcome"], outcome)
		}
	}
}

func TestOCSFDocumentShape(t *testing.T) {
	document, err := Document(SchemaOCSF, sampleEvent())
	if err != nil {
		t.Fatal(err)
	}

	if document["class_uid"] != 2004 {
		t.Errorf("class_uid = %v, want 2004 (Detection Finding)", document["class_uid"])
	}
	if document["status_id"] != 2 {
		t.Errorf("status_id = %v, want 2 (Failure) for a blocked event", document["status_id"])
	}
	// Severity is deliberately fixed: Olta cannot know how severe a stage is
	// for a given organization, and a made-up number would feed a
	// defender's alerting rules something with nothing behind it.
	if document["severity_id"] != 1 {
		t.Errorf("severity_id = %v, want 1 (Informational)", document["severity_id"])
	}
	if document["time"] != sampleEvent().Timestamp.UnixMilli() {
		t.Errorf("time = %v, want epoch milliseconds", document["time"])
	}

	observables, _ := document["observables"].([]map[string]any)
	if len(observables) != 2 {
		t.Fatalf("got %d observables, want 2 (ip and domain)", len(observables))
	}
}

// TestOCSFOmitsAbsentFields keeps the document from carrying empty strings
// where an analyst's query would then match "" as a real value.
func TestOCSFOmitsAbsentFields(t *testing.T) {
	document, err := Document(SchemaOCSF, telemetry.New(telemetry.StageReport, telemetry.OutcomeAllowed))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := document["src_endpoint"]; present {
		t.Error("src_endpoint present for an event with no actor or host")
	}
	unmapped, _ := document["unmapped"].(map[string]any)
	for _, key := range []string{"campaign_id", "recipient_id", "user_agent", "client_profile", "detail"} {
		if _, present := unmapped[key]; present {
			t.Errorf("unmapped.%s present for an event that carries none", key)
		}
	}
}

func TestDocumentRejectsUnknownSchema(t *testing.T) {
	if _, err := Document("stix", sampleEvent()); err == nil {
		t.Fatal("Document accepted an unsupported schema")
	}
}

// TestNoLootReachesTheDocument is the invariant test. These mappings only
// rename and nest what the event already carries, so an event whose detail
// was redacted by WithDetail must stay redacted through both schemas -- this
// asserts it against the marshalled bytes, which is what actually leaves the
// process.
func TestNoLootReachesTheDocument(t *testing.T) {
	event := telemetry.New(telemetry.StageCapture, telemetry.OutcomeCaptured).
		WithDetail("password", "hunter2-should-never-appear").
		WithDetail("cookie", "ESTSAUTH=should-never-appear")

	for _, schema := range []Schema{SchemaECS, SchemaOCSF} {
		document, err := Document(schema, event)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"hunter2-should-never-appear", "should-never-appear"} {
			if strings.Contains(string(encoded), secret) {
				t.Errorf("%s document leaked %q: %s", schema, secret, encoded)
			}
		}
	}
}

func TestNewValidatesConfig(t *testing.T) {
	valid := Config{
		Endpoint:  "https://splunk.example:8088/services/collector/event",
		Transport: TransportSplunkHEC,
		Schema:    SchemaECS,
		Token:     "token",
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"relative endpoint", func(c *Config) { c.Endpoint = "/collector" }},
		{"non-http scheme", func(c *Config) { c.Endpoint = "ftp://example.com/" }},
		{"missing transport", func(c *Config) { c.Transport = "" }},
		{"unknown transport", func(c *Config) { c.Transport = "syslog" }},
		{"missing schema", func(c *Config) { c.Schema = "" }},
		{"unknown schema", func(c *Config) { c.Schema = "stix" }},
		{"missing token", func(c *Config) { c.Token = "  " }},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := valid
			testCase.mutate(&config)
			if _, err := New(config); err == nil {
				t.Error("New accepted an invalid configuration")
			}
		})
	}

	if _, err := New(valid); err != nil {
		t.Fatalf("New rejected a valid configuration: %v", err)
	}
}

// TestSplunkHECEnvelope covers the transport difference that actually
// matters: HEC needs its own wrapper, and a document sent without it is
// silently mis-timestamped by some versions rather than rejected.
func TestSplunkHECEnvelope(t *testing.T) {
	var body []byte
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := New(Config{
		Endpoint:  server.URL + "/services/collector/event",
		Transport: TransportSplunkHEC,
		Schema:    SchemaECS,
		Token:     "hec-token",
		Client:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), sampleEvent()); err != nil {
		t.Fatal(err)
	}

	if authorization != "Splunk hec-token" {
		t.Errorf("Authorization = %q, want the Splunk scheme", authorization)
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["sourcetype"] != "olta:telemetry" {
		t.Errorf("sourcetype = %v", envelope["sourcetype"])
	}
	if _, ok := envelope["event"].(map[string]any); !ok {
		t.Errorf("body has no event envelope: %s", body)
	}
	if got, want := envelope["time"], float64(sampleEvent().Timestamp.UnixMilli())/1000; got != want {
		t.Errorf("time = %v, want %v (HEC expects fractional seconds)", got, want)
	}
}

// TestElasticPostsTheBareDocument is the complement: an Elasticsearch
// document endpoint indexes the body as-is, so an envelope would bury every
// field one level down and break the schema it was chosen for.
func TestElasticPostsTheBareDocument(t *testing.T) {
	var body []byte
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	sink, err := New(Config{
		Endpoint:  server.URL + "/olta-telemetry/_doc",
		Transport: TransportElastic,
		Schema:    SchemaECS,
		Token:     "id:key",
		Client:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), sampleEvent()); err != nil {
		t.Fatal(err)
	}

	if authorization != "ApiKey id:key" {
		t.Errorf("Authorization = %q, want the default ApiKey scheme", authorization)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	if _, wrapped := document["event"].(map[string]any); !wrapped {
		t.Fatalf("body is not the ECS document: %s", body)
	}
	if _, hasEnvelope := document["sourcetype"]; hasEnvelope {
		t.Errorf("Elastic body carries a HEC envelope: %s", body)
	}
	if document["@timestamp"] == nil {
		t.Errorf("body has no @timestamp: %s", body)
	}
}

func TestEmitReportsAnErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	sink, err := New(Config{
		Endpoint:  server.URL,
		Transport: TransportElastic,
		Schema:    SchemaOCSF,
		Token:     "token",
		Client:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), sampleEvent()); err == nil {
		t.Fatal("Emit reported success for an HTTP 403; a rejected event must reach Bus.Failed()")
	}
}

func TestCustomAuthScheme(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := New(Config{
		Endpoint:   server.URL,
		Transport:  TransportElastic,
		Schema:     SchemaECS,
		Token:      "opaque",
		AuthScheme: "Bearer",
		Client:     server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), sampleEvent()); err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer opaque" {
		t.Errorf("Authorization = %q, want the overridden scheme", authorization)
	}
}
