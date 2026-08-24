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
