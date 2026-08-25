package feed

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	feedpkg "github.com/s4l1hs/olta/pkg/feed"
	feedclient "github.com/s4l1hs/olta/pkg/feed/client"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

func websocketEndpoint(serverURL, path string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + path
}

func TestSinkPublishesVersionedEnvelope(t *testing.T) {
	t.Setenv(feedclient.EndpointEnvironment, "")
	t.Setenv(feedclient.PublisherTokenEnvironment, "")

	server := httptest.NewServer(feedpkg.Handler(t.TempDir()))
	defer server.Close()

	subscriber, _, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer subscriber.Close()

	sink := New(websocketEndpoint(server.URL, "/ws/publish"))
	event := telemetry.New(telemetry.StageLure, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink).
		WithCampaign(7, "rid-victim-1")
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	if err := subscriber.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, raw, err := subscriber.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}

	var decoded message
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("message is not valid JSON: %v: %s", err, raw)
	}
	if decoded.Type != "telemetry.v1" {
		t.Fatalf("type = %q, want telemetry.v1", decoded.Type)
	}
	if decoded.Event.Stage != telemetry.StageLure || decoded.Event.RID != "rid-victim-1" {
		t.Fatalf("event = %+v, want the emitted lure event", decoded.Event)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSinkWithEmptyEndpointIsANoOp(t *testing.T) {
	sink := New("")
	event := telemetry.New(telemetry.StageLure, telemetry.OutcomeAllowed)
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit() with empty endpoint returned error: %v", err)
	}
}
