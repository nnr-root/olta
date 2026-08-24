package feed

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func websocketEndpoint(serverURL, path string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + path
}

func bearer(value string) http.Header {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+value)
	return header
}

func TestFeedSeparatesAuthenticatedPublishersAndSubscribers(t *testing.T) {
	server := httptest.NewServer(Handler(t.TempDir(),
		WithPublisherToken("publisher-secret"),
		WithViewerToken("viewer-secret"),
	))
	defer server.Close()

	subscriber, _, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws"), bearer("viewer-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer subscriber.Close()

	publisher, _, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws/publish"), bearer("publisher-secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()

	want := `{"event":"Captured Session","message":"safe"}`
	if err := publisher.WriteMessage(websocket.TextMessage, []byte(want)); err != nil {
		t.Fatal(err)
	}
	if err := subscriber.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, got, err := subscriber.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

func TestFeedRejectsWrongTokenAndCrossOriginBrowser(t *testing.T) {
	server := httptest.NewServer(Handler(t.TempDir(),
		WithPublisherToken("publisher-secret"),
		WithViewerToken("viewer-secret"),
	))
	defer server.Close()

	_, response, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws/publish"), bearer("wrong"))
	if err == nil {
		t.Fatal("publisher connection with wrong token succeeded")
	}
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", response)
	}
	_ = response.Body.Close()

	header := bearer("viewer-secret")
	header.Set("Origin", "https://attacker.example")
	_, response, err = websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws"), header)
	if err == nil {
		t.Fatal("cross-origin subscriber connection succeeded")
	}
	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %v, want 403", response)
	}
	_ = response.Body.Close()
}

func TestFeedReplaysBoundedHistory(t *testing.T) {
	server := httptest.NewServer(Handler(t.TempDir(), WithHistorySize(1)))
	defer server.Close()

	publisher, _, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws/publish"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.WriteMessage(websocket.TextMessage, []byte(`{"sequence":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := publisher.WriteMessage(websocket.TextMessage, []byte(`{"sequence":2}`)); err != nil {
		t.Fatal(err)
	}
	_ = publisher.Close()

	// Give the hub time to process both messages before registering the viewer.
	time.Sleep(20 * time.Millisecond)
	subscriber, _, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer subscriber.Close()
	if err := subscriber.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, got, err := subscriber.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"sequence":2}` {
		t.Fatalf("history = %s, want latest event", got)
	}
}

func TestLoopbackListenerDetection(t *testing.T) {
	for _, address := range []string{"localhost:1337", "127.0.0.1:1337", "[::1]:1337"} {
		if !loopbackListener(address) {
			t.Errorf("%q should be loopback", address)
		}
	}
	for _, address := range []string{":1337", "0.0.0.0:1337", "example.com:1337", "invalid"} {
		if loopbackListener(address) {
			t.Errorf("%q should not be loopback", address)
		}
	}
}
