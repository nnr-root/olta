package campaignstore

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/s4l1hs/olta/pkg/feed"
)

func TestConfiguredFeedEndpointReceivesCapturedSession(t *testing.T) {
	server := httptest.NewServer(feed.Handler(t.TempDir()))
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	observer, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	store := &Store{feedEndpoint: endpoint}
	result := Result{BaseRecipient: BaseRecipient{Email: "authorized-test@example.com"}}
	if err := store.notify(result, "Captured Session", "test", `{"token":"value"}`); err != nil {
		t.Fatal(err)
	}
	if err := observer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, data, err := observer.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var event FeedEvent
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	if event.Event != "Captured Session" || !strings.Contains(event.Tokens, `"token":"value"`) {
		t.Fatalf("unexpected feed event: %#v", event)
	}
}
