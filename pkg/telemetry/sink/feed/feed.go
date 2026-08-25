// Package feed publishes telemetry events to the Olta live feed.
package feed

import (
	"context"
	"encoding/json"

	"github.com/gorilla/websocket"
	feedclient "github.com/s4l1hs/olta/pkg/feed/client"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// message is the versioned envelope. The feed's viewer subprotocol is
// already versioned ("olta.v1"), so a new message type is additive: viewers
// that do not recognize it ignore it.
type message struct {
	Type  string          `json:"type"`
	Event telemetry.Event `json:"event"`
}

// Sink publishes each event to the feed. It dials per event, matching the
// existing campaignstore.notify behavior rather than holding a connection
// open across a long-running proxy process.
type Sink struct {
	endpoint string
}

// New returns a feed sink. An empty endpoint disables publishing.
func New(endpoint string) *Sink { return &Sink{endpoint: endpoint} }

// Emit publishes one event. A feed outage must never surface as an error
// that matters: the bus already ignores sink errors, and the campaign
// database remains the store of record.
func (s *Sink) Emit(_ context.Context, event telemetry.Event) error {
	if s.endpoint == "" {
		return nil
	}
	payload, err := json.Marshal(message{Type: "telemetry.v1", Event: event})
	if err != nil {
		return err
	}
	conn, _, err := feedclient.DialPublisher(s.endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.WriteMessage(websocket.TextMessage, payload)
}

// Close is a no-op: connections are per-event and already closed.
func (s *Sink) Close() error { return nil }
