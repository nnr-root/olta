package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	ctx "github.com/s4l1hs/olta/pkg/campaign/context"
	log "github.com/s4l1hs/olta/pkg/campaign/logger"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	feedclient "github.com/s4l1hs/olta/pkg/feed/client"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// liveFeedPathPattern matches the live feed SSE route, so registerRoutes
// can exempt it from response gzip compression (see the comment there for
// why that exemption is necessary).
var liveFeedPathPattern = regexp.MustCompile(`^/campaigns/[0-9]+/feed$`)

const (
	// liveFeedRingLimit bounds how many recent events the campaign server
	// retains in memory, regardless of how long it has been subscribed.
	liveFeedRingLimit = 200
	// liveFeedSubscriberBuffer bounds the per-dashboard-client fan-out
	// channel. A slow or gone client drops live events rather than
	// blocking the hub or growing without bound.
	liveFeedSubscriberBuffer = 32

	liveFeedMinBackoff = time.Second
	liveFeedMaxBackoff = 30 * time.Second

	// liveFeedKeepalive is how often an idle SSE connection gets a comment
	// line, so intermediary proxies do not time it out as dead.
	liveFeedKeepalive = 15 * time.Second

	// liveFeedConnectionLifetime bounds how long a single SSE response
	// stays open. The admin server's http.Server has a 30s WriteTimeout;
	// rather than fight that (or weaken it for every route), each SSE
	// connection ends itself well inside that window and lets the
	// browser's EventSource reconnect, which it does automatically. The
	// hub replays its ring buffer on every new subscription, so a client
	// that reconnects promptly -- which EventSource does, by default --
	// never sees a gap.
	liveFeedConnectionLifetime = 20 * time.Second
)

// feedEnvelope is the versioned message olta-feed's viewer connections
// receive. See pkg/telemetry/sink/feed.message for the publisher side of
// this same envelope.
type feedEnvelope struct {
	Type  string          `json:"type"`
	Event telemetry.Event `json:"event"`
}

// LiveFeedHub subscribes to olta-feed as a viewer and fans recent
// engagement telemetry out to authenticated campaign dashboard clients over
// Server-Sent Events.
//
// The browser never talks to olta-feed, and never sees its viewer token:
// only this hub, running server-side, holds that connection. Dashboard
// clients talk only to the campaign server, over the same session-cookie
// authenticated connection they already use for the rest of the dashboard.
//
// The hub is safe to use even when the feed is disabled or unreachable --
// that is expected to be the common case. Start becomes a no-op, the ring
// buffer stays empty, and every subscriber simply sees an idle feed.
type LiveFeedHub struct {
	feedURL string
	enabled bool

	mu          sync.Mutex
	ring        []telemetry.Event
	subscribers map[chan telemetry.Event]struct{}

	cancel context.CancelFunc
	done   chan struct{}
}

// NewLiveFeedHub returns a hub configured against the given olta-feed
// endpoint. When enabled is false, or feedURL is empty, Start never dials
// out; the hub still answers subscriptions, just with nothing in them.
func NewLiveFeedHub(feedURL string, enabled bool) *LiveFeedHub {
	return &LiveFeedHub{
		feedURL:     feedURL,
		enabled:     enabled,
		subscribers: make(map[chan telemetry.Event]struct{}),
	}
}

// Start begins the reconnecting viewer subscription in the background.
// Safe to call on a disabled hub: it simply returns.
func (h *LiveFeedHub) Start() {
	if h == nil || !h.enabled || h.feedURL == "" {
		return
	}
	runCtx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan struct{})
	go h.run(runCtx)
}

// Shutdown stops the subscriber, if one is running, and waits for it to
// exit before returning, so it can be called alongside the rest of the
// admin server's graceful shutdown.
func (h *LiveFeedHub) Shutdown() {
	if h == nil || h.cancel == nil {
		return
	}
	h.cancel()
	<-h.done
}

func (h *LiveFeedHub) run(runCtx context.Context) {
	defer close(h.done)
	backoff := liveFeedMinBackoff
	for runCtx.Err() == nil {
		conn, _, err := feedclient.DialViewer(h.feedURL)
		if err != nil {
			log.Warnf("live feed: connect to olta-feed: %v", err)
			if !sleepOrDone(runCtx, backoff) {
				return
			}
			backoff = nextLiveFeedBackoff(backoff)
			continue
		}
		backoff = liveFeedMinBackoff
		h.readLoop(runCtx, conn)
		_ = conn.Close()
		if runCtx.Err() != nil {
			return
		}
		// The connection dropped after having connected successfully at
		// least once; retry promptly rather than applying the not-yet-
		// reachable backoff to a feed that was just working.
		if !sleepOrDone(runCtx, liveFeedMinBackoff) {
			return
		}
	}
}

// readLoop reads viewer messages until the connection errors or runCtx is
// canceled. Canceling runCtx closes the connection to unblock the
// otherwise-blocking read.
func (h *LiveFeedHub) readLoop(runCtx context.Context, conn interface {
	ReadMessage() (int, []byte, error)
	Close() error
}) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-runCtx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var envelope feedEnvelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			continue
		}
		if envelope.Type != "telemetry.v1" {
			continue
		}
		h.Publish(envelope.Event)
	}
}

// Publish appends event to the bounded ring and fans it out to every
// current subscriber. Fan-out is best-effort: a subscriber whose buffer is
// full has its update dropped rather than blocking every other client or
// the reader loop.
func (h *LiveFeedHub) Publish(event telemetry.Event) {
	h.mu.Lock()
	h.ring = append(h.ring, event)
	if len(h.ring) > liveFeedRingLimit {
		h.ring = append([]telemetry.Event(nil), h.ring[len(h.ring)-liveFeedRingLimit:]...)
	}
	subs := make([]chan telemetry.Event, 0, len(h.subscribers))
	for sub := range h.subscribers {
		subs = append(subs, sub)
	}
	h.mu.Unlock()

	for _, sub := range subs {
		select {
		case sub <- event:
		default:
		}
	}
}

// Subscribe registers a new fan-out channel and returns it along with a
// snapshot of the current ring buffer, so a new dashboard client can
// render recent history immediately without waiting for the next event.
func (h *LiveFeedHub) Subscribe() (chan telemetry.Event, []telemetry.Event) {
	ch := make(chan telemetry.Event, liveFeedSubscriberBuffer)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subscribers[ch] = struct{}{}
	replay := append([]telemetry.Event(nil), h.ring...)
	return ch, replay
}

// Unsubscribe removes and closes a channel returned by Subscribe.
func (h *LiveFeedHub) Unsubscribe(ch chan telemetry.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subscribers[ch]; ok {
		delete(h.subscribers, ch)
		close(ch)
	}
}

func sleepOrDone(runCtx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-runCtx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextLiveFeedBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > liveFeedMaxBackoff {
		return liveFeedMaxBackoff
	}
	return next
}

// CampaignLiveFeed streams recent and incoming telemetry for one campaign
// to an authenticated dashboard client over Server-Sent Events. It rides
// the same session-cookie authentication as the rest of the dashboard
// (see registerRoutes) rather than the API's Bearer-token middleware,
// because a browser EventSource cannot attach an Authorization header.
//
// When the feed is disabled, or olta-feed is unreachable, this still
// answers normally: headers, an empty replay, and periodic keepalive
// comments until the client goes away. It never blocks waiting on
// olta-feed and never turns an outage into an error the dashboard has to
// handle.
func (as *AdminServer) CampaignLiveFeed(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	campaignID, err := strconv.ParseInt(vars["id"], 0, 64)
	if err != nil {
		http.Error(w, "Invalid campaign ID", http.StatusBadRequest)
		return
	}
	user, ok := ctx.Get(r, "user").(models.User)
	if !ok {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if _, err := models.GetCampaign(campaignID, user.Id); err != nil {
		http.Error(w, "Campaign not found", http.StatusNotFound)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	hub := as.liveFeed
	ch, replay := hub.Subscribe()
	defer hub.Unsubscribe(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Disable any reverse proxy response buffering (nginx honors this
	// header) that would otherwise defeat streaming.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// Write something immediately, even with an empty replay: an SSE
	// comment line is ignored by EventSource but guarantees the response
	// is not left sitting on a zero-byte body waiting for the first real
	// event, which -- depending on what sits between here and the socket
	// -- can otherwise mean nothing reaches the client until it does.
	fmt.Fprint(w, ": connected\n\n")

	for _, event := range replay {
		if event.CampaignID != campaignID {
			continue
		}
		writeLiveFeedEvent(w, event)
	}
	flusher.Flush()

	keepalive := time.NewTicker(liveFeedKeepalive)
	defer keepalive.Stop()
	lifetime := time.NewTimer(liveFeedConnectionLifetime)
	defer lifetime.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-lifetime.C:
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			if event.CampaignID != campaignID {
				continue
			}
			writeLiveFeedEvent(w, event)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func writeLiveFeedEvent(w http.ResponseWriter, event telemetry.Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		log.Errorf("live feed: marshal event: %v", err)
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", payload)
}
