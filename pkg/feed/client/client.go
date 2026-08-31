// Package client contains shared Olta Feed client configuration.
package client

import (
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

const (
	DefaultWebSocketEndpoint  = "ws://localhost:1337/ws/publish"
	EndpointEnvironment       = "OLTA_FEED_WS_URL"
	PublisherTokenEnvironment = "OLTA_FEED_PUBLISHER_TOKEN"
	// ViewerTokenEnvironment is the same variable name pkg/feed.Config's
	// viewer token is normally sourced from on the olta-feed side (see
	// cmd/olta-feed/main.go), so any process authorized to view the feed --
	// including the campaign server's server-side subscriber -- reads it
	// from here rather than a second, differently-named secret.
	ViewerTokenEnvironment = "OLTA_FEED_VIEWER_TOKEN"
)

// Endpoint returns the environment override, configured endpoint, or default.
func Endpoint(configured string) string {
	if value := os.Getenv(EndpointEnvironment); value != "" {
		return value
	}
	if configured != "" {
		return configured
	}
	return DefaultWebSocketEndpoint
}

// PublisherEndpoint converts the legacy subscriber endpoint to the dedicated
// publisher endpoint while preserving explicitly configured custom paths.
func PublisherEndpoint(configured string) string {
	endpoint := Endpoint(configured)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	if parsed.Path == "" || parsed.Path == "/" || parsed.Path == "/ws" {
		parsed.Path = "/ws/publish"
	}
	return parsed.String()
}

// DialPublisher opens an authenticated publisher connection. Tokens are read
// from the environment so they do not need to appear in URLs or config files.
func DialPublisher(configured string) (*websocket.Conn, *http.Response, error) {
	headers := http.Header{}
	if token := strings.TrimSpace(os.Getenv(PublisherTokenEnvironment)); token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	return websocket.DefaultDialer.Dial(PublisherEndpoint(configured), headers)
}

// SubscriberEndpoint converts the legacy or publisher endpoint to the
// viewer/subscriber endpoint while preserving explicitly configured custom
// paths.
func SubscriberEndpoint(configured string) string {
	endpoint := Endpoint(configured)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	if parsed.Path == "" || parsed.Path == "/" || parsed.Path == "/ws/publish" {
		parsed.Path = "/ws"
	}
	return parsed.String()
}

// DialViewer opens an authenticated viewer connection to olta-feed. Like
// DialPublisher, the token is read from the environment so it never has to
// appear in a config file or, worse, be handed to a browser.
func DialViewer(configured string) (*websocket.Conn, *http.Response, error) {
	headers := http.Header{}
	if token := strings.TrimSpace(os.Getenv(ViewerTokenEnvironment)); token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	return websocket.DefaultDialer.Dial(SubscriberEndpoint(configured), headers)
}
