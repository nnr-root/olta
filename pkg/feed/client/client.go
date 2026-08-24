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
