// Package client contains shared Olta Feed client configuration.
package client

import "os"

const (
	DefaultWebSocketEndpoint = "ws://localhost:1337/ws"
	EndpointEnvironment      = "OLTA_FEED_WS_URL"
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
