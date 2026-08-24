package client

import "testing"

func TestPublisherEndpointUpgradesLegacyPath(t *testing.T) {
	t.Setenv(EndpointEnvironment, "")
	for input, want := range map[string]string{
		"":                              DefaultWebSocketEndpoint,
		"ws://localhost:1337/ws":        "ws://localhost:1337/ws/publish",
		"wss://feed.example/custom":     "wss://feed.example/custom",
		"wss://feed.example/ws/publish": "wss://feed.example/ws/publish",
	} {
		if got := PublisherEndpoint(input); got != want {
			t.Errorf("PublisherEndpoint(%q) = %q, want %q", input, got, want)
		}
	}
}
