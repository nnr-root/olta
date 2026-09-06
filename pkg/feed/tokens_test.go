package feed

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/websocket"
)

func writeTokenFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rewriteTokenFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTokenFileLoadsBothRoles(t *testing.T) {
	path := writeTokenFile(t, `{"publisher":["pub-1"],"viewer":["view-1"]}`)
	store, err := newTokenStore(Config{TokenFile: path})
	if err != nil {
		t.Fatal(err)
	}

	if !store.matchesPublisher("pub-1") || store.matchesPublisher("pub-2") {
		t.Error("publisher token matching is wrong")
	}
	if !store.matchesViewer("view-1") || store.matchesViewer("view-2") {
		t.Error("viewer token matching is wrong")
	}
}

// TestTokenFileOverlapAcceptsBothTokens is the rotation property. Both the
// old and the new token have to work at once, or the overlap that makes a
// rotation non-disruptive is not possible.
func TestTokenFileOverlapAcceptsBothTokens(t *testing.T) {
	path := writeTokenFile(t, `{"publisher":["pub-old","pub-new"],"viewer":["view-old","view-new"]}`)
	store, err := newTokenStore(Config{TokenFile: path})
	if err != nil {
		t.Fatal(err)
	}

	for _, token := range []string{"pub-old", "pub-new"} {
		if !store.matchesPublisher(token) {
			t.Errorf("publisher token %q rejected during an overlap", token)
		}
	}
	for _, token := range []string{"view-old", "view-new"} {
		if !store.matchesViewer(token) {
			t.Errorf("viewer token %q rejected during an overlap", token)
		}
	}
}

func TestReloadPicksUpRotatedTokens(t *testing.T) {
	path := writeTokenFile(t, `{"publisher":["pub-old"],"viewer":["view-old"]}`)
	store, err := newTokenStore(Config{TokenFile: path})
	if err != nil {
		t.Fatal(err)
	}

	rewriteTokenFile(t, path, `{"publisher":["pub-new"],"viewer":["view-new"]}`)
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}

	if store.matchesPublisher("pub-old") {
		t.Error("the retired publisher token is still accepted after a reload")
	}
	if !store.matchesPublisher("pub-new") {
		t.Error("the new publisher token is not accepted after a reload")
	}
	if store.matchesViewer("view-old") {
		t.Error("the retired viewer token is still accepted after a reload")
	}
	if !store.matchesViewer("view-new") {
		t.Error("the new viewer token is not accepted after a reload")
	}
}

// TestFailedReloadKeepsRunningTokens is the safety direction. A truncated or
// half-written file must not lock every client out of a live feed, so a
// failed reload keeps what is already loaded and reports the error.
func TestFailedReloadKeepsRunningTokens(t *testing.T) {
	path := writeTokenFile(t, `{"publisher":["pub-1"],"viewer":["view-1"]}`)
	store, err := newTokenStore(Config{TokenFile: path})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		contents string
	}{
		{"truncated json", `{"publisher":["pub-2"],`},
		{"not json at all", "pub-2\n"},
		{"empty file", ""},
		{"no publisher", `{"viewer":["view-2"]}`},
		{"no viewer", `{"publisher":["pub-2"]}`},
		{"blank entries only", `{"publisher":["  "],"viewer":["view-2"]}`},
		{"same token for both roles", `{"publisher":["shared"],"viewer":["shared"]}`},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rewriteTokenFile(t, path, testCase.contents)
			if err := store.Reload(); err == nil {
				t.Fatal("Reload accepted an unusable token file")
			}
			if !store.matchesPublisher("pub-1") || !store.matchesViewer("view-1") {
				t.Error("a failed reload dropped the tokens that were already working")
			}
		})
	}
}

func TestMissingTokenFileIsAnError(t *testing.T) {
	if _, err := newTokenStore(Config{TokenFile: filepath.Join(t.TempDir(), "absent.json")}); err == nil {
		t.Fatal("newTokenStore accepted a token file that does not exist")
	}
}

// TestNoTokensMeansAuthenticationDisabled preserves the loopback-only
// behavior: an empty set accepts anything, and Run is what refuses to expose
// that beyond loopback.
func TestNoTokensMeansAuthenticationDisabled(t *testing.T) {
	store, err := newTokenStore(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if !store.matchesPublisher("") || !store.matchesViewer("anything") {
		t.Error("an unconfigured store rejected a client; loopback feeds run without tokens")
	}
	if store.publisherConfigured() || store.viewerConfigured() {
		t.Error("an unconfigured store reports tokens configured")
	}
}

func TestConfiguredTokensStillWork(t *testing.T) {
	store, err := newTokenStore(Config{PublisherToken: "pub", ViewerToken: "view"})
	if err != nil {
		t.Fatal(err)
	}
	if !store.matchesPublisher("pub") || store.matchesPublisher("view") {
		t.Error("publisher matching is wrong for configured tokens")
	}
	if !store.matchesViewer("view") || store.matchesViewer("pub") {
		t.Error("viewer matching is wrong for configured tokens")
	}
}

// TestRotationOverAWebSocketConnection drives the rotation end to end against
// a real server: connect with the old token, rotate, and confirm the new
// token is accepted while the retired one is refused.
func TestRotationOverAWebSocketConnection(t *testing.T) {
	path := writeTokenFile(t, `{"publisher":["pub-old","pub-new"],"viewer":["view-old","view-new"]}`)
	feedServer, err := NewServer(t.TempDir(), WithTokenFile(path))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(feedServer.Handler())
	defer server.Close()

	// During the overlap both tokens are accepted.
	for _, token := range []string{"view-old", "view-new"} {
		conn, _, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws"), bearer(token))
		if err != nil {
			t.Fatalf("viewer token %q rejected during the overlap: %v", token, err)
		}
		_ = conn.Close()
	}

	// Retire the old token and reload.
	rewriteTokenFile(t, path, `{"publisher":["pub-new"],"viewer":["view-new"]}`)
	if err := feedServer.ReloadTokens(); err != nil {
		t.Fatal(err)
	}

	if conn, _, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws"), bearer("view-old")); err == nil {
		_ = conn.Close()
		t.Error("a retired viewer token was still accepted after the reload")
	}
	conn, _, err := websocket.DefaultDialer.Dial(websocketEndpoint(server.URL, "/ws"), bearer("view-new"))
	if err != nil {
		t.Fatalf("the current viewer token was rejected after the reload: %v", err)
	}
	_ = conn.Close()
}
