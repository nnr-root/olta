package utls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	tlsclient "github.com/refraction-networking/utls"
)

func TestParseClientProfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantName  string
		wantHello tlsclient.ClientHelloID
	}{
		{name: "chrome", input: "Chrome", wantName: ChromeProfileName, wantHello: tlsclient.HelloChrome_Auto},
		{name: "firefox case insensitive", input: "fireFOX", wantName: FirefoxProfileName, wantHello: tlsclient.HelloFirefox_Auto},
		{name: "safari", input: "Safari", wantName: SafariProfileName, wantHello: tlsclient.HelloIOS_Auto},
		{name: "unknown falls back to chrome", input: "unknown", wantName: ChromeProfileName, wantHello: tlsclient.HelloChrome_Auto},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := ParseClientProfile(test.input)
			if got := profile.Name(); got != test.wantName {
				t.Fatalf("profile name = %q, want %q", got, test.wantName)
			}
			assertClientHelloID(t, profile.ClientHelloID(), test.wantHello)
		})
	}
}

func TestRandomProfileUsesModernPreset(t *testing.T) {
	for i := 0; i < 32; i++ {
		got := Random.ClientHelloID()
		if !isModernClientHello(got) {
			t.Fatalf("random ClientHello = %s-%s, want a modern browser preset", got.Client, got.Version)
		}
	}
}

func TestNewUTLSTransport(t *testing.T) {
	for _, name := range []string{"Chrome", "Firefox", "Safari", "Random"} {
		t.Run(name, func(t *testing.T) {
			var roundTripper http.RoundTripper = NewUTLSTransport(name, 5*time.Second)
			transport, ok := roundTripper.(*Transport)
			if !ok {
				t.Fatalf("NewUTLSTransport() returned %T, want *Transport", roundTripper)
			}
			if transport.profile.Name() != name {
				t.Fatalf("profile name = %q, want %q", transport.profile.Name(), name)
			}
			if transport.HTTP1Transport().DialTLSContext == nil {
				t.Fatal("HTTP/1.1 fallback has no uTLS dialer")
			}
		})
	}
}

func TestTransportNegotiatesHTTPVersions(t *testing.T) {
	tests := []struct {
		name           string
		enableHTTP2    bool
		wantProtoMajor int
	}{
		{name: "HTTP/1.1", enableHTTP2: false, wantProtoMajor: 1},
		{name: "HTTP/2", enableHTTP2: true, wantProtoMajor: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			server.EnableHTTP2 = test.enableHTTP2
			server.StartTLS()
			defer server.Close()

			client := &http.Client{Transport: NewUTLSTransport("Chrome", 5*time.Second)}
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if resp.ProtoMajor != test.wantProtoMajor {
				t.Fatalf("response protocol = %s, want HTTP/%d", resp.Proto, test.wantProtoMajor)
			}
		})
	}
}

func TestALPNFailureIsNetError(t *testing.T) {
	err := alpnNetError("example.com:443", io.ErrUnexpectedEOF)
	if _, ok := err.(net.Error); !ok {
		t.Fatalf("ALPN error type = %T, want net.Error", err)
	}
}

func TestConnectionTimeoutIsNetError(t *testing.T) {
	transport := NewUTLSTransport("Chrome", 10*time.Millisecond).(*Transport)
	transport.SetDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	_, err = transport.RoundTrip(req)
	if err == nil {
		t.Fatal("RoundTrip() error = nil, want connection timeout")
	}

	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Fatalf("connection timeout type = %T, want net.Error", err)
	}
	if !netErr.Timeout() {
		t.Fatalf("connection timeout = %v, want Timeout() true", err)
	}
}

func assertClientHelloID(t *testing.T, got, want tlsclient.ClientHelloID) {
	t.Helper()
	if got.Client != want.Client || got.Version != want.Version {
		t.Fatalf("ClientHello = %s-%s, want %s-%s", got.Client, got.Version, want.Client, want.Version)
	}
}

func isModernClientHello(id tlsclient.ClientHelloID) bool {
	for _, candidate := range modernClientHelloIDs {
		if id.Client == candidate.Client && id.Version == candidate.Version {
			return true
		}
	}
	return false
}
