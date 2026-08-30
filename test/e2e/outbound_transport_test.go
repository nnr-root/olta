package e2e

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utlstransport "github.com/s4l1hs/olta/pkg/proxy/transport/utls"
)

// runOutboundTransport exercises pkg/proxy/transport/utls directly - the
// exact browser-profiled outbound RoundTripper NewHttpProxy wires into
// every request it forwards upstream (see http_proxy.go's NewHttpProxy,
// which builds one with utlstransport.NewUTLSTransport and assigns it as
// ctx.RoundTripper). It cannot be reached through a live HttpProxy instance
// from this package (see gateway_test.go's package doc, point 1: the field
// is unexported with no setter), so this proves the mechanism at its own
// layer: for each of the Chrome, Firefox, Safari, and Random client
// profiles, a real TLS connection is negotiated against a local httptest
// server via SetDialContext, and the negotiated ALPN protocol - observed
// through the resulting response's HTTP version, exactly as
// pkg/proxy/transport/utls/utls_test.go's own
// TestTransportNegotiatesHTTPVersions does - differs between an HTTP/1.1-only
// server and an HTTP/2-capable one.
func runOutboundTransport(t *testing.T) {
	t.Helper()
	for _, profile := range []string{
		utlstransport.ChromeProfileName,
		utlstransport.FirefoxProfileName,
		utlstransport.SafariProfileName,
		utlstransport.RandomProfileName,
	} {
		t.Run(profile, func(t *testing.T) {
			t.Run("HTTP/1.1", func(t *testing.T) {
				assertOutboundNegotiates(t, profile, false, 1)
			})
			t.Run("HTTP/2", func(t *testing.T) {
				assertOutboundNegotiates(t, profile, true, 2)
			})
		})
	}
}

func assertOutboundNegotiates(t *testing.T, profile string, enableHTTP2 bool, wantProtoMajor int) {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = enableHTTP2
	server.StartTLS()
	defer server.Close()

	roundTripper := utlstransport.NewUTLSTransport(profile, 5*time.Second)
	transport, ok := roundTripper.(*utlstransport.Transport)
	if !ok {
		t.Fatalf("NewUTLSTransport() returned %T, want *utlstransport.Transport", roundTripper)
	}

	// SetDialContext points the outbound dial at the local server while the
	// request itself targets a hostname that resolves nowhere, proving it
	// is SetDialContext - not DNS - doing the routing. This is the same
	// integration point (and the same exported method) a live HttpProxy
	// would use to redirect its own outboundTransport at a stand-in
	// backend during a simulation.
	serverAddr := server.Listener.Addr().String()
	transport.SetDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddr)
	})

	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get("https://olta-e2e-upstream.invalid/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.ProtoMajor != wantProtoMajor {
		t.Fatalf("response protocol = %s, want HTTP/%d (profile %s)", resp.Proto, wantProtoMajor, profile)
	}
}
