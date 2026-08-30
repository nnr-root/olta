package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/proxy/database"
)

// freeLoopbackPort asks the OS for an unused loopback TCP port and returns
// it. HttpProxy.Start() (pkg/proxy/core/http_proxy.go:2123) binds its own
// listener asynchronously inside a goroutine and exposes no way to learn
// which port it actually bound - there is no accessor for the unexported
// net.Listener httpsWorker creates - so this harness cannot literally pass
// port 0 and discover the result afterward without a production code
// change. Instead, consistent with the common Go test workaround for APIs
// that do not return their bound address, it asks the OS for a free
// ephemeral port up front, closes the probe listener, and passes that exact
// port number to NewHttpProxy. This keeps the port OS-assigned and
// non-fixed (never a hardcoded literal), at the cost of a narrow
// time-of-check/time-of-use window between the probe closing and
// HttpProxy.Start() binding it, which is the same tradeoff every such
// workaround makes.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probing for a free loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("closing port probe listener: %v", err)
	}
	return port
}

// waitForListening retries dial against addr until it succeeds or deadline
// elapses, closing each probe connection immediately. HttpProxy.Start()
// spawns httpsWorker in its own goroutine and returns immediately, so a
// caller has no synchronous signal that the listener is actually accepting
// connections yet; a bounded retry loop is the only way to wait for it
// without an arbitrary fixed sleep.
func waitForListening(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("proxy listener at %s never became reachable: %v", addr, lastErr)
}

// noopCampaignEventSink implements core.CampaignEventSink with no-ops. It
// exists purely so NewHttpProxy has a sink to hand its campaign-facing
// events to; the gateway/cloaking scenarios this harness drives never reach
// the credential- or cookie-capture call sites (see gateway_test.go's
// package doc for why), so no call here is ever expected to record
// anything meaningful.
type noopCampaignEventSink struct{}

func (noopCampaignEventSink) HandleEmailOpened(string, map[string]string) error { return nil }
func (noopCampaignEventSink) HandleClickedLink(string, map[string]string) error { return nil }
func (noopCampaignEventSink) HandleSubmittedData(string, string, string, map[string]string) error {
	return nil
}
func (noopCampaignEventSink) HandleCapturedCookieSession(string, map[string]map[string]*database.CookieToken, map[string]string) error {
	return nil
}
func (noopCampaignEventSink) HandleCapturedOtherSession(string, map[string]string, map[string]string) error {
	return nil
}
