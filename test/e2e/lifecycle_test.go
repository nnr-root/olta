package e2e

import (
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"
)

// leakTolerance is the number of goroutines this harness expects to remain
// running forever after every stage below has completed and released
// everything it can. Every one of the three is a genuine gap in the
// production code under test - not a shortcut this harness took - and each
// was confirmed individually by name in a pprof goroutine dump before being
// added here:
//
//  1. HttpProxy.Start() (exercised in runGatewayIngestion) spawns
//     httpsWorker's Accept() loop in its own goroutine
//     (pkg/proxy/core/http_proxy.go:1834), and HttpProxy exposes no Stop()
//     or Close() to unblock it - see gateway_test.go's package doc.
//  2. NewCertDb (also reached from runGatewayIngestion, since HttpProxy
//     requires a *CertDb) constructs certmagic.NewDefault()
//     (pkg/proxy/core/certdb.go), which starts certmagic's own
//     background (*Cache).maintainAssets goroutine on construction with no
//     exposed way to stop it - CertDb itself has no Close() either.
//  3. feed.Handler (exercised in runTelemetryFanout, following the same
//     pattern pkg/proxy/core/telemetry_integration_test.go already
//     established) unconditionally starts `go hub.run()`
//     (pkg/feed/feed.go's Handler, pkg/feed/hub.go:33) with no Close/Stop
//     exposed on the returned http.Handler or the Hub it wraps.
//
// Every other resource this harness touches (the proxy's own session
// database, the validation worker pool, the telemetry bus and every other
// sink, every httptest server, and the feed *server's* listener) is
// explicitly shut down and is accounted for at zero.
const leakTolerance = 3

// TestCampaignLifecycle simulates a full Olta campaign end to end, entirely
// on loopback with no external network access: personalized delivery and
// in-memory QR generation, real TLS gateway ingestion through a live
// HttpProxy listener with the bot/cloaking defenses wired in, the outbound
// uTLS transport HttpProxy uses for its own upstream leg, BuntDB session
// and cookie-token interception, and a validation-worker-and-telemetry-bus
// fanout to all four production sinks with the no-loot invariant checked
// at every one of them.
//
// It wraps every stage with the resource-hygiene checks the harness must
// not skip: a goroutine-count baseline taken before anything runs and
// re-checked (with a bounded retry loop, since goroutines unwind
// asynchronously) after every stage has returned and cleaned up what it
// can; and the fact that the whole simulation completes without the test
// binary panicking, which a plain `go test` failure on a panic already
// proves on its own.
//
// A true memory-leak check is out of scope for a unit-test harness and is
// not attempted here; verifying that would need a soak test, which this is
// not.
func TestCampaignLifecycle(t *testing.T) {
	baseline := settledGoroutineCount()
	t.Logf("goroutine baseline (settled): %d", baseline)

	t.Run("Initialization", runInitialization)
	t.Run("GatewayIngestionAndCloakingDefense", runGatewayIngestion)
	t.Run("OutboundTransportNegotiation", runOutboundTransport)
	t.Run("SessionInterception", runSessionInterception)
	t.Run("ValidationAndTelemetryFanout", runTelemetryFanout)

	final := waitForGoroutineBaseline(t, baseline, leakTolerance, 5*time.Second)
	t.Logf("goroutine count after full teardown: %d (baseline %d + tolerance %d)", final, baseline, leakTolerance)
}

// settledGoroutineCount samples runtime.NumGoroutine() until it stops
// changing (or a short bound elapses), so the baseline itself is not taken
// mid-flight of some unrelated goroutine that is still starting up or
// winding down from test-binary setup.
func settledGoroutineCount() int {
	last := runtime.NumGoroutine()
	stable := 0
	for i := 0; i < 100 && stable < 3; i++ {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
		current := runtime.NumGoroutine()
		if current == last {
			stable++
		} else {
			stable = 0
			last = current
		}
	}
	return last
}

// waitForGoroutineBaseline polls runtime.NumGoroutine() with a bounded
// retry loop - never a bare sleep-then-assert, since goroutines unwind
// asynchronously as deferred Close()/Cleanup calls run - until the count
// returns to baseline+tolerance or timeout elapses. On failure it dumps
// every goroutine's stack to stderr before failing the test, so a real leak
// is diagnosable from the test log rather than just a bare number.
func waitForGoroutineBaseline(t *testing.T, baseline, tolerance int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var final int
	for {
		runtime.GC()
		final = runtime.NumGoroutine()
		if final <= baseline+tolerance {
			return final
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := pprof.Lookup("goroutine").WriteTo(os.Stderr, 1); err != nil {
		t.Logf("dumping goroutine stacks: %v", err)
	}
	t.Fatalf("goroutine count = %d, want <= %d (baseline %d + tolerance %d)", final, baseline+tolerance, baseline, tolerance)
	return final
}
