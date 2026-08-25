package telemetry

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

type recordingSink struct {
	mu     sync.Mutex
	events []Event
	block  chan struct{}
	closed bool
}

func (s *recordingSink) Emit(_ context.Context, event Event) error {
	if s.block != nil {
		<-s.block
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *recordingSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// waitAllSinksClosed blocks until bus's background close-after-abandon
// goroutine has fully finished closing every sink, or fails the test after
// a generous deadline.
//
// The abandon path in Bus.Close closes sinks from a background goroutine
// once the abandoned drain finishes with them, rather than before Close
// returns (racing a sink's Emit against its own Close otherwise). A test
// that shortens the package-level sinkTimeout/shutdownTimeout vars must
// wait this out before returning: bus.allSinksClosed is what that
// goroutine closes last, after its own read of those vars, so waiting on
// it — rather than polling a sink's own closed flag, which only observes a
// goroutine nested one level deeper — establishes a real happens-before
// edge. Without it, that goroutine can still be reading the vars after
// this test has returned and a later test has mutated them back.
func waitAllSinksClosed(t *testing.T, bus *Bus) {
	t.Helper()
	select {
	case <-bus.allSinksClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("sinks were never closed by Close's background close-after-abandon goroutine")
	}
}

func TestBusDeliversToEverySink(t *testing.T) {
	first, second := &recordingSink{}, &recordingSink{}
	bus := NewBus(8, first, second)

	bus.Emit(New(StageLure, OutcomeAllowed, TechniqueSpearphishingLink))
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}

	if first.count() != 1 || second.count() != 1 {
		t.Fatalf("counts = %d/%d, want 1/1", first.count(), second.count())
	}
	if !first.closed || !second.closed {
		t.Fatal("Close() did not reach every sink")
	}
}

// A stalled sink must never block a caller on the request path.
func TestBusEmitNeverBlocksOnStalledSink(t *testing.T) {
	release := make(chan struct{})
	sink := &recordingSink{block: release}
	bus := NewBus(2, sink)
	defer func() { close(release); _ = bus.Close() }()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			bus.Emit(New(StageCloak, OutcomeBlocked, TechniqueProxy))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked while a sink was stalled")
	}

	if bus.Dropped() == 0 {
		t.Fatal("Dropped() = 0, want overflow to be counted")
	}
}

func TestNilBusIsSafe(t *testing.T) {
	var bus *Bus
	bus.Emit(New(StageVerify, OutcomeAllowed))
	if got := bus.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d", got)
	}
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBusCloseIsIdempotent(t *testing.T) {
	bus := NewBus(4, &recordingSink{})
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bus.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	bus.Emit(New(StageReport, OutcomeAllowed)) // must not panic on a closed bus
}

// TestBusEmitDuringCloseDoesNotPanic covers the dangerous interleaving:
// Emit checking "closed" and then sending, while Close closes the queue
// between those two steps. Sending on a closed channel panics
// unconditionally — a select's default case does not catch it — and that
// panic would occur on a proxy request goroutine during graceful shutdown.
//
// Run with -race -count=20. A sequential close-then-emit test does not
// exercise this; only concurrent Emit and Close do.
func TestBusEmitDuringCloseDoesNotPanic(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		bus := NewBus(4, &recordingSink{})

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				bus.Emit(New(StageLure, OutcomeAllowed))
				runtime.Gosched()
			}
		}()

		go func() {
			defer wg.Done()
			runtime.Gosched()
			_ = bus.Close()
		}()

		wg.Wait() // a panic in either goroutine fails the test binary
	}
}

// TestBusCloseFlushesAllQueuedEventsWhenHealthy pins the other half of the
// shutdown guarantee: bounding Close must not come at the cost of losing
// events when every sink is actually healthy. A healthy bus flushes
// everything it queued and reports zero undelivered.
func TestBusCloseFlushesAllQueuedEventsWhenHealthy(t *testing.T) {
	sink := &recordingSink{}
	bus := NewBus(64, sink)

	const n = 50
	for i := 0; i < n; i++ {
		bus.Emit(New(StageLure, OutcomeAllowed, TechniqueSpearphishingLink))
	}

	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}

	if got := sink.count(); got != n {
		t.Fatalf("sink received %d events, want %d", got, n)
	}
	if got := bus.Undelivered(); got != 0 {
		t.Fatalf("Undelivered() = %d, want 0 for a healthy shutdown", got)
	}
}

// TestBusCloseAbandonsDrainAtShutdownDeadline is the core A2 regression:
// without an overall deadline, Close waits for drain to walk the entire
// queue, and each event blocks on every sink in turn. With a full queue and
// every sink wedged, that is queueDepth * len(sinks) * sinkTimeout — at
// production defaults (1024, 4, 10s) roughly 11 hours. shutdownTimeout must
// cap Close well below that regardless of queue depth or sink count.
func TestBusCloseAbandonsDrainAtShutdownDeadline(t *testing.T) {
	originalShutdown := shutdownTimeout
	shutdownTimeout = 150 * time.Millisecond
	defer func() { shutdownTimeout = originalShutdown }()

	release := make(chan struct{})

	sinks := make([]Sink, 4)
	for i := range sinks {
		sinks[i] = &recordingSink{block: release}
	}
	bus := NewBus(8, sinks...)
	for i := 0; i < 8; i++ {
		bus.Emit(New(StageCloak, OutcomeBlocked, TechniqueProxy))
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- bus.Close() }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Close() did not return anywhere near the shutdown deadline; queueDepth * len(sinks) * sinkTimeout is back")
	}
	elapsed := time.Since(start)

	// Unblock the sinks so the abandoned drain goroutine (still running in
	// the background) can finish and close them, then wait for that before
	// this test hands the shared sinkTimeout/shutdownTimeout vars back.
	close(release)
	waitAllSinksClosed(t, bus)

	if elapsed > time.Second {
		t.Fatalf("Close() took %s, want close to shutdownTimeout (%s)", elapsed, shutdownTimeout)
	}
}

// TestBusCloseReportsUndeliveredCount asserts the abandoned events are
// counted, not silently discarded. With a queue of 8 events and a wedged
// sink, drain has already pulled the first event off the queue and is
// blocked mid-delivery when Close gives up; the remaining 7 are still
// sitting in the queue when abandon fires and must all be counted.
func TestBusCloseReportsUndeliveredCount(t *testing.T) {
	originalShutdown := shutdownTimeout
	shutdownTimeout = 100 * time.Millisecond
	defer func() { shutdownTimeout = originalShutdown }()

	release := make(chan struct{})
	sink := &recordingSink{block: release}
	bus := NewBus(8, sink)

	const n = 8
	for i := 0; i < n; i++ {
		bus.Emit(New(StageCloak, OutcomeBlocked, TechniqueProxy))
	}

	if err := bus.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	// Event #1 is stuck mid-delivery inside the abandoned drain goroutine
	// (the sink is still wedged); unblock it so that goroutine can finish
	// walking, and counting, the rest of the queue.
	close(release)

	const want = n - 1
	deadline := time.Now().Add(2 * time.Second)
	for bus.Undelivered() < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := bus.Undelivered(); got != want {
		t.Fatalf("Undelivered() = %d, want %d", got, want)
	}

	// The abandoned drain goroutine is still running in the background;
	// wait for it to close the sink before this test hands the shared
	// sinkTimeout/shutdownTimeout vars back.
	waitAllSinksClosed(t, bus)
}

// TestBusCloseReturnsWhenSinkIgnoresContext pins the shutdown guarantee.
// The campaign database sink ignores its context (gorm v1 predates context
// support), so Close must still return rather than block on wg.Wait()
// forever.
func TestBusCloseReturnsWhenSinkIgnoresContext(t *testing.T) {
	original := sinkTimeout
	sinkTimeout = 200 * time.Millisecond
	defer func() { sinkTimeout = original }()

	release := make(chan struct{})
	defer close(release)

	bus := NewBus(4, &recordingSink{block: release})
	bus.Emit(New(StageCapture, OutcomeCaptured))

	done := make(chan error, 1)
	go func() { done <- bus.Close() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() blocked on a sink that ignores its context")
	}
}
