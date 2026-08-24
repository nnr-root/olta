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
