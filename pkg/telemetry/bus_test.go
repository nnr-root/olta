package telemetry

import (
	"context"
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
