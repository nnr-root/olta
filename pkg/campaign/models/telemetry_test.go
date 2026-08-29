package models

import (
	"sync"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

type captureEmitter struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (e *captureEmitter) Emit(event telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *captureEmitter) all() []telemetry.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]telemetry.Event(nil), e.events...)
}

func TestEmitTelemetryReachesTheInstalledEmitter(t *testing.T) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	t.Cleanup(func() { SetTelemetryEmitter(nil) })

	EmitTelemetry(telemetry.New(telemetry.StageReport, telemetry.OutcomeAllowed))

	events := emitter.all()
	if len(events) != 1 || events[0].Stage != telemetry.StageReport {
		t.Fatalf("events = %+v", events)
	}
}

func TestEmitTelemetryIsSafeWithoutAnEmitter(t *testing.T) {
	SetTelemetryEmitter(nil)
	EmitTelemetry(telemetry.New(telemetry.StageDelivery, telemetry.OutcomeAllowed))
	// Reaching here without a panic is the assertion.
}

func TestEmitTelemetryIsRaceSafe(t *testing.T) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	t.Cleanup(func() { SetTelemetryEmitter(nil) })

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			EmitTelemetry(telemetry.New(telemetry.StageOpen, telemetry.OutcomeAllowed))
		}()
	}
	wg.Wait()

	if got := len(emitter.all()); got != 50 {
		t.Fatalf("received %d events, want 50", got)
	}
}
