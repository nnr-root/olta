package models

import (
	"sync"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// The models package already holds its database handle as package state.
// The telemetry emitter follows that same pattern rather than threading an
// extra parameter through every model method.
var telemetryState struct {
	sync.RWMutex
	emitter telemetry.Emitter
}

// SetTelemetryEmitter installs the process-wide emitter. Passing nil
// disables emission, which is what tests and the CLI paths use.
func SetTelemetryEmitter(emitter telemetry.Emitter) {
	telemetryState.Lock()
	defer telemetryState.Unlock()
	telemetryState.emitter = emitter
}

// EmitTelemetry forwards an event when an emitter is installed. It never
// blocks and never fails: a campaign must not break because telemetry is
// unavailable.
func EmitTelemetry(event telemetry.Event) {
	telemetryState.RLock()
	emitter := telemetryState.emitter
	telemetryState.RUnlock()
	if emitter == nil {
		return
	}
	emitter.Emit(event)
}
