package campaignstore

import (
	"context"

	"github.com/s4l1hs/olta/pkg/telemetry"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/campaigndb"
)

// storeSink adapts Store's existing single-writer queue to telemetry.Sink.
//
// The design spec requires the campaigndb sink to write through
// campaignstore's queue, which already owns the database handle and the
// serialization, rather than opening an independent connection. Routing
// through the queue here — instead of handing out a second *gorm.DB-backed
// sink — is what keeps exactly one writer goroutine against the campaign
// database from the proxy process.
type storeSink struct {
	store *Store
}

// TelemetrySink returns a telemetry.Sink that persists events through this
// Store's queue and worker goroutine rather than a database handle of its
// own. It reuses campaigndb's row mapping (campaigndb.Insert) so the schema
// mapping lives in exactly one place.
func (s *Store) TelemetrySink() telemetry.Sink {
	return &storeSink{store: s}
}

// Emit enqueues the insert onto the Store's queue and waits for it to run.
// Waiting (rather than firing and forgetting) preserves the guarantee the
// telemetry bus already relies on: emitTo bounds this call in wall-clock
// time from the caller's side, and a genuine write failure is reported back
// to the bus instead of being silently swallowed.
func (t *storeSink) Emit(ctx context.Context, event telemetry.Event) error {
	result := make(chan error, 1)
	if err := t.store.enqueue(func() error {
		err := campaigndb.Insert(t.store.db, event)
		result <- err
		return err
	}); err != nil {
		return err
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close is a no-op: the Store owns the database handle and its own shutdown
// sequence (Store.Close), so the sink must never close it out from under
// the Store.
func (t *storeSink) Close() error { return nil }
