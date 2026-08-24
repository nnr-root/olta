package telemetry

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Sink receives events. Implementations own their own timeouts and must
// tolerate being called from a single dedicated goroutine.
type Sink interface {
	Emit(context.Context, Event) error
	Close() error
}

// Emitter is the narrow view that middleware depends on, so packages like
// asncloak and jsinspect never learn about buses, sinks, or campaigns.
type Emitter interface {
	Emit(Event)
}

// sinkTimeout bounds one sink write so a wedged sink cannot stall the drain
// goroutine — and therefore Close — forever. It is a var, not a const, so
// the shutdown test can shorten it rather than sleeping for the real value.
var sinkTimeout = 10 * time.Second

// Bus fans one event out to every sink from a dedicated goroutine.
//
// Emit never blocks and never fails. When the queue is full the event is
// dropped and counted, because dropping telemetry is always preferable to
// delaying a victim-facing request. This mirrors the non-blocking broadcast
// already used by the feed hub.
type Bus struct {
	sinks []Sink
	queue chan Event

	// mu makes the closed-check and the queue send atomic with respect to
	// Close. Without it, Emit can pass its closed-check, Close can then
	// close the queue, and Emit's send panics on a closed channel — an
	// unconditional panic that a select's default case does not catch.
	// Emit holds the read lock (uncontended in the steady state) and Close
	// takes the write lock, so the two can never interleave.
	mu     sync.RWMutex
	closed bool

	once sync.Once
	wg   sync.WaitGroup

	// dropped counts events the queue had no room for; failed counts events
	// a sink rejected or timed out on. They are different losses and an
	// operator needs to tell them apart: dropped means the bus is
	// undersized, failed means a sink is broken.
	dropped atomic.Uint64
	failed  atomic.Uint64
}

// NewBus starts the drain goroutine. A queueSize below 1 is raised to 1.
// With no sinks the bus is a no-op that still satisfies Emitter.
func NewBus(queueSize int, sinks ...Sink) *Bus {
	if queueSize < 1 {
		queueSize = 1
	}
	bus := &Bus{
		sinks: sinks,
		queue: make(chan Event, queueSize),
	}
	bus.wg.Add(1)
	go bus.drain()
	return bus
}

// Emit queues an event. Safe on a nil or closed bus, and safe to call
// concurrently with Close.
//
// The read lock is held across both the closed-check and the send. It is
// uncontended except during the instant Close holds the write lock, and the
// send itself is non-blocking, so Emit remains fire-and-forget.
func (b *Bus) Emit(event Event) {
	if b == nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	select {
	case b.queue <- event:
	default:
		b.dropped.Add(1)
	}
}

// Dropped reports how many events were discarded because the queue was full.
func (b *Bus) Dropped() uint64 {
	if b == nil {
		return 0
	}
	return b.dropped.Load()
}

// Failed reports how many sink deliveries returned an error or timed out.
// A non-zero value means the store of record is incomplete.
func (b *Bus) Failed() uint64 {
	if b == nil {
		return 0
	}
	return b.failed.Load()
}

// Close stops accepting events, drains what is queued, and closes every
// sink. It is idempotent.
func (b *Bus) Close() error {
	if b == nil {
		return nil
	}
	var err error
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		close(b.queue)
		b.mu.Unlock()

		b.wg.Wait()
		for _, sink := range b.sinks {
			// Bounded for the same reason sink writes are: a Sink.Close
			// that blocks on a wedged handle would otherwise hang shutdown
			// after drain had already finished cleanly.
			if closeErr := closeSink(sink); closeErr != nil && err == nil {
				err = closeErr
			}
		}
	})
	return err
}

func closeSink(sink Sink) error {
	done := make(chan error, 1)
	go func() { done <- sink.Close() }()

	select {
	case closeErr := <-done:
		return closeErr
	case <-time.After(sinkTimeout):
		return fmt.Errorf("telemetry: sink close timed out after %s", sinkTimeout)
	}
}

// drain delivers each queued event to every sink. Closing the queue does not
// discard buffered events: range yields all of them before the loop exits,
// so Close flushes rather than truncates.
//
// A sink failure never stops other sinks or the loop, but it is never
// silent either. The campaign database is the store of record for an
// engagement; an event disappearing from it with no trace would leave an
// operator unable to tell an uneventful campaign from a broken pipeline.
func (b *Bus) drain() {
	defer b.wg.Done()
	for event := range b.queue {
		for _, sink := range b.sinks {
			if err := emitTo(sink, event); err != nil {
				b.failed.Add(1)
				log.Printf("telemetry: sink %T dropped event %s (stage %s): %v",
					sink, event.ID, event.Stage, err)
			}
		}
	}
}

// emitTo bounds one sink write in wall-clock time, not merely by context.
//
// A context deadline only binds a sink that selects on ctx.Done(). The
// campaign database sink cannot: gorm v1 predates context support and its
// calls are synchronous. Passing the context alone would leave a wedged
// database write able to block drain forever, which in turn blocks Close's
// wg.Wait() forever, hanging graceful shutdown.
//
// Running the call on its own goroutine and abandoning it at the deadline
// buys a drain loop, and therefore a Close, that always makes progress.
//
// The cost is honest: each abandoned call leaves its goroutine alive until
// the sink returns, so a chronically wedged sink leaks one goroutine per
// event for as long as the condition lasts. That is bounded only by how long
// the process runs in that state, not by any constant. It is the right trade
// — a leaked goroutine is recoverable, a hung shutdown is not — but it is
// not a small bounded cost, and a sink that wedges under load is a bug to
// fix in the sink.
func emitTo(sink Sink, event Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), sinkTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sink.Emit(ctx, event) }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("telemetry: sink %T timed out after %s", sink, sinkTimeout)
	}
}
