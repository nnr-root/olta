package telemetry

import (
	"context"
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

	dropped atomic.Uint64
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
			if closeErr := sink.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
	})
	return err
}

// drain delivers each queued event to every sink. Closing the queue does not
// discard buffered events: range yields all of them before the loop exits,
// so Close flushes rather than truncates.
func (b *Bus) drain() {
	defer b.wg.Done()
	for event := range b.queue {
		for _, sink := range b.sinks {
			emitTo(sink, event)
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
// costs at most one leaked goroutine per wedged write, and buys a Close that
// always returns. That is the right trade for a shutdown path.
func emitTo(sink Sink, event Event) {
	ctx, cancel := context.WithTimeout(context.Background(), sinkTimeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A sink failure must not stop other sinks or the drain loop.
		// Sinks log their own failures.
		_ = sink.Emit(ctx, event)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
