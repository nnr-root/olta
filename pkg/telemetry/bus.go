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

// shutdownTimeout bounds Close() itself, independent of queue depth or sink
// count. Without it, a wedged sink turns "drain everything, then close"
// into queueSize × len(sinks) × sinkTimeout in the worst case — with the
// production defaults (a 1024-deep queue and up to 4 sinks) that is roughly
// 11 hours, which is not a graceful shutdown, it is a hang with a deadline.
// A var, not a const, so the shutdown test can shorten it.
var shutdownTimeout = 30 * time.Second

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
	// a sink rejected or timed out on; undelivered counts events Close gave
	// up on entirely because the overall shutdown deadline passed before
	// drain reached them. Three different losses, three different causes:
	// dropped means the bus is undersized, failed means a sink is broken,
	// undelivered means shutdown itself ran out of time.
	dropped     atomic.Uint64
	failed      atomic.Uint64
	undelivered atomic.Uint64

	// abandon is closed by Close once shutdownTimeout passes without drain
	// finishing. drain checks it before starting each event's delivery and,
	// once closed, stops calling sinks and just counts and discards what is
	// left — so the abandoned drain goroutine still terminates promptly
	// in the background instead of continuing to hammer a wedged sink.
	abandon chan struct{}

	// allSinksClosed is closed once closeSinks has actually run to
	// completion, on whichever path got there (the healthy path inside
	// Close, or the background goroutine Close spawns on abandonment).
	// Nothing in the package depends on it — Close's own return already
	// carries the healthy-path result — but it gives tests a real
	// happens-before edge onto "every sink is done being touched by this
	// Bus," instead of polling a sink's own state, which is one goroutine
	// too shallow: it observes the inner per-sink Close call completing,
	// not the outer closeSink/closeSinks call (and its read of the
	// package-level sinkTimeout var) that wraps it.
	allSinksClosed chan struct{}
}

// NewBus starts the drain goroutine. A queueSize below 1 is raised to 1.
// With no sinks the bus is a no-op that still satisfies Emitter.
func NewBus(queueSize int, sinks ...Sink) *Bus {
	if queueSize < 1 {
		queueSize = 1
	}
	bus := &Bus{
		sinks:          sinks,
		queue:          make(chan Event, queueSize),
		abandon:        make(chan struct{}),
		allSinksClosed: make(chan struct{}),
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

// Undelivered reports how many queued events Close abandoned because the
// overall shutdown deadline (shutdownTimeout) passed before drain reached
// them. A non-zero value means shutdown gave up early, not that delivery
// was attempted and failed — see Failed for that.
func (b *Bus) Undelivered() uint64 {
	if b == nil {
		return 0
	}
	return b.undelivered.Load()
}

// Close stops accepting events and drains what is queued, up to an overall
// shutdownTimeout. A healthy bus flushes everything and closes every sink
// well within that budget. If drain has not finished by the deadline, Close
// abandons it and returns: the remaining events are counted in Undelivered
// rather than delivered, and sinks are closed in the background once the
// abandoned drain goroutine actually stops touching them, so Close never
// races a sink's Emit against its own Close call. Close is idempotent.
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

		drained := make(chan struct{})
		go func() {
			b.wg.Wait()
			close(drained)
		}()

		select {
		case <-drained:
			err = b.closeSinks()
			close(b.allSinksClosed)
		case <-time.After(shutdownTimeout):
			log.Printf("telemetry: bus shutdown exceeded %s; abandoning drain, some events will be undelivered", shutdownTimeout)
			close(b.abandon)
			go func() {
				<-drained
				_ = b.closeSinks()
				close(b.allSinksClosed)
			}()
		}
	})
	return err
}

// closeSinks closes every sink, bounded per sink by sinkTimeout for the
// same reason sink writes are: a Sink.Close that blocks on a wedged handle
// would otherwise hang shutdown after drain had already finished cleanly.
func (b *Bus) closeSinks() error {
	var err error
	for _, sink := range b.sinks {
		if closeErr := closeSink(sink); closeErr != nil && err == nil {
			err = closeErr
		}
	}
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

// drain delivers each queued event to every sink, one event at a time, in
// queue order. Closing the queue does not discard buffered events: range
// yields all of them before the loop exits, so a healthy Close flushes
// rather than truncates.
//
// Once Close abandons the drain (shutdownTimeout elapsed), drain stops
// calling sinks and instead counts and discards whatever is left, so this
// goroutine still terminates promptly on its own rather than continuing to
// hammer a wedged sink in the background indefinitely.
func (b *Bus) drain() {
	defer b.wg.Done()
	for event := range b.queue {
		select {
		case <-b.abandon:
			b.undelivered.Add(1)
			continue
		default:
		}
		b.deliver(event)
	}
}

// deliver fans one event out to every sink concurrently and waits for all
// of them, so the per-event cost is the slowest sink's timeout rather than
// the sum of every sink's timeout — turning queueDepth × len(sinks) ×
// sinkTimeout into queueDepth × sinkTimeout in the worst case. Events are
// still processed one at a time in queue order: the next event's delivery
// does not start until every sink has finished (or timed out on) this one,
// so per-sink ordering is unaffected by the fan-out.
//
// A sink failure never stops other sinks or the loop, but it is never
// silent either. The campaign database is the store of record for an
// engagement; an event disappearing from it with no trace would leave an
// operator unable to tell an uneventful campaign from a broken pipeline.
func (b *Bus) deliver(event Event) {
	var wg sync.WaitGroup
	wg.Add(len(b.sinks))
	for _, sink := range b.sinks {
		go func(sink Sink) {
			defer wg.Done()
			if err := emitTo(sink, event); err != nil {
				b.failed.Add(1)
				log.Printf("telemetry: sink %T dropped event %s (stage %s): %v",
					sink, event.ID, event.Stage, err)
			}
		}(sink)
	}
	wg.Wait()
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
