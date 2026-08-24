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

// sinkTimeout bounds one sink write so a wedged sink cannot stall the
// drain goroutine forever.
const sinkTimeout = 10 * time.Second

// Bus fans one event out to every sink from a dedicated goroutine.
//
// Emit never blocks and never fails. When the queue is full the event is
// dropped and counted, because dropping telemetry is always preferable to
// delaying a victim-facing request. This mirrors the non-blocking broadcast
// already used by the feed hub.
type Bus struct {
	sinks  []Sink
	queue  chan Event
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	dropped atomic.Uint64
}

// NewBus starts the drain goroutine. A queueSize below 1 is raised to 1.
// With no sinks the bus is a no-op that still satisfies Emitter.
func NewBus(queueSize int, sinks ...Sink) *Bus {
	if queueSize < 1 {
		queueSize = 1
	}
	bus := &Bus{
		sinks:  sinks,
		queue:  make(chan Event, queueSize),
		closed: make(chan struct{}),
	}
	bus.wg.Add(1)
	go bus.drain()
	return bus
}

// Emit queues an event. Safe on a nil or closed bus.
func (b *Bus) Emit(event Event) {
	if b == nil {
		return
	}
	select {
	case <-b.closed:
		return
	default:
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
		close(b.closed)
		close(b.queue)
		b.wg.Wait()
		for _, sink := range b.sinks {
			if closeErr := sink.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
	})
	return err
}

func (b *Bus) drain() {
	defer b.wg.Done()
	for event := range b.queue {
		for _, sink := range b.sinks {
			ctx, cancel := context.WithTimeout(context.Background(), sinkTimeout)
			_ = sink.Emit(ctx, event)
			cancel()
		}
	}
}
