package validation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

var (
	ErrQueueFull      = errors.New("session validation queue is full")
	ErrWorkerClosed   = errors.New("session validation worker is closed")
	ErrDuplicateEvent = errors.New("session validation event already queued")
)

// defaultSeenCapacity bounds the deduplication set when WorkerConfig leaves
// SeenCapacity unset. It is sized well above the default QueueSize (256) so
// dedup comfortably covers a burst of in-flight and recently queued events,
// while still holding the set's memory to a small, fixed footprint over an
// engagement that runs for days and sees many more than 256 sessions.
const defaultSeenCapacity = 4096

// WorkerConfig controls queue capacity, concurrency, and time limits.
type WorkerConfig struct {
	Workers           int
	QueueSize         int
	ValidationTimeout time.Duration
	Validator         Validator
	// SeenCapacity bounds how many session IDs the deduplication set
	// remembers at once. Once full, the oldest tracked ID is forgotten to
	// make room for the newest, so a session queued long enough ago can be
	// queued again -- trading perfect lifetime deduplication for a fixed
	// memory footprint across a long-running engagement. 0 uses
	// defaultSeenCapacity.
	SeenCapacity int
	// Emitter, when set, receives one replay-stage telemetry.Event per
	// validation result. Telemetry flows through the shared bus rather than
	// a validator-specific webhook, so any sink on that bus receives it.
	Emitter  telemetry.Emitter
	OnResult func(Result)
}

// Worker owns a bounded, non-blocking input queue and a fixed goroutine pool.
type Worker struct {
	config WorkerConfig
	queue  chan Event

	acceptMu  sync.Mutex
	accepting bool
	// seen and seenOrder together implement a bounded FIFO deduplication
	// set: seen answers membership, seenOrder is a fixed-capacity ring
	// buffer (length grows to seenCap once, then never again) recording
	// insertion order so the oldest entry can be evicted from seen in O(1)
	// once the set is full. Both are guarded by acceptMu.
	seen      map[string]struct{}
	seenOrder []string
	seenNext  int
	seenCap   int
	shutdown  chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewWorker starts a validation worker pool.
func NewWorker(config WorkerConfig) (*Worker, error) {
	if config.Workers == 0 {
		config.Workers = 4
	}
	if config.QueueSize == 0 {
		config.QueueSize = 256
	}
	if config.ValidationTimeout == 0 {
		config.ValidationTimeout = 10 * time.Second
	}
	if config.SeenCapacity == 0 {
		config.SeenCapacity = defaultSeenCapacity
	}
	if config.Workers < 1 || config.QueueSize < 1 {
		return nil, fmt.Errorf("session validator workers and queue size must be positive")
	}
	if config.ValidationTimeout <= 0 {
		return nil, fmt.Errorf("session validator timeouts must be positive")
	}
	if config.SeenCapacity < 1 {
		return nil, fmt.Errorf("session validator seen capacity must be positive")
	}
	if config.Validator == nil {
		config.Validator = NewHTTPValidator(nil)
	}
	worker := &Worker{
		config:    config,
		queue:     make(chan Event, config.QueueSize),
		accepting: true,
		seen:      make(map[string]struct{}),
		seenOrder: make([]string, 0, config.SeenCapacity),
		seenCap:   config.SeenCapacity,
		shutdown:  make(chan struct{}),
	}
	worker.wg.Add(config.Workers)
	for range config.Workers {
		go worker.run()
	}
	return worker, nil
}

// remember records sessionID as seen, evicting the oldest tracked session ID
// first if the set is already at capacity. Callers must hold acceptMu.
func (worker *Worker) remember(sessionID string) {
	if len(worker.seenOrder) < worker.seenCap {
		worker.seenOrder = append(worker.seenOrder, sessionID)
	} else {
		oldest := worker.seenOrder[worker.seenNext]
		delete(worker.seen, oldest)
		worker.seenOrder[worker.seenNext] = sessionID
		worker.seenNext = (worker.seenNext + 1) % worker.seenCap
	}
	worker.seen[sessionID] = struct{}{}
}

// Enqueue adds an event without waiting for queue space. Cookie data is cloned
// before ownership passes to the background worker.
func (worker *Worker) Enqueue(event Event) error {
	if worker == nil {
		return ErrWorkerClosed
	}
	worker.acceptMu.Lock()
	defer worker.acceptMu.Unlock()
	if !worker.accepting {
		return ErrWorkerClosed
	}
	if event.SessionID != "" {
		if _, exists := worker.seen[event.SessionID]; exists {
			return ErrDuplicateEvent
		}
	}
	event = cloneEvent(event)
	select {
	case worker.queue <- event:
		if event.SessionID != "" {
			worker.remember(event.SessionID)
		}
		return nil
	default:
		return ErrQueueFull
	}
}

func (worker *Worker) run() {
	defer worker.wg.Done()
	for {
		select {
		case event := <-worker.queue:
			worker.process(event)
		case <-worker.shutdown:
			for {
				select {
				case event := <-worker.queue:
					worker.process(event)
				default:
					return
				}
			}
		}
	}
}

func (worker *Worker) process(event Event) {
	validationContext, cancelValidation := context.WithTimeout(context.Background(), worker.config.ValidationTimeout)
	result := worker.config.Validator.Validate(validationContext, event)
	cancelValidation()
	result = normalizeResult(result, event)
	if worker.config.OnResult != nil {
		worker.config.OnResult(result)
	}
	worker.emitReplay(result)
}

func normalizeResult(result Result, event Event) Result {
	base := baseResult(event, time.Now())
	if result.Timestamp.IsZero() {
		result.Timestamp = base.Timestamp
	}
	if result.SessionReference == "" {
		result.SessionReference = base.SessionReference
	}
	if result.Phishlet == "" {
		result.Phishlet = base.Phishlet
	}
	if result.TargetHost == "" {
		result.TargetHost = base.TargetHost
	}
	if result.Identity.Username == "" {
		result.Identity.Username = base.Identity.Username
	}
	if result.Identity.TenantID == "" {
		result.Identity.TenantID = base.Identity.TenantID
	}
	if result.Identity.Organization == "" {
		result.Identity.Organization = base.Identity.Organization
	}
	if result.Status == "" {
		result.Status = StatusUnknown
	}
	return result
}

// replayOutcome maps a validation status to a replay-stage telemetry
// outcome. There is no boolean validity field on Result to switch on
// instead — Status is the only signal.
func replayOutcome(status Status) telemetry.Outcome {
	switch status {
	case StatusValid:
		// The stolen cookie still works: the session survived.
		return telemetry.OutcomeAllowed
	case StatusInvalid:
		// The session was revoked or expired between capture and replay.
		return telemetry.OutcomeBlocked
	default:
		return telemetry.OutcomeFailed
	}
}

// emitReplay records one replay-stage event per validation result.
// SessionReference is already a truncated SHA-256 digest of the session ID
// (see baseResult in types.go), never the session ID itself, so it is safe
// to carry. Identity.Username and TenantID are deliberately excluded: they
// are recipient identity, allowlisted for the webhook payload but not
// needed by the resilience report.
func (worker *Worker) emitReplay(result Result) {
	if worker.config.Emitter == nil {
		return
	}
	worker.config.Emitter.Emit(
		telemetry.New(telemetry.StageReplay, replayOutcome(result.Status), telemetry.TechniqueWebSessionCookie).
			WithActor(telemetry.Actor{Organization: result.Identity.Organization}).
			WithDetail("session_reference", result.SessionReference).
			WithDetail("phishlet", result.Phishlet).
			WithDetail("target_host", result.TargetHost).
			WithDetail("http_status", result.HTTPStatus),
	)
}

// Close stops new events, drains queued work, and waits for workers. It
// cannot fail: nothing on the shutdown path performs I/O of its own, and
// worker.process errors are per-job results delivered through OnResult, not
// worker-level failures, so there is nothing for Close to report.
func (worker *Worker) Close() {
	if worker == nil {
		return
	}
	worker.closeOnce.Do(func() {
		worker.acceptMu.Lock()
		worker.accepting = false
		worker.acceptMu.Unlock()
		close(worker.shutdown)
		worker.wg.Wait()
	})
}
