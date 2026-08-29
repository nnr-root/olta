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

// WorkerConfig controls queue capacity, concurrency, and time limits.
type WorkerConfig struct {
	Workers           int
	QueueSize         int
	ValidationTimeout time.Duration
	Validator         Validator
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
	seen      map[string]struct{}
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
	if config.Workers < 1 || config.QueueSize < 1 {
		return nil, fmt.Errorf("session validator workers and queue size must be positive")
	}
	if config.ValidationTimeout <= 0 {
		return nil, fmt.Errorf("session validator timeouts must be positive")
	}
	if config.Validator == nil {
		config.Validator = NewHTTPValidator(nil)
	}
	worker := &Worker{
		config:    config,
		queue:     make(chan Event, config.QueueSize),
		accepting: true,
		seen:      make(map[string]struct{}),
		shutdown:  make(chan struct{}),
	}
	worker.wg.Add(config.Workers)
	for range config.Workers {
		go worker.run()
	}
	return worker, nil
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
			worker.seen[event.SessionID] = struct{}{}
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
