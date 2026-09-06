package validation

import (
	"context"
	"errors"
	"fmt"
	"sort"
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
	// RecheckSchedule is the series of delays, measured from capture, at
	// which a session that is still valid is checked again. It covers
	// rechecks only -- the first check happens immediately on capture -- so
	// {5m, 30m, 2h} means four attempts in total. Empty means one check and
	// no more, which is the original behavior.
	//
	// Rechecking is what turns "the token worked once" into "the token
	// stayed usable for at least N hours", which is the number a defender
	// acts on: it is the window during which a stolen session was live, and
	// it is the only direct measurement of whether revocation actually
	// happened. Entries must be increasing; they are sorted if they are not.
	//
	// Schedules live only in memory. A proxy restarted mid-engagement loses
	// every pending recheck, so a session's observed lifetime is truncated
	// at the restart rather than continued. It is not persisted because a
	// resumed schedule would silently re-check sessions the operator may
	// have finished with; the report's censoring already handles a
	// truncated observation correctly.
	RecheckSchedule []time.Duration

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

	// timers holds the pending recheck timers so Close can stop them.
	// time.AfterFunc costs no goroutine until it fires, so one timer per
	// outstanding session is cheap; what it does need is cancellation, or a
	// shutdown would be held open by a recheck scheduled hours out.
	timerMu     sync.Mutex
	timers      map[int64]*time.Timer
	nextTimerID int64
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
	for _, delay := range config.RecheckSchedule {
		if delay <= 0 {
			return nil, fmt.Errorf("session validator recheck delays must be positive")
		}
	}
	if len(config.RecheckSchedule) > 1 {
		schedule := append([]time.Duration(nil), config.RecheckSchedule...)
		sort.Slice(schedule, func(i, j int) bool { return schedule[i] < schedule[j] })
		config.RecheckSchedule = schedule
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
		timers:    make(map[int64]*time.Timer),
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
	worker.emitReplay(result, event)
	worker.scheduleRecheck(event, result)
}

// scheduleRecheck arms the next attempt for a session that is still usable.
//
// Only a still-valid session is followed: once a token is refused there is
// nothing left to measure, and continuing to replay a dead session would be
// noise on the target's own authentication logs for no gain. A status of
// error or unknown also stops the schedule -- the attempt proved nothing, and
// retrying through an outage would record an arbitrary "lifetime" that
// reflects the network rather than the token.
func (worker *Worker) scheduleRecheck(event Event, result Result) {
	if result.Status != StatusValid {
		return
	}
	// The schedule covers rechecks only: attempt 0 is the immediate check on
	// capture, so attempt N takes its delay from schedule[N-1], and the
	// attempt just finished (event.Attempt) indexes the next one.
	if event.Attempt >= len(worker.config.RecheckSchedule) {
		return
	}

	// Delays are measured from capture, not from the previous attempt, so a
	// slow validation cannot drift the whole schedule later.
	delay := time.Until(event.CapturedAt.Add(worker.config.RecheckSchedule[event.Attempt]))
	if delay < 0 {
		delay = 0
	}

	event.Attempt++

	// The timer is created and registered under the same lock the callback
	// takes, so a delay short enough to fire immediately blocks in the
	// callback until registration finishes rather than racing it. The
	// callback closes over an id rather than the timer itself for the same
	// reason: assigning the timer to a variable the callback reads is the
	// classic version of this race.
	worker.timerMu.Lock()
	defer worker.timerMu.Unlock()
	if worker.timers == nil {
		// Close already ran; there is nothing left to schedule onto.
		return
	}
	id := worker.nextTimerID
	worker.nextTimerID++
	worker.timers[id] = time.AfterFunc(delay, func() {
		worker.forgetTimer(id)
		worker.requeue(event)
	})
}

func (worker *Worker) forgetTimer(id int64) {
	worker.timerMu.Lock()
	defer worker.timerMu.Unlock()
	delete(worker.timers, id)
}

// requeue puts a recheck back on the queue. It bypasses Enqueue on purpose:
// Enqueue's deduplication set exists to stop the same capture being validated
// twice, and a scheduled recheck is exactly the case that must be allowed
// through. A full queue drops the recheck rather than blocking -- the
// session's observed lifetime is then simply shorter than reality, which the
// report already treats as a lower bound.
func (worker *Worker) requeue(event Event) {
	worker.acceptMu.Lock()
	accepting := worker.accepting
	worker.acceptMu.Unlock()
	if !accepting {
		return
	}
	select {
	case worker.queue <- event:
	default:
	}
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
func (worker *Worker) emitReplay(result Result, event Event) {
	if worker.config.Emitter == nil {
		return
	}
	// age_seconds is how long after capture this attempt was made, which is
	// what turns a series of attempts into a measured token lifetime. attempt
	// is 1-based so a reader can tell the first replay -- the one that says
	// whether the target's own controls refused a stolen session outright --
	// from a later one.
	age := int64(result.Timestamp.Sub(event.CapturedAt).Seconds())
	if age < 0 {
		age = 0
	}
	worker.config.Emitter.Emit(
		telemetry.New(telemetry.StageReplay, replayOutcome(result.Status), telemetry.TechniqueWebSessionCookie).
			WithActor(telemetry.Actor{Organization: result.Identity.Organization}).
			WithDetail("session_reference", result.SessionReference).
			WithDetail("phishlet", result.Phishlet).
			WithDetail("target_host", result.TargetHost).
			WithDetail("http_status", result.HTTPStatus).
			WithDetail("attempt", event.Attempt+1).
			WithDetail("age_seconds", age),
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

		// Stop pending rechecks before waiting: a schedule reaching hours
		// out would otherwise keep firing into a queue nobody drains, and
		// setting timers to nil tells scheduleRecheck it is too late to arm
		// another one.
		worker.timerMu.Lock()
		pending := worker.timers
		worker.timers = nil
		worker.timerMu.Unlock()
		for _, timer := range pending {
			timer.Stop()
		}

		close(worker.shutdown)
		worker.wg.Wait()
	})
}
