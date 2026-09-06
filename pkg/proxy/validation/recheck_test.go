package validation

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// scriptedValidator returns a preset status per attempt, so a test can say
// "valid, valid, then invalid" and assert what the worker did with it.
type scriptedValidator struct {
	mu       sync.Mutex
	statuses []Status
	calls    int
}

func (v *scriptedValidator) Validate(_ context.Context, _ Event) Result {
	v.mu.Lock()
	defer v.mu.Unlock()
	status := StatusValid
	if v.calls < len(v.statuses) {
		status = v.statuses[v.calls]
	} else if len(v.statuses) > 0 {
		status = v.statuses[len(v.statuses)-1]
	}
	v.calls++
	return Result{Status: status}
}

func (v *scriptedValidator) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

// collectingEmitter records every event the worker emits.
type collectingEmitter struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (e *collectingEmitter) Emit(event telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *collectingEmitter) snapshot() []telemetry.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]telemetry.Event, len(e.events))
	copy(out, e.events)
	return out
}

func (e *collectingEmitter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

func waitForCount(t *testing.T, want int, count func() int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if count() >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("got %d, want %d", count(), want)
		case <-time.After(time.Millisecond):
		}
	}
}

// testEvent builds a job captured just now, with one usable cookie domain.
func testEvent(sessionID string) Event {
	return Event{
		SessionID:  sessionID,
		Phishlet:   "example",
		TargetURL:  "https://login.example.com/",
		CapturedAt: time.Now().UTC(),
	}
}

// TestRecheckFollowsAStillValidSession is the measurement this exists for: a
// token that keeps working is checked again, so its observed lifetime grows
// instead of stopping at "it worked once".
func TestRecheckFollowsAStillValidSession(t *testing.T) {
	validator := &scriptedValidator{statuses: []Status{StatusValid, StatusValid, StatusValid}}
	emitter := &collectingEmitter{}
	worker, err := NewWorker(WorkerConfig{
		Workers:         1,
		Validator:       validator,
		Emitter:         emitter,
		RecheckSchedule: []time.Duration{time.Millisecond, 2 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	if err := worker.Enqueue(testEvent("session-1")); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, 3, emitter.count)

	events := emitter.snapshot()[:3]
	for i, event := range events {
		if event.Stage != telemetry.StageReplay {
			t.Errorf("event %d stage = %q, want %q", i, event.Stage, telemetry.StageReplay)
		}
		if got := event.Detail["attempt"]; got != int64(i+1) {
			t.Errorf("event %d attempt = %v, want %d (1-based)", i, got, i+1)
		}
		if _, ok := event.Detail["age_seconds"]; !ok {
			t.Errorf("event %d carries no age_seconds; without it a series of attempts is not a lifetime", i)
		}
	}
}

// TestRecheckStopsOnceTheTokenIsRefused pins the stopping rule. Once a token
// is refused there is nothing left to measure, and replaying a dead session
// would keep writing to the target's authentication logs for no gain.
func TestRecheckStopsOnceTheTokenIsRefused(t *testing.T) {
	validator := &scriptedValidator{statuses: []Status{StatusValid, StatusInvalid, StatusValid}}
	emitter := &collectingEmitter{}
	worker, err := NewWorker(WorkerConfig{
		Workers:         1,
		Validator:       validator,
		Emitter:         emitter,
		RecheckSchedule: []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	if err := worker.Enqueue(testEvent("session-2")); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, 2, emitter.count)
	time.Sleep(50 * time.Millisecond)

	if got := validator.count(); got != 2 {
		t.Errorf("validator called %d times, want 2: the schedule must stop at the first refusal", got)
	}
	events := emitter.snapshot()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[1].Outcome != telemetry.OutcomeBlocked {
		t.Errorf("second outcome = %q, want %q", events[1].Outcome, telemetry.OutcomeBlocked)
	}
}

// TestRecheckStopsOnAnInconclusiveAttempt covers the other stopping case: an
// error proves nothing about the token, and retrying through an outage would
// record a "lifetime" that describes the network rather than the session.
func TestRecheckStopsOnAnInconclusiveAttempt(t *testing.T) {
	validator := &scriptedValidator{statuses: []Status{StatusError, StatusValid}}
	emitter := &collectingEmitter{}
	worker, err := NewWorker(WorkerConfig{
		Workers:         1,
		Validator:       validator,
		Emitter:         emitter,
		RecheckSchedule: []time.Duration{time.Millisecond, 2 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	if err := worker.Enqueue(testEvent("session-3")); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, 1, emitter.count)
	time.Sleep(50 * time.Millisecond)

	if got := validator.count(); got != 1 {
		t.Errorf("validator called %d times, want 1", got)
	}
}

// TestNoRecheckScheduleKeepsSingleCheck pins that the original behavior is
// what an unconfigured worker still does.
func TestNoRecheckScheduleKeepsSingleCheck(t *testing.T) {
	validator := &scriptedValidator{statuses: []Status{StatusValid}}
	emitter := &collectingEmitter{}
	worker, err := NewWorker(WorkerConfig{Workers: 1, Validator: validator, Emitter: emitter})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	if err := worker.Enqueue(testEvent("session-4")); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, 1, emitter.count)
	time.Sleep(50 * time.Millisecond)

	if got := validator.count(); got != 1 {
		t.Errorf("validator called %d times, want 1 with no recheck schedule", got)
	}
}

// TestCloseCancelsPendingRechecks is the shutdown guarantee. A schedule
// reaching hours out must not hold shutdown open, and Close must return
// promptly rather than waiting for a timer nobody will service.
func TestCloseCancelsPendingRechecks(t *testing.T) {
	validator := &scriptedValidator{statuses: []Status{StatusValid}}
	emitter := &collectingEmitter{}
	worker, err := NewWorker(WorkerConfig{
		Workers:         1,
		Validator:       validator,
		Emitter:         emitter,
		RecheckSchedule: []time.Duration{time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := worker.Enqueue(testEvent("session-5")); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, 1, emitter.count)

	closed := make(chan struct{})
	go func() {
		worker.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return; a pending recheck held shutdown open")
	}
}

// TestRecheckScheduleIsSorted keeps an out-of-order configuration from
// producing a schedule that goes backwards in time.
func TestRecheckScheduleIsSorted(t *testing.T) {
	worker, err := NewWorker(WorkerConfig{
		Workers:         1,
		Validator:       &scriptedValidator{},
		RecheckSchedule: []time.Duration{time.Hour, time.Minute, time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	want := []time.Duration{time.Second, time.Minute, time.Hour}
	for i, delay := range worker.config.RecheckSchedule {
		if delay != want[i] {
			t.Errorf("schedule[%d] = %v, want %v", i, delay, want[i])
		}
	}
}

func TestRecheckScheduleRejectsNonPositiveDelays(t *testing.T) {
	_, err := NewWorker(WorkerConfig{
		Workers:         1,
		Validator:       &scriptedValidator{},
		RecheckSchedule: []time.Duration{time.Minute, -time.Second},
	})
	if err == nil {
		t.Fatal("NewWorker accepted a negative recheck delay")
	}
}
