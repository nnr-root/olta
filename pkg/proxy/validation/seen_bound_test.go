package validation_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/s4l1hs/olta/pkg/proxy/validation"
)

// TestWorkerSeenSetIsBounded proves the deduplication set cannot grow
// without bound over a long-running engagement. Before this fix, Enqueue
// added every session ID it accepted to a map and nothing ever removed an
// entry -- confirmed by reading worker.go, where the only write to seen was
// the insert in Enqueue and no delete existed anywhere in the package.
//
// This test enqueues far more distinct session IDs than SeenCapacity, all
// of which succeed (a large QueueSize keeps every Enqueue call from ever
// hitting ErrQueueFull, so success/failure here is governed only by the
// seen set's own capacity logic, not by consumption speed). It then checks
// both sides of the bound:
//   - a session ID enqueued long enough ago must have been evicted, so
//     re-enqueuing it must succeed instead of returning ErrDuplicateEvent
//     -- proof old entries are actually forgotten, not retained forever.
//   - a session ID enqueued recently (within the last SeenCapacity inserts)
//     must still be rejected as a duplicate -- proof the fix didn't trade
//     the unbounded leak for broken deduplication.
func TestWorkerSeenSetIsBounded(t *testing.T) {
	const capacity = 8
	const totalSessions = capacity * 20

	worker, err := validation.NewWorker(validation.WorkerConfig{
		Workers:      1,
		QueueSize:    totalSessions + 1,
		SeenCapacity: capacity,
		Validator:    statusValidator{status: validation.StatusValid},
	})
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	defer worker.Close()

	for i := 0; i < totalSessions; i++ {
		sessionID := fmt.Sprintf("session-%04d", i)
		if err := worker.Enqueue(testEvent(sessionID)); err != nil {
			t.Fatalf("Enqueue(%q) error = %v, want success", sessionID, err)
		}
	}

	// The very first session ID is far older than `capacity` insertions
	// back, so a bounded set must have evicted it by now: re-enqueueing it
	// must succeed rather than report a duplicate.
	evictedID := fmt.Sprintf("session-%04d", 0)
	if err := worker.Enqueue(testEvent(evictedID)); err != nil {
		t.Fatalf("Enqueue(%q) after eviction window error = %v, want success proving the entry was forgotten (bound holds)", evictedID, err)
	}

	// The most recently inserted session ID is still well within the
	// capacity window, so deduplication must still catch it.
	recentID := fmt.Sprintf("session-%04d", totalSessions-1)
	if err := worker.Enqueue(testEvent(recentID)); !errors.Is(err, validation.ErrDuplicateEvent) {
		t.Fatalf("Enqueue(%q) error = %v, want ErrDuplicateEvent (recent entries must still dedupe)", recentID, err)
	}
}

// TestWorkerRejectsNonPositiveSeenCapacity verifies NewWorker validates
// SeenCapacity the same way it validates Workers and QueueSize, so a
// caller cannot accidentally disable the bound with a negative value.
func TestWorkerRejectsNonPositiveSeenCapacity(t *testing.T) {
	_, err := validation.NewWorker(validation.WorkerConfig{
		SeenCapacity: -1,
		Validator:    statusValidator{status: validation.StatusValid},
	})
	if err == nil {
		t.Fatal("NewWorker with a negative SeenCapacity must fail")
	}
}
