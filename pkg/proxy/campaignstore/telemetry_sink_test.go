package campaignstore

import (
	"context"
	"sync"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// TestTelemetrySinkPersistsEventThroughStoreQueue proves telemetry inserts
// land in telemetry_events by way of the Store's own queue rather than a
// second database connection: TelemetrySink() is backed by the same *Store
// newTestStore builds, and nothing here opens a handle of its own.
func TestTelemetrySinkPersistsEventThroughStoreQueue(t *testing.T) {
	store := newTestStore(t)
	sink := store.TelemetrySink()

	event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked, telemetry.TechniqueProxy).
		WithActor(telemetry.Actor{IP: "203.0.113.9", ASN: "AS8075"}).
		WithDetail("rule", "network")

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit() = %v", err)
	}

	var row struct {
		EventID string
		Stage   string
		Outcome string
	}
	if err := store.db.Table("telemetry_events").Where("event_id = ?", event.ID).Scan(&row).Error; err != nil {
		t.Fatalf("read back inserted row: %v", err)
	}
	if row.EventID != event.ID {
		t.Fatalf("event_id = %q, want %q", row.EventID, event.ID)
	}
	if row.Stage != "cloak" || row.Outcome != "blocked" {
		t.Fatalf("stage/outcome = %q/%q, want cloak/blocked", row.Stage, row.Outcome)
	}
}

// TestTelemetrySinkCloseIsNoOp asserts the sink never touches the Store's
// database handle or shutdown sequence: calling Close on the sink must not
// stop the Store from continuing to accept and persist events.
func TestTelemetrySinkCloseIsNoOp(t *testing.T) {
	store := newTestStore(t)
	sink := store.TelemetrySink()

	if err := sink.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	event := telemetry.New(telemetry.StageVerify, telemetry.OutcomeAllowed)
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit() after sink Close() = %v, want the Store to remain usable", err)
	}
}

// TestTelemetrySinkSerializesConcurrentWrites is the single-writer
// guarantee itself: many goroutines calling Emit concurrently against one
// *gorm.DB handle must not race (run with -race) because every write is
// serialized through the Store's one worker goroutine, and every event
// must still land.
func TestTelemetrySinkSerializesConcurrentWrites(t *testing.T) {
	store := newTestStore(t)
	sink := store.TelemetrySink()

	const n = 50
	events := make([]telemetry.Event, n)
	for i := range events {
		events[i] = telemetry.New(telemetry.StageLure, telemetry.OutcomeAllowed)
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for _, event := range events {
		go func(event telemetry.Event) {
			defer wg.Done()
			if err := sink.Emit(context.Background(), event); err != nil {
				t.Errorf("Emit() = %v", err)
			}
		}(event)
	}
	wg.Wait()

	var count int
	if err := store.db.Table("telemetry_events").Count(&count).Error; err != nil {
		t.Fatalf("count telemetry_events: %v", err)
	}
	if count != n {
		t.Fatalf("count = %d, want %d", count, n)
	}
}
