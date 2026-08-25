// Package campaigndb persists telemetry events to the campaign database,
// which is the store of record for the engagement event stream.
package campaigndb

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// row mirrors the telemetry_events table.
type row struct {
	ID         int64     `gorm:"column:id;primary_key"`
	EventID    string    `gorm:"column:event_id"`
	Timestamp  time.Time `gorm:"column:timestamp"`
	Stage      string    `gorm:"column:stage"`
	Outcome    string    `gorm:"column:outcome"`
	Techniques string    `gorm:"column:techniques"`
	CampaignID int64     `gorm:"column:campaign_id"`
	RID        string    `gorm:"column:rid"`
	Actor      string    `gorm:"column:actor"`
	Detail     string    `gorm:"column:detail"`
}

func (row) TableName() string { return "telemetry_events" }

// Sink writes events to the campaign database.
type Sink struct {
	db *gorm.DB
}

// New returns a sink backed by an open campaign database handle. The sink
// does not own the handle and does not close it.
func New(db *gorm.DB) *Sink { return &Sink{db: db} }

// Emit persists one event. The context bounds nothing today because gorm v1
// predates context support; it is accepted to satisfy telemetry.Sink and to
// leave room for a context-aware driver later.
func (s *Sink) Emit(_ context.Context, event telemetry.Event) error {
	return Insert(s.db, event)
}

// Insert writes one event through the given handle using this package's row
// mapping. It exists so a caller that must serialize writes through its own
// queue — campaignstore's telemetry sink, which owns the Store's single
// writer goroutine against the campaign database — can reuse the mapping
// without duplicating it or going through a second Sink that would own (and
// therefore contend on) its own handle.
func Insert(db *gorm.DB, event telemetry.Event) error {
	actor, err := json.Marshal(event.Actor)
	if err != nil {
		return err
	}
	detail := ""
	if len(event.Detail) > 0 {
		encoded, marshalErr := json.Marshal(event.Detail)
		if marshalErr != nil {
			return marshalErr
		}
		detail = string(encoded)
	}
	return db.Create(&row{
		EventID:    event.ID,
		Timestamp:  event.Timestamp,
		Stage:      string(event.Stage),
		Outcome:    string(event.Outcome),
		Techniques: joinTechniques(event.Techniques),
		CampaignID: event.CampaignID,
		RID:        event.RID,
		Actor:      string(actor),
		Detail:     detail,
	}).Error
}

// Close is a no-op: the database handle is owned by the caller.
func (s *Sink) Close() error { return nil }

func joinTechniques(techniques []telemetry.Technique) string {
	if len(techniques) == 0 {
		return ""
	}
	parts := make([]string, len(techniques))
	for i, technique := range techniques {
		parts[i] = string(technique)
	}
	return strings.Join(parts, ",")
}
