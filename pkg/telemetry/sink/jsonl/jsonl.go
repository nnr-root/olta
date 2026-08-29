// Package jsonl appends telemetry events to a newline-delimited JSON file.
// It is the substrate for offline export and post-engagement analysis.
package jsonl

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Sink appends one JSON object per line. Writes are serialized so the file
// stays parseable when the bus drains concurrently with a manual rotation.
type Sink struct {
	mu   sync.Mutex
	file *os.File
}

// New opens the file for append, creating it when absent. The mode is
// deliberately 0o600: a telemetry log records who was targeted and when,
// and must not be world-readable on a shared host.
func New(path string) (*Sink, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Sink{file: file}, nil
}

// Emit appends one event.
func (s *Sink) Emit(_ context.Context, event telemetry.Event) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	_, err = s.file.Write(encoded)
	return err
}

// Close flushes and closes the file. It is idempotent.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
