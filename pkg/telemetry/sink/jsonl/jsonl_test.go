package jsonl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

func TestSinkAppendsOneLinePerEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")
	sink, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		event := telemetry.New(telemetry.StageLure, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink)
		if err := sink.Emit(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("wrote %d lines, want 3", len(lines))
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d is not valid JSON: %s", i, line)
		}
	}
}

func TestSinkReopensWithoutTruncating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")

	first, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Emit(context.Background(), telemetry.New(telemetry.StageLure, telemetry.OutcomeAllowed)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Emit(context.Background(), telemetry.New(telemetry.StageCapture, telemetry.OutcomeCaptured)); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(raw)), "\n")); got != 2 {
		t.Fatalf("file has %d lines after reopen, want 2 — the sink truncated", got)
	}
}

// TestSinkFileModeIsOwnerOnly guards the deliberate 0o600 permission: a
// telemetry log records who was targeted and when, and must not be
// world-readable on a shared host.
func TestSinkFileModeIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")
	sink, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("file mode = %o, want 0600", mode)
	}
}
