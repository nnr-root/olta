# Purple-Team Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit one ATT&CK-tagged event at every decision point across the proxy, campaign, and feed services, and surface a per-campaign resilience report built from that stream.

**Architecture:** A new `pkg/telemetry` package defines a single `Event` type, a nil-safe `Emitter` interface that middleware depends on, and a bounded non-blocking `Bus` that fans out to `Sink` implementations. The campaign database is the store of record via a new `telemetry_events` table (migration 006). Emission points are added at nine stages; the resilience report reads back from that table.

**Tech Stack:** Go 1.22, `jinzhu/gorm` v1 (campaign DB access), `database/sql` (migrations), `gorilla/mux` (API routing), stdlib `crypto/rand` and `encoding/json`. No new module dependencies.

**Spec:** `docs/superpowers/specs/2026-08-24-purple-team-telemetry-design.md`

## Global Constraints

- Module path is `github.com/s4l1hs/olta`. All internal imports use it.
- Go 1.22. Handle every error explicitly. Preserve concurrent WebSocket and goroutine behavior.
- **No new module dependencies.** The spec names ULID for `Event.ID`; this plan uses a 128-bit `crypto/rand` hex string instead, to avoid adding `oklog/ulid`. Chronological ordering comes from the indexed `timestamp` column, not from the ID. This is a deliberate deviation from the spec — if you want true ULID ordering later, it is a one-function change in `pkg/telemetry/event.go`.
- **The no-loot invariant:** an `Event` must never carry captured credentials, cookies, or tokens. Task 1's `TestEventCarriesNoLoot` enforces this and must never be deleted or weakened.
- **Emission must never block or fail a request path.** Every `Emit` call is fire-and-forget. A full queue drops and counts; it never blocks and never returns an error to a caller on the request path.
- Domain vocabulary (`phishlet`, `lure`, `victim`, `rid`, `evilginx`) is preserved exactly. Do not sanitize these names.
- Preserve existing behavior: every currently-passing test must still pass. Run `go test ./...` before every commit.
- `migrations.CurrentVersion` is currently `5` (migration 005 is in-flight secret-storage work). This plan adds 006 and bumps to `6`. Do not modify 001–005.

---

### Task 1: Event model and the no-loot invariant

**Files:**
- Create: `pkg/telemetry/event.go`
- Test: `pkg/telemetry/event_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `telemetry.Event` struct; `telemetry.Stage` and `telemetry.Outcome` string types with constants `StageDelivery`, `StageOpen`, `StageLure`, `StageCloak`, `StageVerify`, `StageCredential`, `StageCapture`, `StageReplay`, `StageReport` and `OutcomeAllowed`, `OutcomeBlocked`, `OutcomeRedirected`, `OutcomeCaptured`, `OutcomeFailed`; `telemetry.Actor` struct; `telemetry.Technique` string type with technique constants; `func telemetry.New(stage Stage, outcome Outcome, techniques ...Technique) Event`; `func (Event) WithCampaign(campaignID int64, rid string) Event`; `func (Event) WithActor(a Actor) Event`; `func (Event) WithDetail(key string, value any) Event`.

- [ ] **Step 1: Write the failing test**

Create `pkg/telemetry/event_test.go`:

```go
package telemetry

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestNewPopulatesIdentityAndTimestamp(t *testing.T) {
	event := New(StageCapture, OutcomeCaptured, TechniqueStealWebSessionCookie)
	if len(event.ID) != 32 {
		t.Fatalf("ID = %q, want 32 hex characters", event.ID)
	}
	if event.Timestamp.IsZero() {
		t.Fatal("Timestamp is zero")
	}
	if event.Stage != StageCapture || event.Outcome != OutcomeCaptured {
		t.Fatalf("stage/outcome = %q/%q", event.Stage, event.Outcome)
	}
	if len(event.Techniques) != 1 || event.Techniques[0] != TechniqueStealWebSessionCookie {
		t.Fatalf("Techniques = %v", event.Techniques)
	}
}

func TestNewGeneratesDistinctIDs(t *testing.T) {
	first := New(StageLure, OutcomeAllowed)
	second := New(StageLure, OutcomeAllowed)
	if first.ID == second.ID {
		t.Fatalf("duplicate ID %q", first.ID)
	}
}

func TestBuildersAreChainable(t *testing.T) {
	event := New(StageCloak, OutcomeBlocked, TechniqueProxy).
		WithCampaign(7, "abc123").
		WithActor(Actor{IP: "203.0.113.9", ASN: "AS8075", Organization: "Microsoft"}).
		WithDetail("rule", "network")

	if event.CampaignID != 7 || event.RID != "abc123" {
		t.Fatalf("campaign/rid = %d/%q", event.CampaignID, event.RID)
	}
	if event.Actor.ASN != "AS8075" {
		t.Fatalf("Actor.ASN = %q", event.Actor.ASN)
	}
	if event.Detail["rule"] != "network" {
		t.Fatalf("Detail = %v", event.Detail)
	}
}

// TestEventCarriesNoLoot is the load-bearing invariant of this package.
// An Event records the fact of a capture, never its contents. Do not delete
// or weaken this test: it is what allows telling a client that the telemetry
// stream is safe to forward to their SOC.
func TestEventCarriesNoLoot(t *testing.T) {
	const (
		password = "hunter2-SUPER-SECRET"
		cookie   = "ESTSAUTHPERSISTENT=AQABAAAAAAD-SECRET-TOKEN"
		apiKey   = "b4d1dea0000000000000000000000000"
	)

	// Every builder that accepts caller-supplied data is exercised here.
	// A new builder MUST be added to this list when it is introduced.
	events := []Event{
		New(StageCredential, OutcomeCaptured, TechniqueWebPortalCapture).
			WithCampaign(1, "rid-1").
			WithActor(Actor{IP: "203.0.113.5", UserAgent: "Mozilla/5.0"}).
			WithDetail("password", password),

		New(StageCapture, OutcomeCaptured, TechniqueStealWebSessionCookie).
			WithDetail("cookie", cookie).
			WithDetail("nested", map[string]string{"token": cookie}),

		New(StageReplay, OutcomeAllowed, TechniqueWebSessionCookie).
			WithDetail("Authorization", apiKey).
			WithDetail("api_key", apiKey),
	}

	for index, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("event %d: %v", index, err)
		}
		for _, secret := range []string{password, cookie, apiKey} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("event %d leaked %q into %s", index, secret, encoded)
			}
		}
	}
}

// TestEventCarriesNoLootAcrossValueShapes covers the bypasses a type-switch
// allowlist misses. Each case is a shape a proxy handler plausibly produces.
// These are regression tests for real leaks, not hypotheticals.
func TestEventCarriesNoLootAcrossValueShapes(t *testing.T) {
	const secret = "AQABAAAAAAD-SUPER-SECRET-VALUE"

	type credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	cases := []struct {
		name  string
		key   string
		value any
	}{
		// A named type over map[string][]string. A type switch never matches
		// a named type against its underlying type, so http.Header was the
		// original bypass.
		{"http.Header", "request_headers", http.Header{"Authorization": {secret}}},
		{"url.Values", "form", url.Values{"password": {secret}}},

		// Underlying map type that is not one of the switch's exact cases.
		{"map of string slice", "headers", map[string][]string{"cookie": {secret}}},

		// []map[string]any is not []any.
		{"slice of maps", "fields", []map[string]any{{"password": secret}}},

		// A struct never matched at all.
		{"struct", "identity", credentials{Username: "victim", Password: secret}},
		{"pointer to struct", "identity_ptr", &credentials{Password: secret}},

		// Key spellings that exact-equality matching missed.
		{"hyphenated key", "Set-Cookie", secret},
		{"suffixed key", "session_id", secret},
		{"prefixed key", "x_auth_token", secret},
		{"short spelling", "pwd", secret},
		{"bearer", "bearer", secret},
		{"otp", "otp_code", secret},

		// Loot nested under a wholly innocuous outer key.
		{"innocuous outer key", "payload", map[string]any{"nested": map[string]any{"token": secret}}},
		{"innocuous outer, struct inner", "context", credentials{Password: secret}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			event := New(StageCapture, OutcomeCaptured).WithDetail(testCase.key, testCase.value)
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("leaked %q into %s", secret, encoded)
			}
		})
	}
}

// TestWithDetailDoesNotShareDetailMap pins the copy-on-write contract.
// Without it, every event derived from a populated base shares one map, and
// two goroutines extending that base write it concurrently — a fatal runtime
// error that kills the process, not a recoverable request failure.
func TestWithDetailDoesNotShareDetailMap(t *testing.T) {
	base := New(StageLure, OutcomeAllowed).WithDetail("stage", "lure")

	first := base.WithDetail("branch", "one")
	second := base.WithDetail("branch", "two")

	if first.Detail["branch"] != "one" || second.Detail["branch"] != "two" {
		t.Fatalf("branches share a map: first=%v second=%v", first.Detail, second.Detail)
	}
	if _, present := base.Detail["branch"]; present {
		t.Fatalf("base was mutated by a derived event: %v", base.Detail)
	}
}

// Run with -race. Before copy-on-write this failed as a data race, and in
// production as "fatal error: concurrent map writes".
func TestWithDetailIsRaceSafeFromSharedBase(t *testing.T) {
	base := New(StageCapture, OutcomeCaptured).WithDetail("stage", "capture")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = base.WithDetail("worker", n)
		}(i)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/telemetry/ -run TestEvent -v`
Expected: FAIL — the package does not compile, `undefined: New`, `undefined: StageCapture`.

- [ ] **Step 3: Write the implementation**

Create `pkg/telemetry/event.go`:

```go
// Package telemetry defines the ATT&CK-tagged event stream shared by the
// Olta proxy, campaign, and feed services.
//
// An Event records that something happened during an engagement: which
// kill-chain stage, what the outcome was, which ATT&CK technique it
// emulates, and who the actor was. An Event never carries captured
// credentials, cookies, or tokens. Captured material stays in the campaign
// database behind pkg/campaign/secrets. This separation is what makes the
// stream safe to forward to a defender's SOC, and it is enforced by
// TestEventCarriesNoLoot.
package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Stage identifies a point in the engagement kill chain.
type Stage string

const (
	StageDelivery   Stage = "delivery"
	StageOpen       Stage = "open"
	StageLure       Stage = "lure"
	StageCloak      Stage = "cloak"
	StageVerify     Stage = "verify"
	StageCredential Stage = "credential"
	StageCapture    Stage = "capture"
	StageReplay     Stage = "replay"
	StageReport     Stage = "report"
)

// Outcome describes how a stage resolved.
type Outcome string

const (
	OutcomeAllowed    Outcome = "allowed"
	OutcomeBlocked    Outcome = "blocked"
	OutcomeRedirected Outcome = "redirected"
	OutcomeCaptured   Outcome = "captured"
	OutcomeFailed     Outcome = "failed"
)

// Technique is a MITRE ATT&CK technique identifier.
type Technique string

const (
	TechniqueSpearphishingLink     Technique = "T1566.002"
	TechniqueProxy                 Technique = "T1090"
	TechniqueSandboxEvasion        Technique = "T1497"
	TechniqueWebPortalCapture      Technique = "T1056.003"
	TechniqueStealWebSessionCookie Technique = "T1539"
	TechniqueWebSessionCookie      Technique = "T1550.004"
)

// Actor describes the request source. Every field is non-sensitive by
// construction: these are network and client attributes, never credentials.
type Actor struct {
	IP           string `json:"ip,omitempty"`
	ASN          string `json:"asn,omitempty"`
	Organization string `json:"organization,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	Country      string `json:"country,omitempty"`
	ClientProfile string `json:"client_profile,omitempty"`
}

// Event is one tagged observation. CampaignID and RID are optional: cloak
// and verify events fire before lure validation establishes a recipient
// identity, so they carry neither.
type Event struct {
	ID         string         `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	Stage      Stage          `json:"stage"`
	Outcome    Outcome        `json:"outcome"`
	Techniques []Technique    `json:"techniques,omitempty"`
	CampaignID int64          `json:"campaign_id,omitempty"`
	RID        string         `json:"rid,omitempty"`
	Actor      Actor          `json:"actor"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// New builds an event with a fresh identity and the current UTC time.
func New(stage Stage, outcome Outcome, techniques ...Technique) Event {
	return Event{
		ID:         newID(),
		Timestamp:  time.Now().UTC(),
		Stage:      stage,
		Outcome:    outcome,
		Techniques: append([]Technique(nil), techniques...),
	}
}

// WithCampaign attaches recipient correlation.
func (e Event) WithCampaign(campaignID int64, rid string) Event {
	e.CampaignID = campaignID
	e.RID = rid
	return e
}

// WithActor attaches request-source attributes.
func (e Event) WithActor(actor Actor) Event {
	e.Actor = actor
	return e
}

// WithDetail attaches one stage-specific attribute.
//
// Callers must never pass captured credentials, cookies, or tokens. Values
// are redacted on the way in rather than trusted: see redactValue.
//
// Detail is a map, so a plain value-receiver copy would share it with every
// event derived from the same base. Two goroutines extending one populated
// base event would then write the same map concurrently, which is a fatal
// runtime error rather than a recoverable one. The map is therefore copied
// on every call, making the builder genuinely value-semantic.
func (e Event) WithDetail(key string, value any) Event {
	detail := make(map[string]any, len(e.Detail)+1)
	for k, v := range e.Detail {
		detail[k] = v
	}
	detail[key] = redactValue(key, canonical(value))
	e.Detail = detail
	return e
}

// lootMarkers are substrings that mark a detail key as carrying loot. Keys
// are matched by substring, not equality: "set_cookie", "session_id", and
// "x_auth_token" must all redact, and no fixed list of exact spellings
// survives contact with real callers.
var lootMarkers = []string{
	"password", "passwd", "pwd", "secret", "token", "cookie",
	"credential", "api_key", "apikey", "auth", "bearer",
	"session", "otp", "mfa", "signature", "private",
}

const redacted = "[redacted]"

// canonical collapses an arbitrary value into the shapes redactValue can
// walk: map[string]any, []any, or a scalar.
//
// A Go type switch matches only exact dynamic types, so http.Header and
// url.Values — named types whose underlying type is map[string][]string —
// never match a map[string][]string case, and a struct carrying a secret in
// a JSON-tagged field never matches at all. Round-tripping through JSON
// erases those distinctions: every map becomes map[string]any, every slice
// and array becomes []any, pointers are dereferenced, structs become maps
// keyed by their JSON field names, and json.RawMessage is decoded.
//
// A value that cannot be marshalled cannot reach the wire either, so it is
// replaced with a type marker rather than passed through unexamined.
func canonical(value any) any {
	switch value.(type) {
	case nil, string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return value
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("[unencodable %T]", value)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return fmt.Sprintf("[unencodable %T]", value)
	}
	return decoded
}

// redactValue strips loot by key name, recursing into the canonical shapes
// so a nested secret cannot ride along inside a composite value under an
// innocuous outer key.
func redactValue(key string, value any) any {
	if isLootKey(key) {
		return redacted
	}
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = redactValue(k, v)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			// Slice elements inherit the enclosing key: a list under
			// "cookies" is loot even though its indices have no names.
			out[i] = redactValue(key, v)
		}
		return out
	default:
		return value
	}
}

func isLootKey(key string) bool {
	normalized := normalizeKey(key)
	for _, marker := range lootMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func normalizeKey(key string) string {
	lowered := make([]byte, 0, len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z':
			lowered = append(lowered, c+('a'-'A'))
		case c == '-' || c == ' ':
			lowered = append(lowered, '_')
		default:
			lowered = append(lowered, c)
		}
	}
	return string(lowered)
}

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("telemetry: secure random id generation failed: %v", err))
	}
	return hex.EncodeToString(buffer)
}
```

The third case exercises key normalization: `"Authorization"` must redact despite its capital A, and `"api_key"` must redact as a distinct spelling from `"apikey"`. Both are in `lootKeys` after `normalizeKey` lowercases them.

`Actor` is deliberately outside this test's scope. Its fields are non-sensitive by construction — IP, ASN, organization, user agent — so a caller putting loot in `Actor` is a caller bug, not something the type defends against. Do not add redaction to `Actor`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/telemetry/ -v`
Expected: PASS — all four tests.

- [ ] **Step 5: Verify nothing else broke and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/telemetry/event.go pkg/telemetry/event_test.go
git commit -m "feat(telemetry): add ATT&CK-tagged event model with no-loot invariant"
```

---

### Task 2: The bus and the Sink interface

**Files:**
- Create: `pkg/telemetry/bus.go`
- Test: `pkg/telemetry/bus_test.go`

**Interfaces:**
- Consumes: `telemetry.Event` from Task 1.
- Produces: `type Sink interface { Emit(context.Context, Event) error; Close() error }`; `type Emitter interface { Emit(Event) }`; `func NewBus(queueSize int, sinks ...Sink) *Bus`; `func (*Bus) Emit(Event)`; `func (*Bus) Dropped() uint64`; `func (*Bus) Close() error`. `*Bus` satisfies `Emitter`. A nil `*Bus` is safe to call.

- [ ] **Step 1: Write the failing test**

Create `pkg/telemetry/bus_test.go`:

```go
package telemetry

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

type recordingSink struct {
	mu     sync.Mutex
	events []Event
	block  chan struct{}
	closed bool
}

func (s *recordingSink) Emit(_ context.Context, event Event) error {
	if s.block != nil {
		<-s.block
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *recordingSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func TestBusDeliversToEverySink(t *testing.T) {
	first, second := &recordingSink{}, &recordingSink{}
	bus := NewBus(8, first, second)

	bus.Emit(New(StageLure, OutcomeAllowed, TechniqueSpearphishingLink))
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}

	if first.count() != 1 || second.count() != 1 {
		t.Fatalf("counts = %d/%d, want 1/1", first.count(), second.count())
	}
	if !first.closed || !second.closed {
		t.Fatal("Close() did not reach every sink")
	}
}

// A stalled sink must never block a caller on the request path.
func TestBusEmitNeverBlocksOnStalledSink(t *testing.T) {
	release := make(chan struct{})
	sink := &recordingSink{block: release}
	bus := NewBus(2, sink)
	defer func() { close(release); _ = bus.Close() }()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			bus.Emit(New(StageCloak, OutcomeBlocked, TechniqueProxy))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked while a sink was stalled")
	}

	if bus.Dropped() == 0 {
		t.Fatal("Dropped() = 0, want overflow to be counted")
	}
}

func TestNilBusIsSafe(t *testing.T) {
	var bus *Bus
	bus.Emit(New(StageVerify, OutcomeAllowed))
	if got := bus.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d", got)
	}
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBusCloseIsIdempotent(t *testing.T) {
	bus := NewBus(4, &recordingSink{})
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bus.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	bus.Emit(New(StageReport, OutcomeAllowed)) // must not panic on a closed bus
}

// TestBusEmitDuringCloseDoesNotPanic covers the dangerous interleaving:
// Emit checking "closed" and then sending, while Close closes the queue
// between those two steps. Sending on a closed channel panics
// unconditionally — a select's default case does not catch it — and that
// panic would occur on a proxy request goroutine during graceful shutdown.
//
// Run with -race -count=20. A sequential close-then-emit test does not
// exercise this; only concurrent Emit and Close do.
func TestBusEmitDuringCloseDoesNotPanic(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		bus := NewBus(4, &recordingSink{})

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				bus.Emit(New(StageLure, OutcomeAllowed))
				runtime.Gosched()
			}
		}()

		go func() {
			defer wg.Done()
			runtime.Gosched()
			_ = bus.Close()
		}()

		wg.Wait() // a panic in either goroutine fails the test binary
	}
}

// TestBusCloseReturnsWhenSinkIgnoresContext pins the shutdown guarantee.
// The campaign database sink ignores its context (gorm v1 predates context
// support), so Close must still return rather than block on wg.Wait()
// forever.
func TestBusCloseReturnsWhenSinkIgnoresContext(t *testing.T) {
	original := sinkTimeout
	sinkTimeout = 200 * time.Millisecond
	defer func() { sinkTimeout = original }()

	release := make(chan struct{})
	defer close(release)

	bus := NewBus(4, &recordingSink{block: release})
	bus.Emit(New(StageCapture, OutcomeCaptured))

	done := make(chan error, 1)
	go func() { done <- bus.Close() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() blocked on a sink that ignores its context")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/telemetry/ -run TestBus -v`
Expected: FAIL — `undefined: NewBus`.

- [ ] **Step 3: Write the implementation**

Create `pkg/telemetry/bus.go`:

```go
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

// sinkTimeout bounds one sink write so a wedged sink cannot stall the drain
// goroutine — and therefore Close — forever. It is a var, not a const, so
// the shutdown test can shorten it rather than sleeping for the real value.
var sinkTimeout = 10 * time.Second

// Bus fans one event out to every sink from a dedicated goroutine.
//
// Emit never blocks and never fails. When the queue is full the event is
// dropped and counted, because dropping telemetry is always preferable to
// delaying a victim-facing request. This mirrors the non-blocking broadcast
// already used by the feed hub.
type Bus struct {
	sinks []Sink
	queue chan Event

	// mu makes the closed-check and the queue send atomic with respect to
	// Close. Without it, Emit can pass its closed-check, Close can then
	// close the queue, and Emit's send panics on a closed channel — an
	// unconditional panic that a select's default case does not catch.
	// Emit holds the read lock (uncontended in the steady state) and Close
	// takes the write lock, so the two can never interleave.
	mu     sync.RWMutex
	closed bool

	once sync.Once
	wg   sync.WaitGroup

	dropped atomic.Uint64
}

// NewBus starts the drain goroutine. A queueSize below 1 is raised to 1.
// With no sinks the bus is a no-op that still satisfies Emitter.
func NewBus(queueSize int, sinks ...Sink) *Bus {
	if queueSize < 1 {
		queueSize = 1
	}
	bus := &Bus{
		sinks: sinks,
		queue: make(chan Event, queueSize),
	}
	bus.wg.Add(1)
	go bus.drain()
	return bus
}

// Emit queues an event. Safe on a nil or closed bus, and safe to call
// concurrently with Close.
//
// The read lock is held across both the closed-check and the send. It is
// uncontended except during the instant Close holds the write lock, and the
// send itself is non-blocking, so Emit remains fire-and-forget.
func (b *Bus) Emit(event Event) {
	if b == nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
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
		b.mu.Lock()
		b.closed = true
		close(b.queue)
		b.mu.Unlock()

		b.wg.Wait()
		for _, sink := range b.sinks {
			if closeErr := sink.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
	})
	return err
}

// drain delivers each queued event to every sink. Closing the queue does not
// discard buffered events: range yields all of them before the loop exits,
// so Close flushes rather than truncates.
func (b *Bus) drain() {
	defer b.wg.Done()
	for event := range b.queue {
		for _, sink := range b.sinks {
			emitTo(sink, event)
		}
	}
}

// emitTo bounds one sink write in wall-clock time, not merely by context.
//
// A context deadline only binds a sink that selects on ctx.Done(). The
// campaign database sink cannot: gorm v1 predates context support and its
// calls are synchronous. Passing the context alone would leave a wedged
// database write able to block drain forever, which in turn blocks Close's
// wg.Wait() forever, hanging graceful shutdown.
//
// Running the call on its own goroutine and abandoning it at the deadline
// costs at most one leaked goroutine per wedged write, and buys a Close that
// always returns. That is the right trade for a shutdown path.
func emitTo(sink Sink, event Event) {
	ctx, cancel := context.WithTimeout(context.Background(), sinkTimeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A sink failure must not stop other sinks or the drain loop.
		// Sinks log their own failures.
		_ = sink.Emit(ctx, event)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/telemetry/ -race -v`
Expected: PASS — all tests from Tasks 1 and 2, clean under the race detector.

- [ ] **Step 5: Verify nothing else broke and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/telemetry/bus.go pkg/telemetry/bus_test.go
git commit -m "feat(telemetry): add non-blocking fan-out bus and Sink interface"
```

---

### Task 3: Migration 006 — the telemetry_events table

**Files:**
- Create: `pkg/campaign/migrations/sqlite/006_telemetry_events.sql`
- Create: `pkg/campaign/migrations/mysql/006_telemetry_events.sql`
- Modify: `pkg/campaign/migrations/migrations.go` (`CurrentVersion` at line 11, embed block, `requiredSchema`, `legacyRequiredSchema`, `migrationFor`)
- Test: `pkg/campaign/migrations/migrations_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: table `telemetry_events` with columns `id`, `event_id`, `timestamp`, `stage`, `outcome`, `techniques`, `campaign_id`, `rid`, `actor`, `detail`. `migrations.CurrentVersion == 6`.

- [ ] **Step 1: Write the failing test**

Read the existing test file first to match its style: `pkg/campaign/migrations/migrations_test.go`. Append:

```go
func TestTelemetryEventsTableExistsOnFreshInstall(t *testing.T) {
	db := newTestDB(t) // reuse the existing helper in this file
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version = %d, want %d", version, CurrentVersion)
	}
	if CurrentVersion != 6 {
		t.Fatalf("CurrentVersion = %d, want 6", CurrentVersion)
	}

	for _, column := range []string{
		"event_id", "timestamp", "stage", "outcome",
		"techniques", "campaign_id", "rid", "actor", "detail",
	} {
		var count int
		query := "SELECT COUNT(*) FROM pragma_table_info('telemetry_events') WHERE name = ?"
		if err := db.QueryRow(query, column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("telemetry_events is missing column %q", column)
		}
	}
}

func TestTelemetryEventsUpgradeFromVersionFive(t *testing.T) {
	db := newTestDB(t)
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	// Rewind to v5 and drop the new table to simulate a pre-006 database.
	if _, err := db.Exec("DROP TABLE telemetry_events"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 5); err != nil {
		t.Fatal(err)
	}

	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("upgrade v5 to v6: %v", err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != 6 {
		t.Fatalf("version after upgrade = %d, want 6", version)
	}
}
```

If `newTestDB` does not exist in the file under that name, use whatever fixture helper the existing tests use — read the file's first 40 lines to find it.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/campaign/migrations/ -run TestTelemetryEvents -v`
Expected: FAIL — `CurrentVersion = 5, want 6`, and no such table `telemetry_events`.

- [ ] **Step 3: Write the migrations**

Create `pkg/campaign/migrations/sqlite/006_telemetry_events.sql`:

```sql
CREATE TABLE IF NOT EXISTS telemetry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id VARCHAR(32) NOT NULL,
    timestamp DATETIME NOT NULL,
    stage VARCHAR(32) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    techniques VARCHAR(255),
    campaign_id BIGINT,
    rid VARCHAR(255),
    actor TEXT,
    detail TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_telemetry_events_event_id ON telemetry_events(event_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_campaign_id ON telemetry_events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_rid ON telemetry_events(rid);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_timestamp ON telemetry_events(timestamp);
```

Create `pkg/campaign/migrations/mysql/006_telemetry_events.sql`:

```sql
CREATE TABLE IF NOT EXISTS telemetry_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(32) NOT NULL,
    timestamp DATETIME NOT NULL,
    stage VARCHAR(32) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    techniques VARCHAR(255),
    campaign_id BIGINT,
    rid VARCHAR(255),
    actor TEXT,
    detail TEXT,
    UNIQUE KEY idx_telemetry_events_event_id (event_id),
    KEY idx_telemetry_events_campaign_id (campaign_id),
    KEY idx_telemetry_events_rid (rid),
    KEY idx_telemetry_events_timestamp (timestamp)
);
```

The same table must also be added to `001_initial_olta_schema.sql` for both dialects so a fresh install gets it without replaying migrations. Append the `CREATE TABLE` and its indexes to both 001 files, matching each file's existing style.

- [ ] **Step 4: Wire the migration into migrations.go**

In `pkg/campaign/migrations/migrations.go`:

Change line 11:
```go
const CurrentVersion = 6
```

After the 005 embed block, add:
```go
//go:embed sqlite/006_telemetry_events.sql
var sqliteTelemetryEvents string

//go:embed mysql/006_telemetry_events.sql
var mysqlTelemetryEvents string
```

In `requiredSchema`, add:
```go
"telemetry_events": {"id", "event_id", "timestamp", "stage", "outcome", "techniques", "campaign_id", "rid", "actor", "detail"},
```

In `legacyRequiredSchema`, the whole `telemetry_events` table must be skipped, exactly as `campaign_template_variants` already is. Change the existing skip:
```go
if table == "campaign_template_variants" || table == "telemetry_events" {
    continue
}
```
and update the map capacity hint from `len(requiredSchema)-1` to `len(requiredSchema)-2`.

In `migrationFor`, add before the dialect-check case:
```go
case dialect == "sqlite3" && version == 6:
    return sqliteTelemetryEvents, nil
case dialect == "mysql" && version == 6:
    return mysqlTelemetryEvents, nil
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/campaign/migrations/ -v`
Expected: PASS — the two new tests plus every existing migration test.

- [ ] **Step 6: Verify nothing else broke and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/campaign/migrations/
git commit -m "feat(migrations): add telemetry_events table as schema version 6"
```

---

### Task 4: The campaigndb sink

**Files:**
- Create: `pkg/telemetry/sink/campaigndb/campaigndb.go`
- Test: `pkg/telemetry/sink/campaigndb/campaigndb_test.go`

**Interfaces:**
- Consumes: `telemetry.Event`, `telemetry.Sink` (Tasks 1–2); the `telemetry_events` table (Task 3).
- Produces: `func campaigndb.New(db *gorm.DB) *Sink`; `*Sink` satisfies `telemetry.Sink`.

- [ ] **Step 1: Write the failing test**

Create `pkg/telemetry/sink/campaigndb/campaigndb_test.go`:

```go
package campaigndb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/s4l1hs/olta/pkg/campaign/migrations"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "telemetry.db")

	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(raw, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := gorm.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSinkPersistsEvent(t *testing.T) {
	db := newDB(t)
	sink := New(db)

	event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked, telemetry.TechniqueProxy).
		WithActor(telemetry.Actor{IP: "203.0.113.9", ASN: "AS8075", Organization: "Microsoft"}).
		WithDetail("rule", "network")

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	var row struct {
		EventID    string
		Stage      string
		Outcome    string
		Techniques string
		CampaignID int64
		Actor      string
	}
	if err := db.Table("telemetry_events").Where("event_id = ?", event.ID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Stage != "cloak" || row.Outcome != "blocked" {
		t.Fatalf("stage/outcome = %q/%q", row.Stage, row.Outcome)
	}
	if row.Techniques != "T1090" {
		t.Fatalf("techniques = %q, want T1090", row.Techniques)
	}
	if row.CampaignID != 0 {
		t.Fatalf("CampaignID = %d, want 0 for an unattributed cloak event", row.CampaignID)
	}
	if row.Actor == "" {
		t.Fatal("actor JSON was not persisted")
	}
}

func TestSinkPersistsMultipleTechniques(t *testing.T) {
	db := newDB(t)
	sink := New(db)

	event := telemetry.New(telemetry.StageCapture, telemetry.OutcomeCaptured,
		telemetry.TechniqueStealWebSessionCookie, telemetry.TechniqueWebSessionCookie)
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	var row struct{ Techniques string }
	if err := db.Table("telemetry_events").Where("event_id = ?", event.ID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Techniques != "T1539,T1550.004" {
		t.Fatalf("techniques = %q", row.Techniques)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/telemetry/sink/campaigndb/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write the implementation**

Create `pkg/telemetry/sink/campaigndb/campaigndb.go`:

```go
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
	return s.db.Create(&row{
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/telemetry/... -race -v`
Expected: PASS.

- [ ] **Step 5: Verify nothing else broke and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/telemetry/sink/
git commit -m "feat(telemetry): add campaign database sink"
```

---

### Task 5: Proxy bus wiring and the cloak stage

**Files:**
- Modify: `pkg/proxy/middleware/asncloak/asncloak.go` (add `Emitter` field to `Config`, emit in `Evaluate`)
- Modify: `cmd/olta-proxy/main.go` (construct the bus, pass the emitter, close on shutdown)
- Test: `pkg/proxy/middleware/asncloak/asncloak_emit_test.go`

**Interfaces:**
- Consumes: `telemetry.Emitter`, `telemetry.New`, `telemetry.StageCloak`, `telemetry.OutcomeBlocked`, `telemetry.OutcomeRedirected`, `telemetry.TechniqueProxy`, `telemetry.Actor` (Tasks 1–2); `campaigndb.New` (Task 4).
- Produces: `asncloak.Config.Emitter` field of type `telemetry.Emitter`. Cloak events in `telemetry_events`.

- [ ] **Step 1: Write the failing test**

Create `pkg/proxy/middleware/asncloak/asncloak_emit_test.go`:

```go
package asncloak

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

type captureEmitter struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (e *captureEmitter) Emit(event telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *captureEmitter) all() []telemetry.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]telemetry.Event(nil), e.events...)
}

func TestEvaluateEmitsBlockedCloakEvent(t *testing.T) {
	emitter := &captureEmitter{}
	middleware, err := New(Config{
		Enabled:        true,
		Action:         ActionBlock,
		BlockStatus:    404,
		InspectHeaders: true,
		Emitter:        emitter,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	request.Header.Set("User-Agent", "curl/8.4.0")
	request.RemoteAddr = "203.0.113.9:51234"

	if _, matched := middleware.Evaluate(request); !matched {
		t.Fatal("Evaluate() did not match a suspicious user agent")
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	event := events[0]
	if event.Stage != telemetry.StageCloak {
		t.Fatalf("Stage = %q", event.Stage)
	}
	if event.Outcome != telemetry.OutcomeBlocked {
		t.Fatalf("Outcome = %q, want blocked for ActionBlock", event.Outcome)
	}
	if len(event.Techniques) != 1 || event.Techniques[0] != telemetry.TechniqueProxy {
		t.Fatalf("Techniques = %v", event.Techniques)
	}
	if event.RID != "" || event.CampaignID != 0 {
		t.Fatal("cloak events fire before lure validation and must be unattributed")
	}
	if event.Detail["rule"] != "user-agent" {
		t.Fatalf("Detail = %v", event.Detail)
	}
}

func TestEvaluateEmitsRedirectOutcome(t *testing.T) {
	emitter := &captureEmitter{}
	middleware, err := New(Config{
		Enabled:        true,
		Action:         ActionRedirect,
		RedirectURL:    "https://www.google.com/",
		InspectHeaders: true,
		Emitter:        emitter,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	request.Header.Set("User-Agent", "python-requests/2.31.0")
	if _, matched := middleware.Evaluate(request); !matched {
		t.Fatal("Evaluate() did not match")
	}

	events := emitter.all()
	if len(events) != 1 || events[0].Outcome != telemetry.OutcomeRedirected {
		t.Fatalf("events = %+v, want one redirected outcome", events)
	}
}

func TestEvaluateEmitsNothingWhenRequestIsClean(t *testing.T) {
	emitter := &captureEmitter{}
	middleware, err := New(Config{Enabled: true, Action: ActionBlock, BlockStatus: 404, Emitter: emitter})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	if _, matched := middleware.Evaluate(request); matched {
		t.Fatal("clean request should not match")
	}
	if len(emitter.all()) != 0 {
		t.Fatal("a clean request must not emit a cloak event")
	}
}

func TestNilEmitterIsSafe(t *testing.T) {
	middleware, err := New(Config{Enabled: true, Action: ActionBlock, BlockStatus: 404, InspectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://lure.example/x", nil)
	request.Header.Set("User-Agent", "curl/8.4.0")
	if _, matched := middleware.Evaluate(request); !matched {
		t.Fatal("Evaluate() did not match")
	}
	// Reaching here without a panic is the assertion.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/proxy/middleware/asncloak/ -run TestEvaluateEmits -v`
Expected: FAIL — `unknown field Emitter in struct literal`.

- [ ] **Step 3: Add the Emitter to Config and emit from Evaluate**

In `pkg/proxy/middleware/asncloak/asncloak.go`, add the import and the field. Append to the `Config` struct (after `MissingHeaderLimit`):

```go
	// Emitter receives a cloak event for every match. Nil disables emission.
	Emitter telemetry.Emitter
```

Add to the import block: `"github.com/s4l1hs/olta/pkg/telemetry"`.

`Evaluate` currently returns from four separate places. Rather than duplicating emission at each, wrap the existing body. Rename the current method to `evaluate` (lowercase, unchanged logic) and add:

```go
// Evaluate returns the first network, user-agent, header, or protocol match,
// and emits a cloak event when one is found.
func (middleware *Middleware) Evaluate(request *http.Request) (Match, bool) {
	match, matched := middleware.evaluate(request)
	if matched {
		middleware.emitCloak(request, match)
	}
	return match, matched
}

func (middleware *Middleware) emitCloak(request *http.Request, match Match) {
	if middleware.config.Emitter == nil {
		return
	}

	outcome := telemetry.OutcomeBlocked
	if middleware.config.Action == ActionRedirect {
		outcome = telemetry.OutcomeRedirected
	}

	actor := telemetry.Actor{UserAgent: request.UserAgent()}
	if match.IP.IsValid() {
		actor.IP = match.IP.String()
	}
	if match.Network != nil {
		// Network.ASN is a uint32 (provider.go:29); telemetry.Actor.ASN is
		// the display form, so render it as "AS<number>".
		actor.ASN = "AS" + strconv.FormatUint(uint64(match.Network.ASN), 10)
		actor.Organization = match.Network.Organization
	}

	middleware.config.Emitter.Emit(
		telemetry.New(telemetry.StageCloak, outcome, telemetry.TechniqueProxy).
			WithActor(actor).
			WithDetail("rule", match.Rule).
			WithDetail("match_detail", match.Detail),
	)
}
```

Add `"strconv"` to the imports. `Network` is defined at `pkg/proxy/middleware/asncloak/provider.go:27-32` with fields `Prefix netip.Prefix`, `ASN uint32`, `Organization string`, and `Category Category` — the conversion above is required because `ASN` is numeric there and a display string in `telemetry.Actor`.

The test asserts `Detail["rule"] == "user-agent"`, which is the `Match.Rule` value the user-agent branch sets. That branch leaves `Match.Network` nil and `Match.IP` invalid, so both guards above must be present or the test panics.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/proxy/middleware/asncloak/ -race -v`
Expected: PASS — the four new tests plus all existing asncloak tests.

- [ ] **Step 5: Wire the bus into the proxy binary**

In `cmd/olta-proxy/main.go`, after the campaign store is constructed (near line 229, `campaignstore.New(...)`), build the bus. The proxy already has the campaign database path in `*campaign_db`; open a gorm handle for the sink:

```go
telemetryDB, err := gorm.Open("sqlite3", sqlitedsn.DSN(*campaign_db))
if err != nil {
    log.Fatal("open telemetry database: %v", err)
}
defer telemetryDB.Close()

telemetryBus := telemetry.NewBus(1024, campaigndb.New(telemetryDB))
defer telemetryBus.Close()
```

Match the file's existing logging and error-handling idiom — read the surrounding 40 lines first and follow what is already there rather than the sketch above. Use the same `sqlitedsn` helper `campaignstore` uses (`pkg/storage/sqlite`).

Then pass `Emitter: telemetryBus` into the `asncloak.Config` literal already built in this file.

- [ ] **Step 6: Verify the binary builds and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/proxy/middleware/asncloak/ cmd/olta-proxy/main.go
git commit -m "feat(proxy): emit ATT&CK-tagged cloak events (T1090)"
```

---

### Task 6: The verify stage

**Files:**
- Modify: `pkg/proxy/middleware/jsinspect/jsinspect.go` (add `Emitter` to `Config`, emit in `HandleRequest`)
- Modify: `cmd/olta-proxy/main.go` (pass the emitter into `jsinspect.Config`)
- Test: `pkg/proxy/middleware/jsinspect/jsinspect_emit_test.go`

**Interfaces:**
- Consumes: `telemetry.Emitter`, `telemetry.StageVerify`, `telemetry.TechniqueSandboxEvasion` (Tasks 1–2); `telemetryBus` from Task 5.
- Produces: `jsinspect.Config.Emitter` field of type `telemetry.Emitter`.

- [ ] **Step 1: Write the failing test**

Create `pkg/proxy/middleware/jsinspect/jsinspect_emit_test.go`:

```go
package jsinspect

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

type captureEmitter struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (e *captureEmitter) Emit(event telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *captureEmitter) all() []telemetry.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]telemetry.Event(nil), e.events...)
}

func newMiddleware(t *testing.T, emitter telemetry.Emitter) *Middleware {
	t.Helper()
	middleware, err := New(Config{
		Enabled:     true,
		Endpoint:    "/_assets/js/v.js",
		Action:      ActionBlock,
		RedirectURL: "https://www.google.com/",
		Emitter:     emitter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return middleware
}

func assertionRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://lure.example/_assets/js/v.js", strings.NewReader(body))
	request.Header.Set("User-Agent", "Mozilla/5.0")
	return request
}

func TestHandleRequestEmitsBlockedOnSuspiciousAssertion(t *testing.T) {
	emitter := &captureEmitter{}
	middleware := newMiddleware(t, emitter)

	body := `{"version":1,"webdriver":true,"headless":true,"canvas_consistent":true}`
	if _, handled := middleware.HandleRequest(assertionRequest(body)); !handled {
		t.Fatal("HandleRequest() did not handle the verification endpoint")
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	event := events[0]
	if event.Stage != telemetry.StageVerify {
		t.Fatalf("Stage = %q", event.Stage)
	}
	if event.Outcome != telemetry.OutcomeBlocked {
		t.Fatalf("Outcome = %q", event.Outcome)
	}
	if len(event.Techniques) != 1 || event.Techniques[0] != telemetry.TechniqueSandboxEvasion {
		t.Fatalf("Techniques = %v", event.Techniques)
	}
	if event.Detail["webdriver"] != true || event.Detail["headless"] != true {
		t.Fatalf("Detail = %v", event.Detail)
	}
}

func TestHandleRequestEmitsAllowedOnCleanAssertion(t *testing.T) {
	emitter := &captureEmitter{}
	middleware := newMiddleware(t, emitter)

	body := `{"version":1,"renderer":"ANGLE (NVIDIA GeForce RTX 3060)","canvas_consistent":true}`
	if _, handled := middleware.HandleRequest(assertionRequest(body)); !handled {
		t.Fatal("HandleRequest() did not handle the verification endpoint")
	}

	events := emitter.all()
	if len(events) != 1 || events[0].Outcome != telemetry.OutcomeAllowed {
		t.Fatalf("events = %+v, want one allowed outcome", events)
	}
}

func TestHandleRequestEmitsNothingForUnrelatedPath(t *testing.T) {
	emitter := &captureEmitter{}
	middleware := newMiddleware(t, emitter)

	request := httptest.NewRequest(http.MethodGet, "https://lure.example/login", nil)
	if _, handled := middleware.HandleRequest(request); handled {
		t.Fatal("unrelated path should not be handled")
	}
	if len(emitter.all()) != 0 {
		t.Fatal("unrelated path must not emit a verify event")
	}
}

func TestNilEmitterIsSafe(t *testing.T) {
	middleware := newMiddleware(t, nil)
	body := `{"version":1,"webdriver":true,"canvas_consistent":true}`
	if _, handled := middleware.HandleRequest(assertionRequest(body)); !handled {
		t.Fatal("HandleRequest() did not handle the verification endpoint")
	}
	// Reaching here without a panic is the assertion.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/proxy/middleware/jsinspect/ -run TestHandleRequestEmits -v`
Expected: FAIL — `unknown field Emitter in struct literal`.

- [ ] **Step 3: Add the Emitter and emit from HandleRequest**

In `pkg/proxy/middleware/jsinspect/jsinspect.go`, add `"github.com/s4l1hs/olta/pkg/telemetry"` to the imports and append to `Config`:

```go
	// Emitter receives a verify event for every parsed assertion. Nil
	// disables emission.
	Emitter telemetry.Emitter
```

In `HandleRequest`, the two terminal branches after a successful parse become:

```go
	if assertion.Suspicious() {
		middleware.emitVerify(request, assertion, telemetry.OutcomeBlocked)
		return middleware.enforcementResponse(request), true
	}
	middleware.emitVerify(request, assertion, telemetry.OutcomeAllowed)
	return emptyResponse(request, http.StatusNoContent), true
```

If `Action` is `ActionRedirect`, the suspicious outcome should be `telemetry.OutcomeRedirected` rather than blocked; `emitVerify` handles that below. Add:

```go
func (middleware *Middleware) emitVerify(request *http.Request, assertion Assertion, outcome telemetry.Outcome) {
	if middleware.config.Emitter == nil {
		return
	}
	if outcome == telemetry.OutcomeBlocked && middleware.config.Action == ActionRedirect {
		outcome = telemetry.OutcomeRedirected
	}

	middleware.config.Emitter.Emit(
		telemetry.New(telemetry.StageVerify, outcome, telemetry.TechniqueSandboxEvasion).
			WithActor(telemetry.Actor{
				IP:        clientIP(request),
				UserAgent: request.UserAgent(),
			}).
			WithDetail("webdriver", assertion.WebDriver).
			WithDetail("headless", assertion.Headless).
			WithDetail("phantom", assertion.Phantom).
			WithDetail("software_renderer", assertion.SoftwareRenderer).
			WithDetail("canvas_consistent", assertion.CanvasConsistent).
			WithDetail("renderer", assertion.Renderer),
	)
}

func clientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}
```

Add `"net"` to the imports. Note that `TestHandleRequestEmitsBlockedOnSuspiciousAssertion` uses `ActionBlock`, so it expects `OutcomeBlocked`; the redirect branch is covered by the asncloak equivalent and does not need a duplicate test here.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/proxy/middleware/jsinspect/ -race -v`
Expected: PASS — the four new tests plus all existing jsinspect tests.

- [ ] **Step 5: Wire it into the proxy binary**

In `cmd/olta-proxy/main.go`, add `Emitter: telemetryBus` to the `jsinspect.Config` literal, alongside the field added in Task 5.

- [ ] **Step 6: Verify and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/proxy/middleware/jsinspect/ cmd/olta-proxy/main.go
git commit -m "feat(proxy): emit ATT&CK-tagged browser verification events (T1497)"
```

---

### Task 7: Lure, credential, and capture stages

**Files:**
- Modify: `pkg/proxy/campaignstore/store.go` (add emitter, emit from `updateResult`)
- Modify: `cmd/olta-proxy/main.go` (pass the bus into `campaignstore.New`)
- Test: `pkg/proxy/campaignstore/emit_test.go`

**Interfaces:**
- Consumes: `telemetry.Emitter`, `telemetry.StageLure`, `telemetry.StageCredential`, `telemetry.StageCapture`, `telemetry.TechniqueSpearphishingLink`, `telemetry.TechniqueWebPortalCapture`, `telemetry.TechniqueStealWebSessionCookie` (Tasks 1–2).
- Produces: `func (*Store) SetEmitter(telemetry.Emitter)`. Lure, credential, and capture events in `telemetry_events`.

- [ ] **Step 1: Write the failing test**

Create `pkg/proxy/campaignstore/emit_test.go`. Read `pkg/proxy/campaignstore/feed_test.go` first for the existing fixture idiom and reuse whatever store-construction helper it defines.

```go
package campaignstore

import (
	"sync"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

type captureEmitter struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (e *captureEmitter) Emit(event telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *captureEmitter) all() []telemetry.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]telemetry.Event(nil), e.events...)
}

func TestStageForStatusMapsEveryTrackedStatus(t *testing.T) {
	cases := []struct {
		status    string
		stage     telemetry.Stage
		outcome   telemetry.Outcome
		technique telemetry.Technique
	}{
		{"Email/SMS Opened", telemetry.StageOpen, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink},
		{"Clicked Link", telemetry.StageLure, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink},
		{"Submitted Data", telemetry.StageCredential, telemetry.OutcomeCaptured, telemetry.TechniqueWebPortalCapture},
		{"Captured Session", telemetry.StageCapture, telemetry.OutcomeCaptured, telemetry.TechniqueStealWebSessionCookie},
	}

	for _, testCase := range cases {
		stage, outcome, technique, ok := stageForStatus(testCase.status)
		if !ok {
			t.Fatalf("stageForStatus(%q) reported no mapping", testCase.status)
		}
		if stage != testCase.stage || outcome != testCase.outcome || technique != testCase.technique {
			t.Fatalf("stageForStatus(%q) = %q/%q/%q, want %q/%q/%q",
				testCase.status, stage, outcome, technique,
				testCase.stage, testCase.outcome, testCase.technique)
		}
	}

	if _, _, _, ok := stageForStatus("Email/SMS Sent"); ok {
		t.Fatal("proxy-side store must not claim the delivery stage; the campaign owns it")
	}
}

func TestUpdateResultEmitsCorrelatedEvent(t *testing.T) {
	store := newTestStore(t) // reuse the helper from feed_test.go
	emitter := &captureEmitter{}
	store.SetEmitter(emitter)

	seedResult(t, store, "rid-42", 7) // reuse or add a fixture helper

	if err := store.updateResult("rid-42", "Clicked Link", nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	events := emitter.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	event := events[0]
	if event.Stage != telemetry.StageLure {
		t.Fatalf("Stage = %q", event.Stage)
	}
	if event.RID != "rid-42" || event.CampaignID != 7 {
		t.Fatalf("correlation = %q/%d, want rid-42/7", event.RID, event.CampaignID)
	}
}

func TestNilEmitterIsSafe(t *testing.T) {
	store := newTestStore(t)
	seedResult(t, store, "rid-43", 7)
	if err := store.updateResult("rid-43", "Clicked Link", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Reaching here without a panic is the assertion.
}
```

If `feed_test.go` has no `newTestStore` or `seedResult`, write them in this file: `newTestStore` opens a temp SQLite database, runs `migrations.Apply(raw, "sqlite3")`, and calls `New(path, "", false)`; `seedResult` inserts a row into `results` with the given `r_id`, `campaign_id`, `email`, and a `status` of `"Email/SMS Sent"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/proxy/campaignstore/ -run TestStageForStatus -v`
Expected: FAIL — `undefined: stageForStatus`.

- [ ] **Step 3: Write the implementation**

In `pkg/proxy/campaignstore/store.go`, add `"github.com/s4l1hs/olta/pkg/telemetry"` to the imports and an `emitter` field to `Store`:

```go
	emitter telemetry.Emitter
```

Add:

```go
// SetEmitter attaches a telemetry emitter. It must be called before the
// store begins handling requests. A nil emitter disables emission.
func (s *Store) SetEmitter(emitter telemetry.Emitter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emitter = emitter
}

// stageForStatus maps a campaign result status to its telemetry stage. The
// delivery stage is deliberately absent: the campaign service owns it,
// because the proxy never sees an email being sent.
func stageForStatus(status string) (telemetry.Stage, telemetry.Outcome, telemetry.Technique, bool) {
	switch status {
	case "Email/SMS Opened":
		return telemetry.StageOpen, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink, true
	case "Clicked Link":
		return telemetry.StageLure, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink, true
	case "Submitted Data":
		return telemetry.StageCredential, telemetry.OutcomeCaptured, telemetry.TechniqueWebPortalCapture, true
	case "Captured Session":
		return telemetry.StageCapture, telemetry.OutcomeCaptured, telemetry.TechniqueStealWebSessionCookie, true
	default:
		return "", "", "", false
	}
}

func (s *Store) emitStage(result Result, status string, browser map[string]string) {
	s.mu.Lock()
	emitter := s.emitter
	s.mu.Unlock()
	if emitter == nil {
		return
	}

	stage, outcome, technique, ok := stageForStatus(status)
	if !ok {
		return
	}

	// Only non-sensitive browser attributes cross into telemetry. The full
	// browser map and the captured payload stay in the encrypted events row.
	emitter.Emit(
		telemetry.New(stage, outcome, technique).
			WithCampaign(result.CampaignId, result.RId).
			WithActor(telemetry.Actor{
				IP:        result.IP,
				UserAgent: browser["user-agent"],
			}),
	)
}
```

In `updateResult`, after the campaign event row is saved successfully and before the feed notification, add:

```go
	s.emitStage(result, status, browser)
```

Confirm the `browser` map's user-agent key by reading how `eventDetails.Browser` is populated at the call sites in `pkg/proxy/core/http_proxy.go`; if the key differs, use the real one.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/proxy/campaignstore/ -race -v`
Expected: PASS.

- [ ] **Step 5: Wire it into the proxy binary**

In `cmd/olta-proxy/main.go`, after `campaignstore.New(...)` and after `telemetryBus` is constructed (Task 5), add:

```go
campaignEvents.SetEmitter(telemetryBus)
```

- [ ] **Step 6: Verify and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/proxy/campaignstore/ cmd/olta-proxy/main.go
git commit -m "feat(proxy): emit ATT&CK-tagged lure, credential, and capture events"
```

---

### Task 8: Delivery, open, and report stages in the campaign service

**Files:**
- Modify: `pkg/campaign/models/result.go` (emit from `HandleEmailSent`, `HandleEmailOpened`, `HandleEmailReport`)
- Create: `pkg/campaign/models/telemetry.go` (package-level emitter hook)
- Modify: `cmd/olta-campaign/main.go` (construct the bus, install the hook, close on shutdown)
- Test: `pkg/campaign/models/telemetry_test.go`

**Interfaces:**
- Consumes: `telemetry.Emitter`, `telemetry.StageDelivery`, `telemetry.StageOpen`, `telemetry.StageReport` (Tasks 1–2); `campaigndb.New` (Task 4).
- Produces: `func models.SetTelemetryEmitter(telemetry.Emitter)`; `func models.EmitTelemetry(telemetry.Event)`.

The models package uses package-level globals for its database handle already, so a package-level emitter matches the existing pattern rather than threading a parameter through every model method.

- [ ] **Step 1: Write the failing test**

Create `pkg/campaign/models/telemetry_test.go`:

```go
package models

import (
	"sync"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

type captureEmitter struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (e *captureEmitter) Emit(event telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *captureEmitter) all() []telemetry.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]telemetry.Event(nil), e.events...)
}

func TestEmitTelemetryReachesTheInstalledEmitter(t *testing.T) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	t.Cleanup(func() { SetTelemetryEmitter(nil) })

	EmitTelemetry(telemetry.New(telemetry.StageReport, telemetry.OutcomeAllowed))

	events := emitter.all()
	if len(events) != 1 || events[0].Stage != telemetry.StageReport {
		t.Fatalf("events = %+v", events)
	}
}

func TestEmitTelemetryIsSafeWithoutAnEmitter(t *testing.T) {
	SetTelemetryEmitter(nil)
	EmitTelemetry(telemetry.New(telemetry.StageDelivery, telemetry.OutcomeAllowed))
	// Reaching here without a panic is the assertion.
}

func TestEmitTelemetryIsRaceSafe(t *testing.T) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	t.Cleanup(func() { SetTelemetryEmitter(nil) })

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			EmitTelemetry(telemetry.New(telemetry.StageOpen, telemetry.OutcomeAllowed))
		}()
	}
	wg.Wait()

	if got := len(emitter.all()); got != 50 {
		t.Fatalf("received %d events, want 50", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/campaign/models/ -run TestEmitTelemetry -v`
Expected: FAIL — `undefined: SetTelemetryEmitter`.

- [ ] **Step 3: Write the emitter hook**

Create `pkg/campaign/models/telemetry.go`:

```go
package models

import (
	"sync"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// The models package already holds its database handle as package state.
// The telemetry emitter follows that same pattern rather than threading an
// extra parameter through every model method.
var telemetryState struct {
	sync.RWMutex
	emitter telemetry.Emitter
}

// SetTelemetryEmitter installs the process-wide emitter. Passing nil
// disables emission, which is what tests and the CLI paths use.
func SetTelemetryEmitter(emitter telemetry.Emitter) {
	telemetryState.Lock()
	defer telemetryState.Unlock()
	telemetryState.emitter = emitter
}

// EmitTelemetry forwards an event when an emitter is installed. It never
// blocks and never fails: a campaign must not break because telemetry is
// unavailable.
func EmitTelemetry(event telemetry.Event) {
	telemetryState.RLock()
	emitter := telemetryState.emitter
	telemetryState.RUnlock()
	if emitter == nil {
		return
	}
	emitter.Emit(event)
}
```

- [ ] **Step 4: Emit from the three result handlers**

In `pkg/campaign/models/result.go`, add `"github.com/s4l1hs/olta/pkg/telemetry"` to the imports.

In `HandleEmailSent` (both variants around lines 105 and 127), after the event is created successfully and before returning:

```go
	EmitTelemetry(
		telemetry.New(telemetry.StageDelivery, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink).
			WithCampaign(r.CampaignId, r.RId),
	)
```

In `HandleEmailOpened` (both variants around lines 174 and 189), likewise:

```go
	EmitTelemetry(
		telemetry.New(telemetry.StageOpen, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink).
			WithCampaign(r.CampaignId, r.RId).
			WithActor(telemetry.Actor{IP: r.IP}),
	)
```

In `HandleEmailReport`, emit the defender signal. This stage carries no ATT&CK technique — a user reporting a phish is not an adversary behavior:

```go
	EmitTelemetry(
		telemetry.New(telemetry.StageReport, telemetry.OutcomeAllowed).
			WithCampaign(r.CampaignId, r.RId),
	)
```

Confirm the struct field names on `Result` (`CampaignId`, `RId`, `IP`) by reading the type before writing these; the plan uses the names visible in `pkg/proxy/campaignstore/store.go`, and the campaign-side model may differ in casing.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/campaign/models/ -race -v`
Expected: PASS — the three new tests plus every existing models test.

- [ ] **Step 6: Wire the bus into the campaign binary**

In `cmd/olta-campaign/main.go`, after the database is initialized (the `models.Setup()` call), construct a bus over the same gorm handle the models package already holds and install it:

```go
telemetryBus := telemetry.NewBus(1024, campaigndb.New(models.DB()))
defer telemetryBus.Close()
models.SetTelemetryEmitter(telemetryBus)
```

The models package holds its handle as an unexported `var db *gorm.DB` (`pkg/campaign/models/models.go:17`) with no accessor, so **you must add one** — Task 11 depends on it existing under exactly this name:

```go
// DB returns the package-level database handle. It is nil until Setup runs.
func DB() *gorm.DB { return db }
```

Put it in `models.go` next to the `db` declaration. Report the accessor's final name in your report file; if you name it anything other than `DB`, Task 11 will not compile.

Ensure `telemetryBus.Close()` runs on the existing `SIGTERM` shutdown path this file already implements, not only via `defer`.

- [ ] **Step 7: Verify and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/campaign/models/ cmd/olta-campaign/main.go
git commit -m "feat(campaign): emit delivery, open, and user-report telemetry"
```

---

### Task 9: The replay stage and the webhook sink

**Files:**
- Create: `pkg/telemetry/sink/webhook/webhook.go` (moved from `pkg/proxy/telemetry/dispatcher.go`)
- Delete: `pkg/proxy/telemetry/dispatcher.go`
- Modify: `pkg/proxy/validation/worker.go` (emit a replay event per validation result)
- Modify: `cmd/olta-proxy/main.go` (add the webhook sink to the bus; drop the old dispatcher wiring)
- Test: `pkg/telemetry/sink/webhook/webhook_test.go`

**Interfaces:**
- Consumes: `telemetry.Event`, `telemetry.Sink` (Tasks 1–2); `telemetry.StageReplay`, `telemetry.TechniqueWebSessionCookie`.
- Produces: `func webhook.New(rawURL string, client *http.Client) (*Sink, error)`; `*Sink` satisfies `telemetry.Sink`; `webhook.DetectProvider`, `webhook.Provider` and its constants, preserved from the old package.

- [ ] **Step 1: Move the dispatcher and adapt it**

Move `pkg/proxy/telemetry/dispatcher.go` to `pkg/telemetry/sink/webhook/webhook.go`. Change the package clause to `package webhook`. Rename `Dispatcher` to `Sink` and `NewDispatcher` to `New`. Keep `Provider`, `ProviderGeneric`, `ProviderSlack`, `ProviderDiscord`, and `DetectProvider` exactly as they are.

Replace the payload-building function's parameter type: it currently takes a `validation.Result`; it must now take a `telemetry.Event`. Delete the `pkg/proxy/validation` import — this is what breaks the old coupling and lets any stage reach a webhook, not just validation.

Add the `Sink` interface methods:

```go
// Emit posts one event to the configured webhook.
func (s *Sink) Emit(ctx context.Context, event telemetry.Event) error {
	return s.post(ctx, s.payload(event))
}

// Close is a no-op: the HTTP client is shared and owned by the caller.
func (s *Sink) Close() error { return nil }
```

Adapt the existing `post` helper to accept a `context.Context` and build its request with `http.NewRequestWithContext`.

Move `pkg/proxy/telemetry/`'s tests, if any exist, alongside the new package and update them. Delete the now-empty `pkg/proxy/telemetry/` directory.

- [ ] **Step 2: Write the failing test**

Create `pkg/telemetry/sink/webhook/webhook_test.go`:

```go
package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

func TestSinkPostsEvent(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	event := telemetry.New(telemetry.StageReplay, telemetry.OutcomeAllowed, telemetry.TechniqueWebSessionCookie).
		WithCampaign(3, "rid-9")
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	if body == "" {
		t.Fatal("webhook received an empty body")
	}
	if !json.Valid([]byte(body)) {
		t.Fatalf("webhook body is not valid JSON: %s", body)
	}
	if !strings.Contains(body, "T1550.004") {
		t.Fatalf("payload omitted the ATT&CK technique: %s", body)
	}
}

func TestSinkRejectsNonAbsoluteURL(t *testing.T) {
	if _, err := New("/relative/path", nil); err == nil {
		t.Fatal("New() accepted a relative URL")
	}
}

func TestSinkCarriesNoLoot(t *testing.T) {
	const cookie = "ESTSAUTHPERSISTENT=AQABAAAAAAD-SECRET-TOKEN"

	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	event := telemetry.New(telemetry.StageCapture, telemetry.OutcomeCaptured).WithDetail("cookie", cookie)
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, cookie) {
		t.Fatalf("webhook leaked a captured cookie: %s", body)
	}
}
```

- [ ] **Step 3: Run test to verify it fails, then passes**

Run: `go test ./pkg/telemetry/sink/webhook/ -v`
Expected: FAIL first (package does not compile until the move in Step 1 is complete and `payload` is adapted), then PASS once the adaptation is done.

- [ ] **Step 4: Emit the replay stage from the validation worker**

In `pkg/proxy/validation/worker.go`, add a `telemetry.Emitter` field to the worker's configuration struct and emit once per validation result.

`validation.Result` (`pkg/proxy/validation/types.go:47-56`) has no boolean validity field; it carries a `Status` of `StatusValid`, `StatusInvalid`, `StatusUnknown`, or `StatusError`. Map it:

```go
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

func (w *Worker) emitReplay(result Result) {
	if w.emitter == nil {
		return
	}
	w.emitter.Emit(
		telemetry.New(telemetry.StageReplay, replayOutcome(result.Status), telemetry.TechniqueWebSessionCookie).
			WithActor(telemetry.Actor{Organization: result.Identity.Organization}).
			WithDetail("session_reference", result.SessionReference).
			WithDetail("phishlet", result.Phishlet).
			WithDetail("target_host", result.TargetHost).
			WithDetail("http_status", result.HTTPStatus),
	)
}
```

`SessionReference` is already a truncated SHA-256 digest of the session ID (`types.go:154`), not the session ID itself, so it is safe to carry. Do **not** add `result.Identity.Username` or `TenantID` — they are allowlisted for the webhook payload but are recipient identity, and the resilience report has no use for them.

Call `w.emitReplay(result)` at the point the worker currently hands its result to the dispatcher. Adjust the receiver name and the config field to match the worker's real struct — read `worker.go` first.

- [ ] **Step 5: Rewire the proxy binary**

In `cmd/olta-proxy/main.go`, replace the old `telemetry.NewDispatcher(*webhook_url, ...)` wiring. When `*webhook_url` is non-empty, build the webhook sink and include it in the bus's sink list:

```go
sinks := []telemetry.Sink{campaigndb.New(telemetryDB)}
if *webhook_url != "" {
    webhookSink, err := webhook.New(*webhook_url, nil)
    if err != nil {
        log.Fatal("configure webhook sink: %v", err)
    }
    sinks = append(sinks, webhookSink)
}
telemetryBus := telemetry.NewBus(1024, sinks...)
defer telemetryBus.Close()
```

This replaces the `telemetryBus` construction added in Task 5. Pass the bus into the validation worker's config alongside the wiring from Tasks 5–7.

Behavior change worth noting in the commit message: `-webhook-url` now receives every stage, not only session-validation results. That is the intended generalization.

- [ ] **Step 6: Verify and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/telemetry/sink/webhook/ pkg/proxy/validation/ pkg/proxy/telemetry/ cmd/olta-proxy/main.go
git commit -m "feat(telemetry): generalize webhook dispatcher to a sink and emit replay events"
```

---

### Task 10: The resilience report query layer

**Files:**
- Create: `pkg/campaign/resilience/resilience.go`
- Test: `pkg/campaign/resilience/resilience_test.go`

**Interfaces:**
- Consumes: the `telemetry_events` table (Task 3); a `*gorm.DB` handle.
- Produces: `func resilience.Compute(db *gorm.DB, campaignID int64, enabled Features) (Report, error)`; types `Features`, `Report`, `FunnelStage`, `FrictionEntry`, `RaceSummary`.

- [ ] **Step 1: Write the failing test**

Create `pkg/campaign/resilience/resilience_test.go`:

```go
package resilience

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/s4l1hs/olta/pkg/campaign/migrations"
	"github.com/s4l1hs/olta/pkg/telemetry"
	"github.com/s4l1hs/olta/pkg/telemetry/sink/campaigndb"
)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resilience.db")

	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(raw, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := gorm.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seed writes one event at a fixed offset from a base time.
func seed(t *testing.T, db *gorm.DB, base time.Time, offset time.Duration,
	stage telemetry.Stage, outcome telemetry.Outcome, rid string) {
	t.Helper()
	event := telemetry.New(stage, outcome).WithCampaign(1, rid)
	event.Timestamp = base.Add(offset)
	if err := campaigndb.New(db).Emit(nil, event); err != nil {
		t.Fatal(err)
	}
}

func allFeatures() Features {
	return Features{Cloaker: true, Verify: true, SessionValidator: true}
}

func TestFunnelCountsDistinctTargetsPerStage(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	seed(t, db, base, 0, telemetry.StageDelivery, telemetry.OutcomeAllowed, "a")
	seed(t, db, base, 0, telemetry.StageDelivery, telemetry.OutcomeAllowed, "b")
	seed(t, db, base, time.Minute, telemetry.StageLure, telemetry.OutcomeAllowed, "a")
	// Duplicate lure event for the same target must not double-count.
	seed(t, db, base, 2*time.Minute, telemetry.StageLure, telemetry.OutcomeAllowed, "a")
	seed(t, db, base, 3*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "a")

	report, err := Compute(db, 1, allFeatures())
	if err != nil {
		t.Fatal(err)
	}

	counts := map[telemetry.Stage]int{}
	for _, stage := range report.Funnel {
		counts[stage.Stage] = stage.Targets
	}
	if counts[telemetry.StageDelivery] != 2 {
		t.Fatalf("delivery = %d, want 2", counts[telemetry.StageDelivery])
	}
	if counts[telemetry.StageLure] != 1 {
		t.Fatalf("lure = %d, want 1 distinct target", counts[telemetry.StageLure])
	}
	if counts[telemetry.StageCapture] != 1 {
		t.Fatalf("capture = %d, want 1", counts[telemetry.StageCapture])
	}
}

// A disabled feature must report "not measured", never zero. Zero reads as
// "nothing was blocked" when the truth is "nothing was watching".
func TestDisabledStageIsNotMeasuredRatherThanZero(t *testing.T) {
	db := newDB(t)
	report, err := Compute(db, 1, Features{Cloaker: false, Verify: true, SessionValidator: true})
	if err != nil {
		t.Fatal(err)
	}

	for _, stage := range report.Funnel {
		if stage.Stage != telemetry.StageCloak {
			continue
		}
		if stage.Measured {
			t.Fatal("cloak stage reported as measured while the cloaker is disabled")
		}
		return
	}
	t.Fatal("cloak stage missing from the funnel")
}

func TestFrictionGroupsBlocksByOrganization(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		event := telemetry.New(telemetry.StageCloak, telemetry.OutcomeBlocked).
			WithActor(telemetry.Actor{ASN: "AS8075", Organization: "Microsoft"})
		event.Timestamp = base
		if err := campaigndb.New(db).Emit(nil, event); err != nil {
			t.Fatal(err)
		}
	}

	report, err := Compute(db, 1, allFeatures())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Friction) != 1 {
		t.Fatalf("Friction = %+v, want one entry", report.Friction)
	}
	if report.Friction[0].Organization != "Microsoft" || report.Friction[0].Count != 3 {
		t.Fatalf("Friction[0] = %+v", report.Friction[0])
	}
}

func TestRaceClassifiesAllThreeOutcomes(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	// Time-to-report is measured from delivery, so every target needs one.
	for _, rid := range []string{"fast", "slow", "silent"} {
		seed(t, db, base, 0, telemetry.StageDelivery, telemetry.OutcomeAllowed, rid)
	}

	// Target "fast" reported before the session was captured.
	seed(t, db, base, 1*time.Minute, telemetry.StageReport, telemetry.OutcomeAllowed, "fast")
	seed(t, db, base, 5*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "fast")

	// Target "slow" was captured first, then reported.
	seed(t, db, base, 2*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "slow")
	seed(t, db, base, 9*time.Minute, telemetry.StageReport, telemetry.OutcomeAllowed, "slow")

	// Target "silent" was captured and never reported.
	seed(t, db, base, 3*time.Minute, telemetry.StageCapture, telemetry.OutcomeCaptured, "silent")

	report, err := Compute(db, 1, allFeatures())
	if err != nil {
		t.Fatal(err)
	}
	if report.Race.ReportedBeforeCapture != 1 {
		t.Fatalf("ReportedBeforeCapture = %d, want 1", report.Race.ReportedBeforeCapture)
	}
	if report.Race.ReportedAfterCapture != 1 {
		t.Fatalf("ReportedAfterCapture = %d, want 1", report.Race.ReportedAfterCapture)
	}
	if report.Race.NeverReported != 1 {
		t.Fatalf("NeverReported = %d, want 1", report.Race.NeverReported)
	}
	if report.Race.MedianTimeToReportSeconds != 300 {
		t.Fatalf("MedianTimeToReportSeconds = %d, want 300", report.Race.MedianTimeToReportSeconds)
	}
}
```

The median expectation: time-to-report runs from each target's **delivery** event, not from whatever event happened to come first. Both targets are delivered at offset 0, so "fast" reports at 60s and "slow" at 540s. With an even count the median is the mean of the two middle values: `(60+540)/2 = 300`.

Measuring from delivery rather than from first-seen is the whole point of the metric — a defender's response time starts when the mail lands, not when the victim happens to click. `buildRace` must therefore key on `StageDelivery`, and a target with no delivery event contributes no duration.

Note `seed` passes a nil context to `Emit`; the campaigndb sink ignores its context, which is why that is safe. If a future sink uses it, change `seed` to pass `context.Background()`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/campaign/resilience/ -v`
Expected: FAIL — `undefined: Compute`.

- [ ] **Step 3: Write the implementation**

Create `pkg/campaign/resilience/resilience.go`:

```go
// Package resilience computes the per-campaign purple-team report from the
// telemetry event stream.
package resilience

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Features records which optional proxy capabilities were enabled for the
// engagement. A stage whose feature was off is reported as unmeasured, never
// as zero: zero reads as "nothing was blocked" when the truth is "nothing
// was watching".
type Features struct {
	Cloaker          bool `json:"cloaker"`
	Verify           bool `json:"verify"`
	SessionValidator bool `json:"session_validator"`
}

// FunnelStage is one step of the kill chain.
type FunnelStage struct {
	Stage      telemetry.Stage       `json:"stage"`
	Techniques []telemetry.Technique `json:"techniques,omitempty"`
	Targets    int                   `json:"targets"`
	Measured   bool                  `json:"measured"`
}

// FrictionEntry counts cloaker enforcement grouped by network owner. A high
// count from a security vendor's ASN is evidence the target's stack
// detonated the link.
type FrictionEntry struct {
	Organization string `json:"organization"`
	ASN          string `json:"asn"`
	Count        int    `json:"count"`
}

// RaceSummary answers whether the human layer beat the attacker.
type RaceSummary struct {
	ReportedBeforeCapture     int   `json:"reported_before_capture"`
	ReportedAfterCapture      int   `json:"reported_after_capture"`
	NeverReported             int   `json:"never_reported"`
	MedianTimeToReportSeconds int64 `json:"median_time_to_report_seconds"`
}

// Report is the full per-campaign resilience view.
type Report struct {
	CampaignID int64           `json:"campaign_id"`
	Features   Features        `json:"features"`
	Funnel     []FunnelStage   `json:"funnel"`
	Friction   []FrictionEntry `json:"friction"`
	Race       RaceSummary     `json:"race"`
}

// funnelOrder is the kill chain in sequence, with the technique each stage
// emulates. It mirrors the mapping table in the design spec.
var funnelOrder = []struct {
	stage      telemetry.Stage
	techniques []telemetry.Technique
}{
	{telemetry.StageDelivery, []telemetry.Technique{telemetry.TechniqueSpearphishingLink}},
	{telemetry.StageOpen, []telemetry.Technique{telemetry.TechniqueSpearphishingLink}},
	{telemetry.StageLure, []telemetry.Technique{telemetry.TechniqueSpearphishingLink}},
	{telemetry.StageCloak, []telemetry.Technique{telemetry.TechniqueProxy}},
	{telemetry.StageVerify, []telemetry.Technique{telemetry.TechniqueSandboxEvasion}},
	{telemetry.StageCredential, []telemetry.Technique{telemetry.TechniqueWebPortalCapture}},
	{telemetry.StageCapture, []telemetry.Technique{telemetry.TechniqueStealWebSessionCookie}},
	{telemetry.StageReplay, []telemetry.Technique{telemetry.TechniqueWebSessionCookie}},
}

type eventRow struct {
	Stage      string
	Outcome    string
	RID        string
	Timestamp  time.Time
	Actor      string
	CampaignID int64
}

// Compute builds the report for one campaign.
//
// Cloak events are unattributed by design (they fire before lure
// validation), so they are read across the whole table rather than filtered
// by campaign. Every other stage is campaign-scoped.
func Compute(db *gorm.DB, campaignID int64, enabled Features) (Report, error) {
	report := Report{CampaignID: campaignID, Features: enabled}

	var rows []eventRow
	query := db.Table("telemetry_events").
		Select("stage, outcome, rid, timestamp, actor, campaign_id").
		Where("campaign_id = ? OR campaign_id = 0", campaignID)
	if err := query.Scan(&rows).Error; err != nil {
		return Report{}, err
	}

	report.Funnel = buildFunnel(rows, enabled)
	report.Friction = buildFriction(rows)
	report.Race = buildRace(rows)
	return report, nil
}

func measured(stage telemetry.Stage, enabled Features) bool {
	switch stage {
	case telemetry.StageCloak:
		return enabled.Cloaker
	case telemetry.StageVerify:
		return enabled.Verify
	case telemetry.StageReplay:
		return enabled.SessionValidator
	default:
		return true
	}
}

func buildFunnel(rows []eventRow, enabled Features) []FunnelStage {
	distinct := make(map[telemetry.Stage]map[string]bool, len(funnelOrder))
	for _, row := range rows {
		stage := telemetry.Stage(row.Stage)
		if distinct[stage] == nil {
			distinct[stage] = make(map[string]bool)
		}
		// Cloak and verify events have no RID, so each row counts once.
		key := row.RID
		if key == "" {
			key = row.Timestamp.Format(time.RFC3339Nano) + row.Actor
		}
		distinct[stage][key] = true
	}

	funnel := make([]FunnelStage, 0, len(funnelOrder))
	for _, entry := range funnelOrder {
		funnel = append(funnel, FunnelStage{
			Stage:      entry.stage,
			Techniques: entry.techniques,
			Targets:    len(distinct[entry.stage]),
			Measured:   measured(entry.stage, enabled),
		})
	}
	return funnel
}

func buildFriction(rows []eventRow) []FrictionEntry {
	type key struct{ organization, asn string }
	counts := make(map[key]int)

	for _, row := range rows {
		if telemetry.Stage(row.Stage) != telemetry.StageCloak {
			continue
		}
		if row.Outcome != string(telemetry.OutcomeBlocked) && row.Outcome != string(telemetry.OutcomeRedirected) {
			continue
		}
		var actor telemetry.Actor
		if row.Actor != "" {
			if err := json.Unmarshal([]byte(row.Actor), &actor); err != nil {
				continue
			}
		}
		if actor.Organization == "" && actor.ASN == "" {
			continue
		}
		counts[key{actor.Organization, actor.ASN}]++
	}

	entries := make([]FrictionEntry, 0, len(counts))
	for k, count := range counts {
		entries = append(entries, FrictionEntry{Organization: k.organization, ASN: k.asn, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Organization < entries[j].Organization
	})
	return entries
}

func buildRace(rows []eventRow) RaceSummary {
	firstReport := make(map[string]time.Time)
	firstCapture := make(map[string]time.Time)
	firstDelivery := make(map[string]time.Time)

	for _, row := range rows {
		if row.RID == "" {
			continue
		}
		switch telemetry.Stage(row.Stage) {
		case telemetry.StageDelivery:
			if seen, ok := firstDelivery[row.RID]; !ok || row.Timestamp.Before(seen) {
				firstDelivery[row.RID] = row.Timestamp
			}
		case telemetry.StageReport:
			if seen, ok := firstReport[row.RID]; !ok || row.Timestamp.Before(seen) {
				firstReport[row.RID] = row.Timestamp
			}
		case telemetry.StageCapture:
			if seen, ok := firstCapture[row.RID]; !ok || row.Timestamp.Before(seen) {
				firstCapture[row.RID] = row.Timestamp
			}
		}
	}

	var summary RaceSummary
	durations := make([]int64, 0, len(firstReport))

	for rid, captured := range firstCapture {
		reported, ok := firstReport[rid]
		switch {
		case !ok:
			summary.NeverReported++
		case reported.Before(captured):
			summary.ReportedBeforeCapture++
		default:
			summary.ReportedAfterCapture++
		}
	}
	// Targets who reported without ever being captured also count as wins.
	for rid, reported := range firstReport {
		if _, captured := firstCapture[rid]; !captured {
			summary.ReportedBeforeCapture++
			_ = reported
		}
	}

	// Time-to-report runs from delivery: a defender's clock starts when the
	// mail lands, not when the victim happens to click. A target with no
	// delivery event contributes no duration rather than a misleading zero.
	for rid, reported := range firstReport {
		delivered, ok := firstDelivery[rid]
		if !ok {
			continue
		}
		durations = append(durations, int64(reported.Sub(delivered).Seconds()))
	}
	summary.MedianTimeToReportSeconds = median(durations)
	return summary
}

func median(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/campaign/resilience/ -race -v`
Expected: PASS — all four tests.

If `TestRaceClassifiesAllThreeOutcomes` reports `ReportedBeforeCapture = 2`, the "reported without ever being captured" loop is double-counting a target that was also captured; re-check the `if _, captured := firstCapture[rid]; !captured` guard.

- [ ] **Step 5: Verify and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/campaign/resilience/
git commit -m "feat(campaign): compute kill-chain funnel, friction, and report-race metrics"
```

---

### Task 11: The resilience API endpoint and ATT&CK Navigator export

**Files:**
- Create: `pkg/campaign/controllers/api/resilience.go`
- Modify: `pkg/campaign/controllers/api/server.go` (register the two routes)
- Test: `pkg/campaign/controllers/api/resilience_test.go`

**Interfaces:**
- Consumes: `resilience.Compute`, `resilience.Report`, `resilience.Features` (Task 10).
- Produces: `GET /api/v1/campaigns/{id:[0-9]+}/resilience` returning `resilience.Report` as JSON; `GET /api/v1/campaigns/{id:[0-9]+}/resilience/navigator` returning an ATT&CK Navigator layer.

- [ ] **Step 1: Write the failing test**

Create `pkg/campaign/controllers/api/resilience_test.go`. Read an existing API test in this package first (for example the import or quishing preview tests) and reuse its authenticated-request helper rather than building a new one.

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResilienceEndpointRequiresAuth(t *testing.T) {
	server := newTestAPIServer(t) // reuse this package's existing helper

	request := httptest.NewRequest(http.MethodGet, "/api/v1/campaigns/1/resilience", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

func TestResilienceEndpointReturnsReport(t *testing.T) {
	server := newTestAPIServer(t)

	request := authenticatedRequest(t, http.MethodGet, "/api/v1/campaigns/1/resilience", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var payload struct {
		CampaignID int64 `json:"campaign_id"`
		Funnel     []struct {
			Stage    string `json:"stage"`
			Measured bool   `json:"measured"`
		} `json:"funnel"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CampaignID != 1 {
		t.Fatalf("campaign_id = %d", payload.CampaignID)
	}
	if len(payload.Funnel) != 8 {
		t.Fatalf("funnel has %d stages, want 8", len(payload.Funnel))
	}
}

func TestNavigatorLayerIsWellFormed(t *testing.T) {
	server := newTestAPIServer(t)

	request := authenticatedRequest(t, http.MethodGet, "/api/v1/campaigns/1/resilience/navigator", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var layer struct {
		Versions struct {
			Navigator string `json:"navigator"`
			Layer     string `json:"layer"`
		} `json:"versions"`
		Domain     string `json:"domain"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       int    `json:"score"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}
	if layer.Domain != "enterprise-attack" {
		t.Fatalf("domain = %q", layer.Domain)
	}
	if layer.Versions.Layer == "" {
		t.Fatal("layer version is required by Navigator")
	}
	if len(layer.Techniques) == 0 {
		t.Fatal("layer contains no techniques")
	}
	for _, technique := range layer.Techniques {
		if technique.TechniqueID == "" {
			t.Fatal("a technique entry has an empty techniqueID")
		}
	}
}
```

If `newTestAPIServer` and `authenticatedRequest` do not exist under those names, use whatever this package's existing tests use, and adapt the calls.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/campaign/controllers/api/ -run TestResilience -v`
Expected: FAIL — 404, because the route is not registered.

- [ ] **Step 3: Write the handlers**

Create `pkg/campaign/controllers/api/resilience.go`:

```go
package api

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/resilience"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Resilience returns the purple-team report for one campaign.
func (as *Server) Resilience(w http.ResponseWriter, r *http.Request) {
	report, ok := as.resilienceReport(w, r)
	if !ok {
		return
	}
	JSONResponse(w, report, http.StatusOK)
}

// navigatorLayer is the MITRE ATT&CK Navigator layer format.
type navigatorLayer struct {
	Name        string              `json:"name"`
	Versions    navigatorVersions   `json:"versions"`
	Domain      string              `json:"domain"`
	Description string              `json:"description"`
	Techniques  []navigatorTechnique `json:"techniques"`
}

type navigatorVersions struct {
	Layer     string `json:"layer"`
	Navigator string `json:"navigator"`
	Attack    string `json:"attack"`
}

type navigatorTechnique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Color       string `json:"color"`
	Comment     string `json:"comment"`
	Enabled     bool   `json:"enabled"`
}

// ResilienceNavigator returns an ATT&CK Navigator layer for one campaign.
// Score is the number of distinct targets that reached the stage emulating
// the technique, so an unexercised technique scores zero.
func (as *Server) ResilienceNavigator(w http.ResponseWriter, r *http.Request) {
	report, ok := as.resilienceReport(w, r)
	if !ok {
		return
	}

	techniques := make([]navigatorTechnique, 0, len(report.Funnel))
	for _, stage := range report.Funnel {
		for _, technique := range stage.Techniques {
			comment := string(stage.Stage)
			color := "#8ec843" // exercised but nothing got through
			if !stage.Measured {
				comment += " (not measured)"
				color = "#d3d3d3"
			} else if stage.Targets > 0 {
				color = "#e60d0d" // targets reached this stage
			}
			techniques = append(techniques, navigatorTechnique{
				TechniqueID: string(technique),
				Score:       stage.Targets,
				Color:       color,
				Comment:     comment,
				Enabled:     stage.Measured,
			})
		}
	}

	JSONResponse(w, navigatorLayer{
		Name:        "Olta campaign " + strconv.FormatInt(report.CampaignID, 10),
		Versions:    navigatorVersions{Layer: "4.5", Navigator: "4.9.0", Attack: "14"},
		Domain:      "enterprise-attack",
		Description: "Techniques emulated during an authorized Olta engagement.",
		Techniques:  techniques,
	}, http.StatusOK)
}

// resilienceReport parses the campaign id, authorizes the caller, and
// computes the report. It writes the error response itself and reports
// false when the caller should stop.
func (as *Server) resilienceReport(w http.ResponseWriter, r *http.Request) (resilience.Report, bool) {
	vars := mux.Vars(r)
	campaignID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid campaign ID"}, http.StatusBadRequest)
		return resilience.Report{}, false
	}

	// Authorize exactly as the existing campaign detail handler does: the
	// caller must own the campaign. Read CampaignID's handler in this
	// package and mirror its ownership check rather than inventing one.
	user := ctx.Get(r, "user").(models.User)
	if _, err := models.GetCampaign(campaignID, user.Id); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Campaign not found"}, http.StatusNotFound)
		return resilience.Report{}, false
	}

	report, err := resilience.Compute(models.DB(), campaignID, as.telemetryFeatures)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return resilience.Report{}, false
	}
	return report, true
}
```

Import block for this file: `net/http`, `strconv`, `github.com/gorilla/mux`, `github.com/s4l1hs/olta/pkg/campaign/context` (aliased as `ctx`, matching how the neighboring handlers in this package import it), `github.com/s4l1hs/olta/pkg/campaign/models`, and `github.com/s4l1hs/olta/pkg/campaign/resilience`. There is no `telemetry` import — the handler works entirely in `resilience` types.

`as.telemetryFeatures` is a new `resilience.Features` field on `Server`, populated at construction from the proxy feature flags. The campaign service does not own those flags, so add them to the campaign config as three booleans under a `telemetry` object in `config.json`, defaulting to false, and document that they must match how `olta-proxy` was launched. A mismatch produces a report that claims a stage was measured when it was not — call this out in the config comment.

Register both routes in `pkg/campaign/controllers/api/server.go` alongside the existing campaign routes, using the same middleware chain the neighboring campaign routes use:

```go
router.HandleFunc("/campaigns/{id:[0-9]+}/resilience", as.Resilience).Methods("GET")
router.HandleFunc("/campaigns/{id:[0-9]+}/resilience/navigator", as.ResilienceNavigator).Methods("GET")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/campaign/controllers/api/ -race -v`
Expected: PASS — the three new tests plus every existing API test.

- [ ] **Step 5: Verify and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/campaign/controllers/api/ cmd/olta-campaign/config.json
git commit -m "feat(api): add campaign resilience report and ATT&CK Navigator export"
```

---

### Task 12: The dashboard panel

**Files:**
- Create: `cmd/olta-campaign/static/js/src/app/resilience.js`
- Modify: `cmd/olta-campaign/templates/campaign_results.html` (add the panel container and script tag)
- Modify: `cmd/olta-campaign/static/js/dist/app/` (rebuild bundle if the project builds JS; otherwise ship src directly, matching how the existing app files are served)

**Interfaces:**
- Consumes: `GET /api/v1/campaigns/{id}/resilience` and `.../navigator` (Task 11).
- Produces: a "Resilience" panel on the campaign results page.

- [ ] **Step 1: Confirm how the bundle is built**

Run: `ls cmd/olta-campaign/static/js/src/app/ cmd/olta-campaign/static/js/dist/app/ && ls cmd/olta-campaign/*.json cmd/olta-campaign/webpack.config.js 2>/dev/null`

The existing dashboard code is jQuery-based, calls the API through the `api.*` wrapper (for example `api.campaignId.results(campaign.id)` at `campaign_results.js:645`), chains `.success()` / `.error()`, and escapes every interpolated value with the global `escapeHtml()` helper. Follow that idiom exactly. Do not introduce a framework, a new HTTP client, or template literals if the surrounding files do not use them.

If a webpack config exists, add the new file to the same entry the other `app/` files use and rebuild the bundle; otherwise `dist/app/` is a copy of `src/app/` and the file must be copied across.

- [ ] **Step 2: Add the API wrapper entries**

In the file that defines the `api` object (find it with `grep -rn "campaignId" cmd/olta-campaign/static/js/src/app/ | grep -v campaign_results`), add two entries alongside the existing `campaignId.results`:

```javascript
resilience: function (id) {
    return query("/campaigns/" + id + "/resilience", "GET", {}, false)
},
navigator: function (id) {
    return query("/campaigns/" + id + "/resilience/navigator", "GET", {}, false)
}
```

Match the real signature of the `query` helper in that file — the argument list above mirrors the existing `results` entry, so copy whatever that one passes.

- [ ] **Step 3: Write the panel**

Create `cmd/olta-campaign/static/js/src/app/resilience.js`:

```javascript
// Renders the purple-team resilience panel on the campaign results page.

// humanDuration formats a second count as a short, readable duration.
function humanDuration(seconds) {
    if (!seconds || seconds < 0) {
        return "n/a"
    }
    if (seconds < 60) {
        return seconds + "s"
    }
    if (seconds < 3600) {
        return Math.round(seconds / 60) + "m"
    }
    return (seconds / 3600).toFixed(1) + "h"
}

// renderFunnel builds the kill-chain table. A stage whose feature was
// disabled renders "Not measured", never 0: zero reads as "nothing was
// blocked" when the truth is "nothing was watching".
function renderFunnel(funnel) {
    var rows = ""
    $.each(funnel, function (i, stage) {
        var count = stage.measured
            ? '<strong>' + escapeHtml(String(stage.targets)) + '</strong>'
            : '<span class="text-muted">Not measured</span>'
        var techniques = (stage.techniques || []).map(function (t) {
            return '<code>' + escapeHtml(t) + '</code>'
        }).join(" ")
        rows += '<tr>' +
            '<td>' + escapeHtml(stage.stage) + '</td>' +
            '<td>' + techniques + '</td>' +
            '<td class="text-right">' + count + '</td>' +
            '</tr>'
    })
    return '<h4>Kill Chain</h4>' +
        '<table class="table table-condensed table-hover">' +
        '<thead><tr><th>Stage</th><th>ATT&amp;CK</th><th class="text-right">Targets</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table>'
}

// renderFriction shows cloaker enforcement grouped by network owner. A high
// count from a security vendor's ASN is evidence the target's stack
// detonated the link.
function renderFriction(friction) {
    if (!friction || friction.length === 0) {
        return '<h4>Defensive Friction</h4><p class="text-muted">No cloaker enforcement recorded.</p>'
    }
    var rows = ""
    $.each(friction, function (i, entry) {
        rows += '<tr>' +
            '<td>' + escapeHtml(entry.organization || "unknown") + '</td>' +
            '<td>' + escapeHtml(entry.asn || "") + '</td>' +
            '<td class="text-right">' + escapeHtml(String(entry.count)) + '</td>' +
            '</tr>'
    })
    return '<h4>Defensive Friction</h4>' +
        '<table class="table table-condensed table-hover">' +
        '<thead><tr><th>Organization</th><th>ASN</th><th class="text-right">Blocked</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table>'
}

// renderRace answers whether the human layer beat the attacker.
function renderRace(race) {
    return '<h4>Report vs. Capture</h4>' +
        '<table class="table table-condensed">' +
        '<tr><td>Reported before capture</td><td class="text-right"><strong>' +
        escapeHtml(String(race.reported_before_capture)) + '</strong></td></tr>' +
        '<tr><td>Reported after capture</td><td class="text-right">' +
        escapeHtml(String(race.reported_after_capture)) + '</td></tr>' +
        '<tr><td>Never reported</td><td class="text-right">' +
        escapeHtml(String(race.never_reported)) + '</td></tr>' +
        '<tr><td>Median time to report</td><td class="text-right">' +
        escapeHtml(humanDuration(race.median_time_to_report_seconds)) + '</td></tr>' +
        '</table>'
}

function loadResilience(campaignId) {
    api.campaignId.resilience(campaignId)
        .success(function (report) {
            $("#resilience-panel").html(
                renderFunnel(report.funnel) +
                renderFriction(report.friction) +
                renderRace(report.race) +
                '<a class="btn btn-default btn-sm" href="/api/v1/campaigns/' +
                encodeURIComponent(campaignId) +
                '/resilience/navigator" download="olta-navigator-layer.json">' +
                'Download ATT&amp;CK Navigator layer</a>'
            )
        })
        .error(function (data) {
            $("#resilience-panel").html(
                '<div class="alert alert-danger">Could not load the resilience report.</div>'
            )
        })
}
```

Every value from the API is escaped before it reaches the DOM. `entry.organization` in particular comes from a remote cloud IP-range feed and is untrusted input.

Confirm that `escapeHtml` is in scope from a script loaded before this one — it is used unqualified throughout `campaign_results.js`, so it is a global defined in a shared file.

- [ ] **Step 4: Wire the panel into the results page**

In `cmd/olta-campaign/templates/campaign_results.html`, add a container `<div id="resilience-panel"></div>` in the same tab or card structure the existing panels use, and add the script tag alongside the existing `campaign_results.js` tag — after it, so `escapeHtml` and `api` are already defined.

Then call the loader once the campaign is known. `campaign_results.js` already resolves the campaign before rendering its own panels; find where it does that and add:

```javascript
loadResilience(campaign.id)
```

immediately after. Do not put it on a polling timer — the report is a summary, not a live view, and `campaign_results.js` already polls enough.

- [ ] **Step 5: Verify manually**

```bash
go build -o build/olta-campaign ./cmd/olta-campaign
```

Start the campaign service against a database that has telemetry rows, open a campaign results page, and confirm: the panel renders, a disabled stage shows `Not measured` rather than `0`, and the Navigator link downloads a file that loads in the ATT&CK Navigator without manual editing.

- [ ] **Step 6: Run the full suite and commit**

```bash
go build ./cmd/... && go test -race ./...
git add cmd/olta-campaign/
git commit -m "feat(dashboard): add campaign resilience panel with Navigator export"
```

---

### Task 13: The feed and JSONL sinks

**Files:**
- Create: `pkg/telemetry/sink/feed/feed.go`
- Create: `pkg/telemetry/sink/jsonl/jsonl.go`
- Modify: `cmd/olta-proxy/main.go` (add both sinks to the bus)
- Test: `pkg/telemetry/sink/jsonl/jsonl_test.go`

**Interfaces:**
- Consumes: `telemetry.Event`, `telemetry.Sink` (Tasks 1–2); `feedclient.DialPublisher` from `pkg/feed/client`.
- Produces: `func feed.New(endpoint string) *Sink`; `func jsonl.New(path string) (*Sink, error)`. Both satisfy `telemetry.Sink`.

This task completes the four sinks named in the spec. It has no dependency on Tasks 5–12 and may be done any time after Task 4.

- [ ] **Step 1: Write the failing test for the JSONL sink**

Create `pkg/telemetry/sink/jsonl/jsonl_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/telemetry/sink/jsonl/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write the JSONL sink**

Create `pkg/telemetry/sink/jsonl/jsonl.go`:

```go
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

// New opens the file for append, creating it when absent.
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
```

The file mode is `0o600`: a telemetry log records who was targeted and when, and must not be world-readable on a shared host.

- [ ] **Step 4: Write the feed sink**

Create `pkg/telemetry/sink/feed/feed.go`. This replaces nothing — `campaignstore.notify` keeps its existing behavior so the current operator feed is unchanged. The new sink adds a second, richer message type that the feed UI can adopt later.

```go
// Package feed publishes telemetry events to the Olta live feed.
package feed

import (
	"context"
	"encoding/json"

	"github.com/gorilla/websocket"
	feedclient "github.com/s4l1hs/olta/pkg/feed/client"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

// message is the versioned envelope. The feed's viewer subprotocol is
// already versioned ("olta.v1"), so a new message type is additive: viewers
// that do not recognize it ignore it.
type message struct {
	Type  string           `json:"type"`
	Event telemetry.Event  `json:"event"`
}

// Sink publishes each event to the feed. It dials per event, matching the
// existing campaignstore.notify behavior rather than holding a connection
// open across a long-running proxy process.
type Sink struct {
	endpoint string
}

// New returns a feed sink. An empty endpoint disables publishing.
func New(endpoint string) *Sink { return &Sink{endpoint: endpoint} }

// Emit publishes one event. A feed outage must never surface as an error
// that matters: the bus already ignores sink errors, and the campaign
// database remains the store of record.
func (s *Sink) Emit(_ context.Context, event telemetry.Event) error {
	if s.endpoint == "" {
		return nil
	}
	payload, err := json.Marshal(message{Type: "telemetry.v1", Event: event})
	if err != nil {
		return err
	}
	conn, _, err := feedclient.DialPublisher(s.endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.WriteMessage(websocket.TextMessage, payload)
}

// Close is a no-op: connections are per-event and already closed.
func (s *Sink) Close() error { return nil }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/telemetry/... -race -v`
Expected: PASS.

- [ ] **Step 6: Add both sinks to the proxy bus**

In `cmd/olta-proxy/main.go`, extend the sink list built in Task 9. Add a `-telemetry-file` flag next to the existing telemetry flags:

```go
var telemetry_file = flag.String("telemetry-file", "", "Append ATT&CK-tagged telemetry events to this JSONL file")
```

Then:

```go
if *feed_enabled {
    sinks = append(sinks, feedsink.New(*feed_url))
}
if *telemetry_file != "" {
    fileSink, err := jsonl.New(*telemetry_file)
    if err != nil {
        log.Fatal("open telemetry file: %v", err)
    }
    sinks = append(sinks, fileSink)
}
```

Import the feed sink with an alias (`feedsink "github.com/s4l1hs/olta/pkg/telemetry/sink/feed"`) — `cmd/olta-proxy/main.go` already imports `pkg/feed/client`, and two packages named `feed` in one file will not compile.

- [ ] **Step 7: Verify and commit**

```bash
go build ./cmd/... && go test ./...
git add pkg/telemetry/sink/ cmd/olta-proxy/main.go
git commit -m "feat(telemetry): add feed and JSONL sinks"
```

---

## Final Verification

- [ ] `go build ./cmd/...` succeeds
- [ ] `go test -race ./...` passes with no failures
- [ ] `go vet ./...` is clean
- [ ] `TestEventCarriesNoLoot` and `TestSinkCarriesNoLoot` both pass
- [ ] All four sinks from the spec exist and are wired: `campaigndb`, `feed`, `webhook`, `jsonl`
- [ ] All nine stages from the spec's mapping table emit — grep the codebase for each `telemetry.Stage*` constant and confirm each has a non-test call site
- [ ] A disabled stage renders `Not measured` in both the API response (`measured: false`) and the dashboard, never `0`
- [ ] Proxy request latency is unchanged when every sink is stalled — verify by running the proxy with an unreachable `-webhook-url` and confirming lure requests still serve promptly
- [ ] Update `CHANGELOG.md` under a new `### Added` entry describing the telemetry layer, the nine tagged stages, migration 006, and the resilience endpoints
