# Purple-Team Telemetry and ATT&CK Tagging

**Date:** 2026-08-24
**Status:** Approved for planning
**Scope:** A shared telemetry event spine across `olta-proxy`, `olta-campaign`, and `olta-feed`, plus one consumer: a per-campaign resilience report.

## Problem

`CLAUDE.md` positions Olta as a platform for authorized SOC teams to "measure defense resilience and export telemetry data." No such capability exists. A search across all Go, Markdown, and JSON sources for `sigma`, `mitre`, `att&ck`, `siem`, `splunk`, `elastic`, `ecs`, `syslog`, and `cef` returns zero results. The only outbound telemetry is `pkg/proxy/telemetry/dispatcher.go`, a Slack/Discord/generic webhook wired exclusively to session-validation alerts.

Every feature in the 1.0.0-Alpha changelog serves the red side. Olta competes with EvilGophish on offensive sophistication — a race against detection vendors that must be re-run forever. The defensive half is unoccupied ground that the project's own positioning already claims.

Three signals are collected today and discarded:

- **Cloaker decisions.** `asncloak.Evaluate` (`pkg/proxy/middleware/asncloak/asncloak.go:108`) returns a match and an action, then forgets it. Requests blocked from cloud ASNs are direct evidence that the target's security stack detonated the link.
- **Browser verification decisions.** `jsinspect.HandleRequest` (`pkg/proxy/middleware/jsinspect/jsinspect.go:166`) decides headless/automation, then forgets it.
- **User reports.** `HandleEmailReport` already fires from the IMAP monitor (`pkg/campaign/imap/monitor.go:175`). This is a genuine *defender* signal — a human recognized the phish — and it currently only increments a counter.

## Goals

1. One canonical, ATT&CK-tagged event emitted at every decision point across all three services.
2. An event stream that is safe to hand to a client's SOC, enforced by test rather than convention.
3. A per-campaign resilience report that answers: how far did the attack get, what pushed back, and did humans report it before the token was stolen?

## Non-Goals

- SIEM connectors (Splunk HEC, Elastic, syslog/ECS/OCSF). Straightforward once the bus exists; building them without a real client SIEM to validate against is guesswork.
- Sigma/KQL/SPL detection-rule generation. Same reasoning.
- Decoupling the proxy from the campaign SQLite file. Tracked separately; see *Known Tension* below.
- Any change to how captured credentials or tokens are stored. That is the in-flight `pkg/campaign/secrets` work and this design consumes it rather than altering it.

## Approaches Considered

**A. Retrofit onto existing paths.** Add ATT&CK tags to the campaign `events` table and extend the feed payload. No new package.

Rejected. The `events` table is keyed on `campaign_id` + recipient email (`pkg/campaign/migrations/sqlite/001_initial_olta_schema.sql:137`), and cloaker decisions fire *before* lure validation, so they have no RID and no campaign to attach to. The most valuable signals are exactly the ones this approach cannot represent.

**C. Full OpenTelemetry pipeline with SIEM connectors.** An OTel collector, ECS schema, vendor exporters.

Rejected as YAGNI. A heavy dependency tree and an ops burden for a tool whose entire deployment story is three static binaries on a disposable VPS.

**B. A shared `pkg/telemetry` event spine with sink fan-out.** Selected. Detailed below.

## Design

### 1. The event model

Promote `pkg/proxy/telemetry` to `pkg/telemetry`, shared by all three services.

```go
type Event struct {
    ID         string       // 128-bit random hex, 32 chars
    Timestamp  time.Time
    Stage      Stage        // delivery|open|lure|cloak|verify|credential|capture|replay|report
    Outcome    Outcome      // allowed|blocked|redirected|captured|failed
    Techniques []Technique  // ATT&CK IDs
    CampaignID int64        // 0 before correlation
    RID        string       // empty for cloak and verify
    Actor      Actor        // IP, ASN, user agent, geo, TLS client profile
    Detail     map[string]any
}
```

The ID is a 128-bit `crypto/rand` value hex-encoded to 32 characters, not a ULID. A ULID would add a module dependency for time-sortability that the indexed `timestamp` column already provides, so the trade was not worth it. Chronological ordering comes from `timestamp`, never from the ID.

`CampaignID` and `RID` are optional, and that is the load-bearing decision. Cloak and verify events fire before lure validation establishes a recipient identity. Allowing unattributed events is what makes those two stages representable at all, and it is the specific thing approach A could not do.

### 2. The no-loot invariant

**An `Event` never carries captured credentials, cookies, or tokens.**

Captured material stays in the campaign database behind the `pkg/campaign/secrets` AES-GCM layer. Telemetry records *the fact of* a capture — stage, outcome, technique, timing, actor — never its contents. `Actor` and `Detail` pass through the redaction discipline already established in `pkg/campaign/models/redaction.go`.

This is what makes the stream safe to forward to a client's SOC, so it is enforced by a test that must never be deleted (see *Testing*), not by reviewer vigilance.

### 3. ATT&CK mapping and emission points

| Stage | Emission point | Technique |
|---|---|---|
| delivery | `pkg/campaign/models/result.go` `HandleEmailSent` | T1566.002 Spearphishing Link |
| open | `pkg/campaign/models/result.go` `HandleEmailOpened` | T1566.002 |
| lure | `pkg/proxy/campaignstore/store.go:156` `HandleClickedLink` | T1566.002 |
| cloak | `pkg/proxy/middleware/asncloak/asncloak.go:108` `Evaluate` — new | T1090 Proxy |
| verify | `pkg/proxy/middleware/jsinspect/jsinspect.go:166` `HandleRequest` — new | T1497 Virtualization/Sandbox Evasion |
| credential | `pkg/proxy/campaignstore/store.go:161` `HandleSubmittedData` | T1056.003 Web Portal Capture |
| capture | `pkg/proxy/campaignstore/store.go:170` `HandleCapturedCookieSession` | T1539 Steal Web Session Cookie |
| replay | `pkg/proxy/validation` — rewire existing | T1550.004 Web Session Cookie |
| report | `pkg/campaign/imap/monitor.go:175` `HandleEmailReport` | *defender signal, no technique* |

Six of the nine fire at call sites that already exist and need only a one-line emit: delivery, open, lure, credential, capture, and report. Two are genuinely new instrumentation — cloak and verify. One rewires an existing dispatcher — replay.

**SMS campaigns reuse T1566.002 rather than getting their own technique.** Enterprise ATT&CK has no smishing sub-technique; the nearest match, T1660 Phishing, belongs to the Mobile matrix, and mixing matrices would invalidate the Navigator layer in section 6, which declares `domain: "enterprise-attack"`. T1566.002 is defensible for an SMS-delivered phishing link — the technique describes the link, not the transport. To keep engagement reports able to separate the two channels without misusing a technique ID, every delivery, open, lure, and credential event carries `medium` in its detail, valued `"email"` or `"sms"`. The `SMSTarget` flag already on each result supplies it.

The three that make the layer purple rather than red are cloak, verify, and report: the first two record what pushed back, and the third records that a human noticed.

### 4. Bus and sinks

```go
type Sink interface {
    Emit(context.Context, Event) error
    Close() error
}

// What middleware sees. Nil-safe, so asncloak and jsinspect stay
// ignorant of buses and campaigns.
type Emitter interface { Emit(Event) }

type Bus struct {
    sinks []Sink
    queue chan Event   // bounded; drops and counts on overflow
}
```

**Emission never blocks or fails the request path.** This is not a new pattern in this codebase — `campaignstore` already uses a queue and condition variable so HTTP goroutines never block on database writes (`pkg/proxy/campaignstore/store.go:99-133`), and `hub.go:54` uses a non-blocking select that drops on backpressure. The bus makes the pattern reusable instead of re-derived per call site.

Sinks:

- **`campaigndb`** — store of record. Writes through the existing `campaignstore` queue, which already owns the database handle and the serialization.
- **`feed`** — live operator view. The feed protocol already carries a version constant (`viewerProtocol = "olta.v1"`, `pkg/feed/feed.go:26`) to hang an enriched payload off.
- **`webhook`** — generalize the existing `Dispatcher` from validation-only to any `Event`. The Slack, Discord, and generic dialects already work.
- **`jsonl`** — optional append-only export file.

Wiring: `cmd/olta-proxy/main.go` constructs a bus from flags and passes an `Emitter` into `asncloak`, `jsinspect`, and `campaignstore`. `cmd/olta-campaign/main.go` constructs its own for the delivery, open, and report stages.

### 5. Schema

New table `telemetry_events`, added as campaign migration **006** for both SQLite and MySQL, bumping `migrations.CurrentVersion` from 5 to 6 (`pkg/campaign/migrations/migrations.go:11`). Migration 005 is the in-flight secret-storage work and is not disturbed.

Columns: `id`, `event_id` (32-char random hex, unique), `timestamp`, `stage`, `outcome`, `techniques`, `campaign_id` (nullable), `rid` (nullable), `actor` (JSON), `detail` (JSON). Indexed on `campaign_id`, `rid`, and `timestamp`.

### 6. The resilience report

Endpoint `GET /api/v1/campaigns/{id}/resilience`, behind the existing `RequireLogin` and `RequireAPIKey` middleware, plus a dashboard panel. This follows the shape of the preview APIs added in 1.0.0-Alpha.

**Kill-chain funnel.** Targets surviving each stage: delivered → opened → clicked → passed cloak → passed verify → credentials submitted → session captured → session still valid at T+1h. Each stage labeled with its ATT&CK ID.

Three of these stages depend on optional proxy features: cloak requires `-enable-cloaker`, verify requires `-enable-js-inspect`, and the final validity check requires `-enable-session-validator`. When a feature is disabled its stage reports "not measured" rather than a count. A disabled stage must never render as zero, which would read as "nothing was blocked" when the truth is "nothing was watching."

**Defensive friction.** Cloaker blocks and redirects grouped by ASN and cloud provider. Forty requests from Microsoft ASNs eight seconds after delivery means Defender for Office 365 detonated the link. This is a real finding about the client's security stack, inferred from data Olta already collects and currently discards.

**The report-vs-capture race.** Per target, `time_to_report` minus `time_to_capture`. In aggregate: median time-to-report, and the proportion of targets who reported before capture, after capture, or never.

This is the headline metric. It measures whether the human layer beat the attacker, it derives entirely from data Olta already collects, and no competing tool computes it. It is also honest in a way a "detection scorecard" would not be: Olta cannot see the client's SIEM and must not claim to know what the SIEM detected.

**ATT&CK Navigator layer export.** A small handler emitting the techniques exercised, colored by stage outcome. The mapping table in section 3 is the entire data source.

## Known Tension

Using the campaign database as the store of record makes the shared-SQLite seam between `olta-proxy` and `olta-campaign` load-bearing for one more feature. That seam is a known architectural limit: it forces both services onto one filesystem and prevents multi-node proxy deployments.

Accepted deliberately. The alternative — shipping telemetry over the feed WebSocket — is fire-and-forget with no delivery guarantee, and would mean building the decoupling and the telemetry at the same time.

The `Sink` interface is the compensation. Because every write goes through it, later decoupling becomes a one-file change (swap `sink/campaigndb` for `sink/grpc`) rather than a hunt through scattered call sites. This design makes that future work easier, not harder.

## Testing

Test-driven, matching the existing repository habit: 52 test files, `go test ./...` green, `-race` already used on the mailer and worker packages.

- **The no-loot invariant.** Construct every `Event` kind from fixtures seeded with known secret values, marshal, and assert no secret substring survives. This test must never be deleted; it is what allows telling a client the stream is safe to ingest.
- **Bus.** Stays non-blocking under a stalled sink. Drops and counts on overflow. Clean under `-race`.
- **Emission points.** Table-driven, one case per row of the section 3 mapping, asserting stage, technique, and outcome.
- **Migration 006.** Fresh install and v5→v6 upgrade, following the pattern in `pkg/campaign/migrations/migrations_test.go`.
- **Report math.** A fixture campaign with fixed timestamps, asserting funnel counts and all three race outcomes: reported but never captured, captured but never reported, and both.

The cloak and verify emitters become the first test seams anywhere near `pkg/proxy/core`, which currently has zero test files across 15 source files.

## Success Criteria

1. Every stage in the section 3 table emits a tagged event, verified by test.
2. The no-loot invariant test passes against fixtures containing real-shaped secrets.
3. `GET /api/v1/campaigns/{id}/resilience` returns funnel, friction, and race metrics for a completed campaign.
4. A generated ATT&CK Navigator layer loads in Navigator without manual editing.
5. `go build ./cmd/...` and `go test -race ./...` remain green.
6. Proxy request-path latency is unchanged when all sinks are stalled.
