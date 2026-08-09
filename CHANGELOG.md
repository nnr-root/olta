# Changelog

All notable changes to Olta are documented in this file.

## [1.0.0-Alpha] - 2026-08-08

### Added

- Established the Olta monorepo layout with the `olta-proxy`, `olta-campaign`, and `olta-feed` entry points under `cmd/`, and reusable implementation packages under `pkg/`.
- Added one embedded initial schema per supported campaign database at `pkg/campaign/migrations/{sqlite,mysql}/001_initial_olta_schema.sql`.
- Added schema-version tracking and final-schema validation for both fresh installs and compatible pre-Olta databases.
- Added native Ansible deployment roles that build and install Olta services from this repository.
- Added a uTLS-backed proxy transport with Chrome, Firefox, Safari, and per-connection Random browser profiles, including HTTP/2 and HTTP/1.1 ALPN negotiation.
- Added the in-memory campaign quishing service with configurable image size, foreground and background colors, and Low, Medium, or High error correction.
- Added recipient-specific `{{.QRCode}}` and `{{.RIdQR}}` email template tags and an authenticated `POST /api/quishing/preview` dashboard API.
- Added Phase 3 smart-cloaking middleware for the proxy gateway with lock-free in-memory IPv4/IPv6 CIDR and ASN matching for cloud providers and security crawlers.
- Added rule-based User-Agent, browser-header, and HTTP protocol inspection with configurable 302 redirect or 403/404 block enforcement before lure validation and session initialization.
- Added `-enable-cloaker`, `-cloaker-redirect-url`, `-cloaker-action`, `-cloaker-block-status`, and `-cloaker-trust-proxy-headers` options to `olta-proxy`.
- Added opt-in client-side environment verification with WebDriver/headless checks, WebGL software-renderer detection, and Canvas consistency assertions injected into proxied HTML responses.
- Added `-enable-js-inspect` and `-js-inspect-endpoint` options to `olta-proxy`, with configurable 302 safe-URL redirects or 403 enforcement for suspicious browser assertions.
- Added an opt-in asynchronous captured-session validation worker pool driven by proxy database capture events, with bounded queues, request timeouts, and non-sensitive identity metadata extraction.
- Added Discord, Slack, and generic JSON webhook telemetry for sanitized session validation results, configurable with `-enable-session-validator` and `-webhook-url`.
- Added randomized campaign delivery jitter with global `-min-send-delay` and `-max-send-delay` settings and optional per-campaign delay overrides.
- Added multi-variant campaign templates with deterministic round-robin recipient assignment, recipient-level persisted variant IDs, and variant-specific delivery, open, click, submission, captured-session, report, and error metrics in campaign API responses.
- Added campaign schema version 2 migrations for SQLite and MySQL, including automatic Variant A backfill for existing email campaigns and recipient results.
- Added embedded browser-in-the-browser campaign components with responsive simulated address bars, HTTP/HTTPS status indicators, draggable window chrome, and Windows 11, macOS, and Ubuntu/GNOME-style Linux themes.
- Added automatic client-platform theme selection plus explicit `{{.BITBFrame}}` and `{{.BITBFrameTheme}}` campaign template helpers.
- Added modular OAuth 2.0/OpenID Connect consent components with application and publisher branding, requested-scope presentation, redirect URI metadata, accept/cancel events, and the `{{.OAuthConsent}}` campaign template helper.
- Added single-binary CSS and JavaScript distribution for BITB and OAuth consent components through embedded campaign asset routes under `/static/components/`.
- Added a pure rule-based campaign personalizer with concurrency-safe nested spintax expansion that preserves Go template actions and ordinary HTML/CSS braces.
- Added a built-in scenario library with coherent subject, plaintext, and HTML variants for student/academia, general HR, finance/accounting, and IT/software engineering audiences.
- Added Turkish-normalized recipient routing across department, position, and role metadata, with `general_hr_scenarios` as the default fallback.
- Added rich personalization fields for `{{.FirstName}}`, `{{.LastName}}`, `{{.Position}}`, `{{.Department}}`, `{{.Company}}`, `{{.ManagerName}}`, and `{{.PhishingURL}}`.
- Added `-enable-spintax` and `-enable-role-routing` campaign options, both enabled by default.
- Added campaign schema version 3 migrations for SQLite and MySQL to persist recipient department, role, company, and manager metadata across targets, results, and test-email requests.

### Changed

- Renamed the Go module to `github.com/s4l1hs/olta` and migrated every internal import path.
- Updated build scripts, service definitions, runtime messages, and asset resolution for the three Olta binaries.
- Enabled SQLite WAL mode, busy timeouts, foreign-key enforcement, and bounded connection usage to improve concurrent campaign access.
- Consolidated inherited campaign migration histories into the unified Olta v1 schema; fresh databases no longer replay redundant historical migrations.
- Updated deployment recipes to target `olta-campaign` and `olta-proxy` rather than downloading upstream binaries.
- Replaced non-releasable worker tickers and added graceful `SIGTERM` handling for service-managed campaign shutdowns.
- Updated the email worker shutdown path to cancel active jitter waits, wait for dispatch goroutines, and unlock persisted mail logs for clean campaign resumption.
- Added the `-client-profile` proxy option and routed outbound HTTP traffic through the browser-profiled transport while preserving upstream proxy support and standard timeout errors.
- Replaced the fixed QR helper with an in-memory generator that returns Base64 PNG, data URI, and inline MIME attachment data without temporary filesystem writes.
- Refreshed the Olta logo, architecture diagram, and README screenshots to remove legacy EvilGophish branding.

### Verified

- Resolved the complete Go test suite, including migration, model, controller, API, worker, proxy, feed, and storage tests.
- Verified with `go test -count=1 ./...`.
- Verified all command packages build with `go build ./cmd/...`.
- Benchmarked local cloaker CIDR lookups at sub-microsecond latency with zero allocations.
- Added focused coverage for HTML verification injection, assertion enforcement, jitter range calculation, cancellation-aware delay waits, A/B distribution, variant rendering and metrics aggregation, API exposure, and schema v1-to-v2 backfill.
- Added focused coverage for BITB theme rendering and platform assets, OAuth metadata escaping and scope injection, template helper execution, and embedded component asset routing.
- Added focused coverage for nested spintax randomness, template-action preservation, category routing and fallback behavior, rich placeholder substitution, personalized mail generation, and schema v2-to-v3 migration.
- Benchmarked spintax evaluation at approximately 496 ns/op with 261 B/op and 3 allocations/op on Apple M2 hardware.
- Verified the campaign mailer and worker packages with the Go race detector and the full repository with `go vet ./...`.

[1.0.0-Alpha]: https://github.com/s4l1hs/olta/releases/tag/v1.0.0-alpha
