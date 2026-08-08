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

### Changed

- Renamed the Go module to `github.com/s4l1hs/olta` and migrated every internal import path.
- Updated build scripts, service definitions, runtime messages, and asset resolution for the three Olta binaries.
- Enabled SQLite WAL mode, busy timeouts, foreign-key enforcement, and bounded connection usage to improve concurrent campaign access.
- Consolidated inherited campaign migration histories into the unified Olta v1 schema; fresh databases no longer replay redundant historical migrations.
- Updated deployment recipes to target `olta-campaign` and `olta-proxy` rather than downloading upstream binaries.
- Replaced non-releasable worker tickers and added graceful `SIGTERM` handling for service-managed campaign shutdowns.
- Added the `-client-profile` proxy option and routed outbound HTTP traffic through the browser-profiled transport while preserving upstream proxy support and standard timeout errors.
- Replaced the fixed QR helper with an in-memory generator that returns Base64 PNG, data URI, and inline MIME attachment data without temporary filesystem writes.
- Refreshed the Olta logo, architecture diagram, and README screenshots to remove legacy EvilGophish branding.

### Verified

- Resolved the complete Go test suite, including migration, model, controller, API, worker, proxy, feed, and storage tests.
- Verified with `go test -count=1 ./...`.
- Verified all command packages build with `go build ./cmd/...`.

[1.0.0-Alpha]: https://github.com/s4l1hs/olta/releases/tag/v1.0.0-alpha
