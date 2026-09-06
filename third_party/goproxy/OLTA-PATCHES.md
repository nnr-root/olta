# Olta's patches to goproxy

This is a vendored copy of `github.com/kgretzky/goproxy`
(`v0.0.0-20220622134552-7d0e0c658440`), itself a fork of
`github.com/elazarl/goproxy`, carried here so Olta can patch it. The root
`go.mod` points its `replace` directive at this directory.

It exists because the change below is not reachable from outside the package:
it happens inside `handleHttps`, below the layer any `OnResponse` handler can
see, so no amount of work in `pkg/proxy/core` can affect it.

Only test files were dropped from the upstream copy. Everything else is
upstream's, unmodified except where marked `OLTA PATCH`.

## 1. Reproduce the origin's response framing (`https.go`, `olta_framing.go`)

**Upstream behavior.** Every MITM'd HTTPS response had its `Content-Length`
deleted and `Transfer-Encoding: chunked` set, with the comment "since we don't
know the length of resp", and its body written through a chunked writer.

**Why that is a problem for Olta.** An origin that serves a plain
`Content-Length` response reached the victim as a chunked one. That difference
is visible on the wire to anything comparing the proxied site against the real
one — which is precisely what an AiTM proxy must not be distinguishable by.
`pkg/proxy/core` already reconciles `Content-Length` and clears stale
`Transfer-Encoding` after a body rewrite (see `shouldReconcileBodyFraming` in
`http_proxy.go`), and every bit of that work was being discarded here.

**The patch.** `applyOltaResponseFraming` decides the framing from the
response itself: a known length keeps `Content-Length` and is written raw; a
genuinely unknown length is still chunked, which is the case upstream's
comment actually described. `HEAD` is untouched, as upstream had it.

## Known divergence NOT patched: `Connection: close`

`handleHttps` also sets `Connection: close` on every response, with the
comment "otherwise chrome will keep CONNECT tunnel open forever". A real
origin rarely sends that header, so it remains a wire-level fingerprint, and
it is also inconsistent with the surrounding loop, which goes on reading
further requests from the same connection regardless.

It is deliberately left alone. Removing it changes connection lifetime
behavior for every real browser, and this repository has no way to test that
hermetically — the end-to-end harness documents that it cannot drive a full
MITM-to-upstream pass-through in process (`test/e2e/gateway_test.go`). Fixing
a fingerprint by introducing hangs in real browsers would be a bad trade, so
the divergence is recorded here rather than guessed at.

## Formatting

`dispatcher.go` and `doc.go` are not `gofmt`-clean. That is upstream's own
formatting and it is left alone on purpose: reformatting them would add noise
to every future diff against upstream for no benefit. The repository's own
`gofmt` check covers `pkg`, `cmd` and `test`, not `third_party`.

## Updating

Re-copy upstream's `*.go` and `LICENSE` (excluding `*_test.go`), then
reapply the `OLTA PATCH` markers in `https.go` and restore
`olta_framing.go`. Run `go build ./...` and `go test ./...` from the
repository root afterwards.
