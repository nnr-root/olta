package goproxy

import (
	"net/http"
	"strconv"
)

// applyOltaResponseFraming reproduces the origin's own message framing on a
// MITM'd HTTPS response, instead of forcing chunked transfer on every one.
//
// Upstream deleted Content-Length and set Transfer-Encoding: chunked
// unconditionally here, with the comment "since we don't know the length of
// resp". That was true when the body was an unread stream. It is not true for
// a response whose length is known -- which is the normal case once a
// response has been read and rewritten -- and the consequence was that an
// origin serving a plain Content-Length response reached the victim as a
// chunked one. That difference is visible on the wire to anything comparing
// the proxied site against the real one, and it happened below the layer any
// OnResponse handler can reach, so it could not be corrected from outside
// this package.
//
// It returns true when the body must still be chunked: a response whose
// length is genuinely unknown, which is exactly the case the original comment
// described.
//
// HEAD is left exactly as upstream had it: its framing headers describe a
// body that is never sent, so rewriting them would misdescribe the response.
func applyOltaResponseFraming(resp *http.Response) bool {
	if resp == nil {
		return true
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return false
	}

	if resp.ContentLength < 0 {
		// Genuinely unknown length: chunked is the only correct framing.
		resp.Header.Del("Content-Length")
		resp.Header.Set("Transfer-Encoding", "chunked")
		return true
	}

	resp.Header.Del("Transfer-Encoding")
	// The header is written only when the origin framed the response that way
	// or the body is non-empty. Adding "Content-Length: 0" to a response that
	// never carried one -- a 204, say -- would be its own divergence from the
	// origin, which is the thing this function exists to avoid.
	if resp.ContentLength > 0 || resp.Header.Get("Content-Length") != "" {
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	return false
}
