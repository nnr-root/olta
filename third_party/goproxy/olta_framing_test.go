package goproxy

import (
	"net/http"
	"testing"
)

func response(status int, contentLength int64, header http.Header, method string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode:    status,
		ContentLength: contentLength,
		Header:        header,
		Request:       &http.Request{Method: method},
	}
}

// TestKnownLengthKeepsOriginFraming is the fingerprint this patch exists to
// remove: an origin that served a plain Content-Length response must reach the
// client the same way, not as a chunked one.
func TestKnownLengthKeepsOriginFraming(t *testing.T) {
	resp := response(200, 1234, http.Header{"Content-Length": []string{"1234"}}, http.MethodGet)

	if applyOltaResponseFraming(resp) {
		t.Fatal("a response with a known length was chunked")
	}
	if got := resp.Header.Get("Content-Length"); got != "1234" {
		t.Errorf("Content-Length = %q, want 1234", got)
	}
	if got := resp.Header.Get("Transfer-Encoding"); got != "" {
		t.Errorf("Transfer-Encoding = %q, want none", got)
	}
}

// TestRewrittenBodyGetsTheCorrectedLength covers the case that produced the
// bug in the first place: the pipeline rewrote the body, so the origin's
// stale header must be corrected rather than deleted.
func TestRewrittenBodyGetsTheCorrectedLength(t *testing.T) {
	resp := response(200, 2000, http.Header{"Content-Length": []string{"1234"}}, http.MethodGet)

	if applyOltaResponseFraming(resp) {
		t.Fatal("a response with a known length was chunked")
	}
	if got := resp.Header.Get("Content-Length"); got != "2000" {
		t.Errorf("Content-Length = %q, want the corrected 2000", got)
	}
}

// TestUnknownLengthStillChunks keeps the case upstream's comment actually
// described: with no known length, chunked is the only correct framing.
func TestUnknownLengthStillChunks(t *testing.T) {
	resp := response(200, -1, nil, http.MethodGet)

	if !applyOltaResponseFraming(resp) {
		t.Fatal("a response with an unknown length was not chunked")
	}
	if got := resp.Header.Get("Transfer-Encoding"); got != "chunked" {
		t.Errorf("Transfer-Encoding = %q, want chunked", got)
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Errorf("Content-Length = %q, want none alongside chunked", got)
	}
}

// TestStaleChunkedHeaderIsCleared covers an origin that chunked its own
// response: once the body is buffered its length is known, and leaving the
// origin's Transfer-Encoding in place would describe framing that is no
// longer being used.
func TestStaleChunkedHeaderIsCleared(t *testing.T) {
	resp := response(200, 42, http.Header{"Transfer-Encoding": []string{"chunked"}}, http.MethodGet)

	if applyOltaResponseFraming(resp) {
		t.Fatal("a response with a known length was chunked")
	}
	if got := resp.Header.Get("Transfer-Encoding"); got != "" {
		t.Errorf("Transfer-Encoding = %q, want it cleared", got)
	}
	if got := resp.Header.Get("Content-Length"); got != "42" {
		t.Errorf("Content-Length = %q, want 42", got)
	}
}

// TestEmptyBodyWithoutAnOriginHeaderStaysBare is the divergence guard: adding
// "Content-Length: 0" to a response that never carried one -- a 204, say --
// would be its own difference from the origin.
func TestEmptyBodyWithoutAnOriginHeaderStaysBare(t *testing.T) {
	resp := response(http.StatusNoContent, 0, nil, http.MethodGet)

	if applyOltaResponseFraming(resp) {
		t.Fatal("an empty response was chunked")
	}
	if _, present := resp.Header["Content-Length"]; present {
		t.Errorf("Content-Length was added to a response that never carried one: %v", resp.Header)
	}
}

// TestEmptyBodyWithAnOriginHeaderKeepsIt is the complement: an origin that
// did send "Content-Length: 0" keeps it.
func TestEmptyBodyWithAnOriginHeaderKeepsIt(t *testing.T) {
	resp := response(200, 0, http.Header{"Content-Length": []string{"0"}}, http.MethodGet)

	if applyOltaResponseFraming(resp) {
		t.Fatal("an empty response was chunked")
	}
	if got := resp.Header.Get("Content-Length"); got != "0" {
		t.Errorf("Content-Length = %q, want 0", got)
	}
}

// TestHeadIsUntouched preserves upstream's behavior: a HEAD response's
// framing headers describe a body that is never sent, so rewriting them would
// misdescribe the response.
func TestHeadIsUntouched(t *testing.T) {
	header := http.Header{"Content-Length": []string{"9999"}}
	resp := response(200, -1, header, http.MethodHead)

	if applyOltaResponseFraming(resp) {
		t.Fatal("a HEAD response was chunked")
	}
	if got := resp.Header.Get("Content-Length"); got != "9999" {
		t.Errorf("Content-Length = %q, want the origin's 9999 untouched", got)
	}
}

func TestNilResponseChunks(t *testing.T) {
	if !applyOltaResponseFraming(nil) {
		t.Fatal("a nil response must fall back to chunked rather than claim a length")
	}
}
