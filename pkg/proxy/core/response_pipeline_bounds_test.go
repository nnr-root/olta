package core

import (
	"bytes"
	"io"
	"io/ioutil"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// compileSubFilterRegex: sub_filter pattern compilation caching.
// ---------------------------------------------------------------------------

func TestCompileSubFilterRegex_CachesCompiledPattern(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	re1, err := proxy.compileSubFilterRegex(`example\.com`)
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	re2, err := proxy.compileSubFilterRegex(`example\.com`)
	if err != nil {
		t.Fatalf("second compile: %v", err)
	}
	if re1 != re2 {
		t.Errorf("expected the same *regexp.Regexp instance to be returned from the cache, got distinct pointers %p != %p", re1, re2)
	}
}

func TestCompileSubFilterRegex_DistinctPatternsGetDistinctEntries(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	reA, err := proxy.compileSubFilterRegex(`a\.example\.com`)
	if err != nil {
		t.Fatalf("compile a: %v", err)
	}
	reB, err := proxy.compileSubFilterRegex(`b\.example\.com`)
	if err != nil {
		t.Fatalf("compile b: %v", err)
	}
	if reA == reB {
		t.Errorf("expected distinct patterns to get distinct cache entries")
	}
	if !reA.MatchString("a.example.com") || reA.MatchString("b.example.com") {
		t.Errorf("cached regex for pattern a matched the wrong string")
	}
}

func TestCompileSubFilterRegex_CompileFailureBehavesLikeUncached(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	// an unbalanced group is an invalid regex
	badPattern := `(unclosed`

	_, err1 := proxy.compileSubFilterRegex(badPattern)
	if err1 == nil {
		t.Fatalf("expected a compile error for %q", badPattern)
	}
	if _, ok := proxy.subFilterRegexCache.Load(badPattern); ok {
		t.Errorf("a pattern that failed to compile must not be cached")
	}

	// retried on every call, exactly like the pre-caching regexp.Compile
	// behavior - the caller's fallthrough (log + skip) is unaffected.
	_, err2 := proxy.compileSubFilterRegex(badPattern)
	if err2 == nil {
		t.Fatalf("expected the compile error to recur on a second call")
	}
}

func TestCompileSubFilterRegex_ConcurrentCallsAreSafe(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)
	pattern := `concurrent\.example\.com`

	const goroutines = 32
	results := make(chan *regexp.Regexp, goroutines)
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			re, err := proxy.compileSubFilterRegex(pattern)
			results <- re
			errs <- err
		}()
	}
	var first *regexp.Regexp
	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("goroutine %d: unexpected error: %v", i, err)
		}
		re := <-results
		if first == nil {
			first = re
		} else if re != first {
			t.Errorf("goroutine %d: got a different cached instance than the first goroutine", i)
		}
	}
}

// ---------------------------------------------------------------------------
// isRewritableBodyMime: skip the rewrite pipeline for binary MIME types.
// ---------------------------------------------------------------------------

func TestIsRewritableBodyMime(t *testing.T) {
	tests := []struct {
		mime string
		want bool
	}{
		{"text/html", true},
		{"application/json", true},
		{"application/javascript", true},
		{"text/css", true},
		{"text/plain", true},
		// image/svg+xml is XML/text and can legitimately be a sub_filter
		// target - must NOT be classified as non-rewritable even though it
		// starts with "image/".
		{"image/svg+xml", true},

		{"image/png", false},
		{"image/jpeg", false},
		{"image/gif", false},
		{"image/webp", false},
		{"video/mp4", false},
		{"video/webm", false},
		{"audio/mpeg", false},
		{"font/woff2", false},
		{"application/font-woff2", false},
		{"application/zip", false},
		{"application/pdf", false},
		{"application/octet-stream", false},
	}
	for _, tt := range tests {
		t.Run(tt.mime, func(t *testing.T) {
			if got := isRewritableBodyMime(tt.mime); got != tt.want {
				t.Errorf("isRewritableBodyMime(%q) = %v, want %v", tt.mime, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// readBoundedResponseBody: bound memory use, never truncate the client.
// ---------------------------------------------------------------------------

func TestReadBoundedResponseBody_SmallBodyIsReadNormally(t *testing.T) {
	want := []byte("a small response body")
	body, oversize, remainder, err := readBoundedResponseBody(bytes.NewReader(want), 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oversize {
		t.Fatalf("body under the cap must not be reported oversize")
	}
	if remainder != nil {
		t.Errorf("remainder must be nil for a body under the cap")
	}
	if string(body) != string(want) {
		t.Errorf("body = %q, want %q", body, want)
	}
}

func TestReadBoundedResponseBody_ExactlyAtCapIsNotOversize(t *testing.T) {
	want := bytes.Repeat([]byte("x"), 100)
	body, oversize, remainder, err := readBoundedResponseBody(bytes.NewReader(want), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oversize {
		t.Errorf("a body exactly at the cap must not be reported oversize")
	}
	if remainder != nil {
		t.Errorf("remainder must be nil when not oversize")
	}
	if len(body) != 100 {
		t.Errorf("len(body) = %d, want 100", len(body))
	}
}

// TestReadBoundedResponseBody_OversizeBodyPassesThroughUnmodified is the
// core Task 3(b) guarantee: a response larger than the cap must reach the
// client byte-for-byte, never truncated, while readBoundedResponseBody
// itself only ever buffers maxSize+1 bytes into the body return value -
// the rest streams through the remainder reader without being copied into
// a second full-body buffer.
func TestReadBoundedResponseBody_OversizeBodyPassesThroughUnmodified(t *testing.T) {
	const capSize = 1024
	const totalSize = capSize*4 + 777 // deliberately not a clean multiple

	original := make([]byte, totalSize)
	for i := range original {
		original[i] = byte(i % 256)
	}

	body, oversize, remainder, err := readBoundedResponseBody(bytes.NewReader(original), capSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !oversize {
		t.Fatalf("expected the body to be reported oversize")
	}
	if len(body) != capSize+1 {
		t.Fatalf("readBoundedResponseBody must only ever buffer maxSize+1 bytes into body, got %d (cap %d)", len(body), capSize)
	}
	if remainder == nil {
		t.Fatalf("expected a non-nil remainder reader for an oversize body")
	}

	got, err := ioutil.ReadAll(remainder)
	if err != nil {
		t.Fatalf("reading remainder: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("remainder did not reproduce the original body unmodified: got %d bytes, want %d bytes (equal=%v)", len(got), len(original), bytes.Equal(got, original))
	}
}

// TestReadBoundedResponseBody_BufferedPortionIsBoundedNotFullBody asserts,
// with a source many times larger than the cap, that the []byte returned
// by readBoundedResponseBody never grows past maxSize+1 regardless of how
// large the underlying body actually is - i.e. bounded, not "read it all
// and check afterward".
func TestReadBoundedResponseBody_BufferedPortionIsBoundedNotFullBody(t *testing.T) {
	const capSize = 4096
	const totalSize = capSize * 50 // 50x the cap

	source := bytes.NewReader(bytes.Repeat([]byte("z"), totalSize))

	body, oversize, remainder, err := readBoundedResponseBody(source, capSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !oversize {
		t.Fatalf("expected oversize to be true for a body 50x the cap")
	}
	if len(body) > capSize+1 {
		t.Fatalf("buffered body length %d exceeds cap+1 (%d) - the oversize path allocated more than the bound", len(body), capSize+1)
	}

	// remainder re-serves the already-buffered prefix followed by the rest
	// of the original reader, so draining it alone reproduces the full,
	// original body - readBoundedResponseBody's own buffering (what's
	// being asserted above via len(body)) already happened before
	// remainder was ever touched.
	drained, err := ioutil.ReadAll(remainder)
	if err != nil {
		t.Fatalf("draining remainder: %v", err)
	}
	if len(drained) != totalSize {
		t.Errorf("drained remainder length = %d, want total size %d", len(drained), totalSize)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// benchSubFilterBody is a representative HTML-ish payload with several
// occurrences of the pattern being rewritten, used by both benchmarks
// below so their numbers are comparable.
var benchSubFilterBody = []byte(strings.Repeat(
	`<a href="https://login.example.com/sso">Sign in</a><script src="https://login.example.com/app.js"></script>`,
	50,
))

const benchSubFilterPattern = `login\.example\.com`
const benchSubFilterReplacement = `login.phish.test`

// BenchmarkSubFilterApply_Uncached recompiles the sub_filter pattern on
// every iteration, mirroring the pipeline's behavior before Task 3's
// caching was added (regexp.Compile was called once per sub_filter per
// proxied response).
func BenchmarkSubFilterApply_Uncached(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		re, err := regexp.Compile(benchSubFilterPattern)
		if err != nil {
			b.Fatalf("compile: %v", err)
		}
		_ = applySubFilterRegex(benchSubFilterBody, re, benchSubFilterReplacement)
	}
}

// BenchmarkSubFilterApply_Cached applies the same pattern through
// (*HttpProxy).compileSubFilterRegex, which compiles once and reuses the
// cached *regexp.Regexp on every subsequent call - this is what the
// OnResponse closure does after Task 3.
func BenchmarkSubFilterApply_Cached(b *testing.B) {
	proxy := &HttpProxy{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		re, err := proxy.compileSubFilterRegex(benchSubFilterPattern)
		if err != nil {
			b.Fatalf("compile: %v", err)
		}
		_ = applySubFilterRegex(benchSubFilterBody, re, benchSubFilterReplacement)
	}
}

// BenchmarkReadBoundedResponseBody_Oversize measures the bounded-read path
// against a body far larger than the cap, to show the buffered portion
// (and therefore the allocation this benchmark attributes to
// readBoundedResponseBody itself) stays proportional to the cap rather
// than to the source size.
func BenchmarkReadBoundedResponseBody_Oversize(b *testing.B) {
	const capSize = 64 * 1024
	const totalSize = capSize * 100 // 6.4MB source, 64KB cap

	source := bytes.Repeat([]byte("y"), totalSize)
	b.SetBytes(int64(capSize))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		body, oversize, remainder, err := readBoundedResponseBody(bytes.NewReader(source), capSize)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if !oversize {
			b.Fatalf("expected oversize")
		}
		_ = body
		// Drain the remainder so the benchmark also accounts for relaying
		// the rest of the body, matching what the real OnResponse path
		// eventually does when copying resp.Body to the client.
		if _, err := io.Copy(io.Discard, remainder); err != nil {
			b.Fatalf("draining remainder: %v", err)
		}
	}
}
