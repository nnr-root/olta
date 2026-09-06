package imap

import (
	"bytes"
	"fmt"
	"net/textproto"
	"strings"
	"testing"

	"github.com/jordan-wright/email"
)

// The IMAP monitor is the only producer of telemetry.StageReport, which is
// what the resilience report's race summary -- "did the human layer beat the
// attacker?" -- is computed from. Everything downstream of matchEmail is
// network or database bound; matchEmail itself is pure, and it is the step
// that decides whether a user's report is recognized at all. These tests
// cover it.

// newEmail builds an *email.Email with the given text and HTML bodies.
func newEmail(text, html string) *email.Email {
	return &email.Email{
		Text: []byte(text),
		HTML: []byte(html),
	}
}

// rid returns a recipient ID of exactly n characters, drawn from the same
// alphabet models.generateResultId uses.
func rid(n int) string {
	const alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	for i := range out {
		out[i] = alphaNum[i%len(alphaNum)]
	}
	return string(out)
}

// attach builds an attachment with the given filename, content type and body.
func attach(filename, contentType string, content []byte) *email.Attachment {
	header := textproto.MIMEHeader{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &email.Attachment{
		Filename: filename,
		Header:   header,
		Content:  content,
	}
}

// rawEmail renders a minimal RFC 822 message, for use as a forwarded
// attachment.
func rawEmail(body string) []byte {
	return []byte("From: victim@example.com\r\n" +
		"To: soc@example.com\r\n" +
		"Subject: Fwd: suspicious message\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		body + "\r\n")
}

func onlyRID(t *testing.T, rids map[string]bool) string {
	t.Helper()
	if len(rids) != 1 {
		t.Fatalf("got %d rids, want exactly 1: %v", len(rids), rids)
	}
	for got := range rids {
		return got
	}
	return ""
}

// TestMatchEmailAcceptsEveryGeneratedRIDLength is the regression test for the
// bug this file was written to find. models.generateResultId produces a
// recipient ID of a random length between 8 and 32 characters, but this
// package inherited Gophish's fixed-7-character pattern. Every rid was
// therefore truncated to its first 7 characters before models.GetResult was
// asked for it, so no reported email could ever be matched to a result and
// StageReport never fired for any of them.
//
// The whole documented range is covered, not a sample, because the failure
// was silent: a truncated rid looks like a perfectly well-formed rid.
func TestMatchEmailAcceptsEveryGeneratedRIDLength(t *testing.T) {
	for length := 8; length <= 32; length++ {
		want := rid(length)
		body := fmt.Sprintf("Please review: https://login.example.com/account?rid=%s", want)

		rids, err := matchEmail(newEmail(body, ""))
		if err != nil {
			t.Fatalf("length %d: matchEmail returned error: %v", length, err)
		}
		got := onlyRID(t, rids)
		if got != want {
			t.Errorf("length %d: rid = %q, want %q (a truncated rid can never be found by models.GetResult)",
				length, got, want)
		}
	}
}

// TestMatchEmailRejectsTooShortRID pins the lower bound. Seven characters is
// what the inherited pattern used to accept; nothing Olta generates is that
// short, so a 7-character candidate is not a recipient ID and must not be
// reported as one.
func TestMatchEmailRejectsTooShortRID(t *testing.T) {
	rids, err := matchEmail(newEmail("see ?rid=abcdefg for details", ""))
	if err != nil {
		t.Fatalf("matchEmail returned error: %v", err)
	}
	if len(rids) != 0 {
		t.Errorf("rids = %v, want none: 7 characters is below the generated minimum of 8", rids)
	}
}

func TestMatchEmailEncodings(t *testing.T) {
	want := rid(12)

	cases := []struct {
		name string
		body string
	}{
		{
			name: "plain query parameter",
			body: "https://login.example.com/?rid=" + want,
		},
		{
			name: "undecoded quoted-printable equals",
			body: "https://login.example.com/?rid=3D" + want,
		},
		{
			name: "Microsoft ATP url encoding",
			body: "https://safelinks.example.net/?url=https%3A%2F%2Flogin.example.com%2F%3Frid%3D" + want,
		},
		{
			name: "ATP url encoding with quoted-printable equals",
			body: "https://safelinks.example.net/%3Frid%3D3D" + want,
		},
		{
			name: "rid followed by another parameter",
			body: "https://login.example.com/?rid=" + want + "&utm_source=email",
		},
		{
			name: "rid inside an href attribute",
			body: `<a href="https://login.example.com/?rid=` + want + `">Sign in</a>`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rids, err := matchEmail(newEmail(testCase.body, ""))
			if err != nil {
				t.Fatalf("matchEmail returned error: %v", err)
			}
			if got := onlyRID(t, rids); got != want {
				t.Errorf("rid = %q, want %q", got, want)
			}
		})
	}
}

// TestMatchEmailSearchesTextAndHTML covers both bodies being scanned, and
// the deduplication that makes one rid appearing in both count once.
func TestMatchEmailSearchesTextAndHTML(t *testing.T) {
	shared := rid(9)
	htmlOnly := rid(14)

	rids, err := matchEmail(newEmail(
		"plain text copy: https://x.example/?rid="+shared,
		`<p><a href="https://x.example/?rid=`+shared+`">a</a> <a href="https://x.example/?rid=`+htmlOnly+`">b</a></p>`,
	))
	if err != nil {
		t.Fatalf("matchEmail returned error: %v", err)
	}
	if len(rids) != 2 {
		t.Fatalf("rids = %v, want exactly 2 (the shared rid counted once)", rids)
	}
	for _, want := range []string{shared, htmlOnly} {
		if !rids[want] {
			t.Errorf("rid %q missing from %v", want, rids)
		}
	}
}

func TestMatchEmailNoRID(t *testing.T) {
	rids, err := matchEmail(newEmail(
		"Hi team, this looks like a scam but there is no tracking link in it.",
		"<p>Nothing here.</p>",
	))
	if err != nil {
		t.Fatalf("matchEmail returned error: %v", err)
	}
	if len(rids) != 0 {
		t.Errorf("rids = %v, want none", rids)
	}
}

// TestMatchEmailForwardedAttachment covers the path that actually matters in
// practice: users forward the phish as an attachment rather than inline, so
// the rid is in the attached message, not the covering note.
func TestMatchEmailForwardedAttachment(t *testing.T) {
	want := rid(20)

	cases := []struct {
		name        string
		filename    string
		contentType string
	}{
		{name: "eml extension", filename: "suspicious.eml", contentType: ""},
		{name: "rfc822 content type", filename: "forwarded-message", contentType: "message/rfc822"},
		{name: "both", filename: "suspicious.eml", contentType: "message/rfc822"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			outer := newEmail("Forwarding this, looks phishy.", "")
			outer.Attachments = []*email.Attachment{
				attach(testCase.filename, testCase.contentType,
					rawEmail("https://login.example.com/?rid="+want)),
			}

			rids, err := matchEmail(outer)
			if err != nil {
				t.Fatalf("matchEmail returned error: %v", err)
			}
			if got := onlyRID(t, rids); got != want {
				t.Errorf("rid = %q, want %q", got, want)
			}
		})
	}
}

// TestMatchEmailIgnoresNonMessageAttachments proves the attachment scan is
// gated on the attachment actually being a message. A rid-shaped string in a
// screenshot's filename or a text note is not a report of that rid.
func TestMatchEmailIgnoresNonMessageAttachments(t *testing.T) {
	outer := newEmail("Screenshot attached.", "")
	outer.Attachments = []*email.Attachment{
		attach("screenshot.png", "image/png",
			[]byte("https://login.example.com/?rid="+rid(10))),
		attach("notes.txt", "text/plain",
			[]byte("https://login.example.com/?rid="+rid(11))),
	}

	rids, err := matchEmail(outer)
	if err != nil {
		t.Fatalf("matchEmail returned error: %v", err)
	}
	if len(rids) != 0 {
		t.Errorf("rids = %v, want none: only message/rfc822 and .eml attachments are parsed", rids)
	}
}

// TestMatchEmailKeepsRIDsFoundBeforeAUnparseableAttachment documents the
// error contract callers depend on. checkForNewEmails skips the whole message
// when matchEmail errors, so it matters what has already been found: the rids
// collected so far are returned alongside the error rather than discarded.
func TestMatchEmailKeepsRIDsFoundBeforeAUnparseableAttachment(t *testing.T) {
	want := rid(16)
	outer := newEmail("https://login.example.com/?rid="+want, "")
	outer.Attachments = []*email.Attachment{
		attach("broken.eml", "message/rfc822", []byte{}),
	}

	rids, err := matchEmail(outer)
	if err == nil {
		t.Fatal("matchEmail returned no error for an empty .eml attachment")
	}
	if !rids[want] {
		t.Errorf("rids = %v, want the rid found in the body to survive the attachment error", rids)
	}
}

// TestCheckRIDsAccumulates covers the accumulator contract directly:
// checkRIDs adds to the caller's map rather than replacing it, which is what
// lets matchEmail fold the body and every attachment into one set.
func TestCheckRIDsAccumulates(t *testing.T) {
	first, second := rid(8), rid(13)
	rids := map[string]bool{}

	checkRIDs(newEmail("?rid="+first, ""), rids)
	checkRIDs(newEmail("", "?rid="+second), rids)
	checkRIDs(newEmail("?rid="+first, ""), rids)

	if len(rids) != 2 || !rids[first] || !rids[second] {
		t.Errorf("rids = %v, want exactly {%q, %q}", rids, first, second)
	}
}

// TestGoPhishRegexDoesNotMatchOtherParameters guards against the pattern
// broadening into a general "any 8+ character token" match, which would
// report unrelated tracking identifiers as campaign recipients.
func TestGoPhishRegexDoesNotMatchOtherParameters(t *testing.T) {
	for _, body := range []string{
		"https://x.example/?ridge=abcdefghij",
		"https://x.example/?id=abcdefghij",
		"https://x.example/?user_rid=abcdefghij",
		"rid=abcdefghij",
		"https://x.example/?rid=",
		"https://x.example/?rid=short",
	} {
		rids, err := matchEmail(newEmail(body, ""))
		if err != nil {
			t.Fatalf("%q: matchEmail returned error: %v", body, err)
		}
		if len(rids) != 0 {
			t.Errorf("%q: rids = %v, want none", body, rids)
		}
	}
}

// TestMatchEmailStopsAtTheGeneratedMaximum pins the upper bound. A token
// longer than any rid Olta generates is captured only up to 32 characters;
// the assertion records that plainly so a future change to
// models.generateResultId's range is caught here rather than silently
// truncating again.
func TestMatchEmailStopsAtTheGeneratedMaximum(t *testing.T) {
	overlong := rid(40)
	rids, err := matchEmail(newEmail("https://x.example/?rid="+overlong, ""))
	if err != nil {
		t.Fatalf("matchEmail returned error: %v", err)
	}
	got := onlyRID(t, rids)
	if len(got) != 32 {
		t.Errorf("captured %d characters, want 32 (models.generateResultId's maximum)", len(got))
	}
	if !strings.HasPrefix(overlong, got) {
		t.Errorf("captured %q, which is not a prefix of %q", got, overlong)
	}
}

// TestRawEmailFixtureIsParseable makes sure the helper above really produces
// a message the email library accepts, so a failure in the attachment tests
// points at matchEmail rather than at the fixture.
func TestRawEmailFixtureIsParseable(t *testing.T) {
	parsed, err := email.NewEmailFromReader(bytes.NewReader(rawEmail("body text")))
	if err != nil {
		t.Fatalf("fixture is not a parseable message: %v", err)
	}
	if !strings.Contains(string(parsed.Text), "body text") {
		t.Errorf("parsed text = %q, want it to contain the body", parsed.Text)
	}
}
