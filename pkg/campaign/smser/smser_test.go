package smser

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
)

// fakeBaseClient stands in for Twilio's transport. twilio.ClientParams takes
// a client.BaseClient, and the concrete client is the only thing in the
// library that touches the network -- so implementing this three-method
// interface covers the send path end to end without a socket.
type fakeBaseClient struct {
	mu       sync.Mutex
	requests int
	lastURL  string
	lastData url.Values

	// newResponse builds a fresh response per call. It has to be a factory
	// rather than a stored *http.Response: the generated client reads the
	// body to completion, so a shared response is drained after the first
	// send and every later one fails with EOF -- which would silently turn
	// a multi-message test into a single-message test.
	newResponse func() *http.Response

	// err is returned instead of a response. A nil response with a non-nil
	// error is how the real client reports a failed send, which is the case
	// that must reach Sms.Backoff.
	err error
}

func (c *fakeBaseClient) AccountSid() string { return "AC00000000000000000000000000000000" }

func (c *fakeBaseClient) SetTimeout(time.Duration) {}

func (c *fakeBaseClient) SendRequest(_ string, rawURL string, data url.Values,
	_ map[string]interface{}) (*http.Response, error) {
	c.mu.Lock()
	c.requests++
	c.lastURL = rawURL
	c.lastData = data
	c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	return c.newResponse(), nil
}

func (c *fakeBaseClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests
}

func (c *fakeBaseClient) lastRequest() (string, url.Values) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastURL, c.lastData
}

// createdMessageResponse is a minimal Twilio "message created" reply, enough
// for the generated client to decode without error.
func createdMessageResponse() *http.Response {
	body := `{"sid":"SM00000000000000000000000000000000","status":"queued"}`
	return &http.Response{
		StatusCode: http.StatusCreated,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

// fakeSms records which of the four Sms callbacks sendSms invoked, which is
// the entire observable contract of the send loop.
type fakeSms struct {
	mu sync.Mutex

	generateErr error
	client      *twilio.RestClient

	generated int
	succeeded int
	errored   int
	backedOff int

	lastError   error
	lastBackoff error

	// callbackErr is returned by every callback, to prove sendSms keeps
	// going when a callback itself fails.
	callbackErr error
}

func (s *fakeSms) Generate(msg *TwilioMessage) error {
	s.mu.Lock()
	s.generated++
	s.mu.Unlock()
	if s.generateErr != nil {
		return s.generateErr
	}
	if s.client != nil {
		msg.Client = *s.client
	}
	to, from, body := "+15550000001", "+15550000002", "test body"
	msg.Params = openapi.CreateMessageParams{To: &to, From: &from, Body: &body}
	return nil
}

func (s *fakeSms) Success() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.succeeded++
	return s.callbackErr
}

func (s *fakeSms) Error(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errored++
	s.lastError = err
	return s.callbackErr
}

func (s *fakeSms) Backoff(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backedOff++
	s.lastBackoff = err
	return s.callbackErr
}

func (s *fakeSms) counts() (generated, succeeded, errored, backedOff int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generated, s.succeeded, s.errored, s.backedOff
}

// restClient builds a RestClient whose transport is the supplied fake.
func restClient(transport *fakeBaseClient) *twilio.RestClient {
	return twilio.NewRestClientWithParams(twilio.ClientParams{Client: transport})
}

func TestSendSmsSuccess(t *testing.T) {
	transport := &fakeBaseClient{newResponse: createdMessageResponse}
	sms := &fakeSms{client: restClient(transport)}

	sendSms(context.Background(), []Sms{sms})

	generated, succeeded, errored, backedOff := sms.counts()
	if generated != 1 {
		t.Errorf("Generate called %d times, want 1", generated)
	}
	if succeeded != 1 {
		t.Errorf("Success called %d times, want 1", succeeded)
	}
	if errored != 0 || backedOff != 0 {
		t.Errorf("Error/Backoff called %d/%d times, want 0/0 on a successful send", errored, backedOff)
	}
	if transport.count() != 1 {
		t.Errorf("transport saw %d requests, want 1", transport.count())
	}

	// The parameters Generate filled in must be what actually goes on the
	// wire; a message that generates correctly but sends empty fields would
	// still be counted a success by every assertion above.
	rawURL, data := transport.lastRequest()
	if !strings.Contains(rawURL, "/Messages.json") {
		t.Errorf("request URL = %q, want the Messages endpoint", rawURL)
	}
	if got := data.Get("To"); got != "+15550000001" {
		t.Errorf("To = %q, want the recipient Generate set", got)
	}
	if got := data.Get("Body"); got != "test body" {
		t.Errorf("Body = %q, want the body Generate set", got)
	}
}

// TestSendSmsGenerateFailureIsPermanent covers the split that matters most
// here: a Generate failure is the message's own fault (a missing template, an
// unknown recipient) and must reach Error, which marks the smslog
// permanently failed -- never Backoff, which would schedule a retry of
// something that cannot succeed.
func TestSendSmsGenerateFailureIsPermanent(t *testing.T) {
	generateErr := errors.New("no text template specified")
	transport := &fakeBaseClient{newResponse: createdMessageResponse}
	sms := &fakeSms{generateErr: generateErr}

	sendSms(context.Background(), []Sms{sms})

	_, succeeded, errored, backedOff := sms.counts()
	if errored != 1 {
		t.Errorf("Error called %d times, want 1", errored)
	}
	if sms.lastError != generateErr {
		t.Errorf("Error received %v, want the generate error %v", sms.lastError, generateErr)
	}
	if backedOff != 0 {
		t.Errorf("Backoff called %d times, want 0: a generate failure cannot be retried into success", backedOff)
	}
	if succeeded != 0 {
		t.Errorf("Success called %d times, want 0", succeeded)
	}
	if transport.count() != 0 {
		t.Errorf("transport saw %d requests, want 0: nothing should be sent for a message that failed to generate", transport.count())
	}
}

// TestSendSmsSendFailureBacksOff is the mirror case: the message generated
// fine and the send itself failed, which is transient (rate limiting, a
// carrier outage) and must reach Backoff for a retry rather than Error.
func TestSendSmsSendFailureBacksOff(t *testing.T) {
	sendErr := errors.New("429 too many requests")
	transport := &fakeBaseClient{err: sendErr}
	sms := &fakeSms{client: restClient(transport)}

	sendSms(context.Background(), []Sms{sms})

	_, succeeded, errored, backedOff := sms.counts()
	if backedOff != 1 {
		t.Errorf("Backoff called %d times, want 1", backedOff)
	}
	if sms.lastBackoff == nil {
		t.Error("Backoff received a nil error, want the send failure")
	}
	if errored != 0 {
		t.Errorf("Error called %d times, want 0: a failed send is retryable", errored)
	}
	if succeeded != 0 {
		t.Errorf("Success called %d times, want 0", succeeded)
	}
}

// TestSendSmsContinuesAfterAFailure proves one bad message does not strand
// the rest of the batch -- the whole batch shares one campaign, so an early
// failure silently dropping the remainder would look like a campaign that
// simply reached fewer people.
func TestSendSmsContinuesAfterAFailure(t *testing.T) {
	transport := &fakeBaseClient{newResponse: createdMessageResponse}

	failGenerate := &fakeSms{generateErr: errors.New("bad template")}
	failSend := &fakeSms{client: restClient(&fakeBaseClient{err: errors.New("carrier rejected")})}
	ok1 := &fakeSms{client: restClient(transport)}
	ok2 := &fakeSms{client: restClient(transport)}

	sendSms(context.Background(), []Sms{failGenerate, ok1, failSend, ok2})

	for name, sms := range map[string]*fakeSms{"first": ok1, "second": ok2} {
		if _, succeeded, _, _ := sms.counts(); succeeded != 1 {
			t.Errorf("%s healthy message: Success called %d times, want 1", name, succeeded)
		}
	}
	if _, _, errored, _ := failGenerate.counts(); errored != 1 {
		t.Errorf("generate-failure message: Error called %d times, want 1", errored)
	}
	if _, _, _, backedOff := failSend.counts(); backedOff != 1 {
		t.Errorf("send-failure message: Backoff called %d times, want 1", backedOff)
	}
}

// TestSendSmsSurvivesFailingCallbacks covers the log-and-continue contract:
// every callback's error is logged, never propagated, so a database hiccup
// while recording one result cannot abort the rest of the batch.
func TestSendSmsSurvivesFailingCallbacks(t *testing.T) {
	transport := &fakeBaseClient{newResponse: createdMessageResponse}
	first := &fakeSms{client: restClient(transport), callbackErr: errors.New("db write failed")}
	second := &fakeSms{client: restClient(transport)}

	sendSms(context.Background(), []Sms{first, second})

	if _, succeeded, _, _ := second.counts(); succeeded != 1 {
		t.Errorf("second message: Success called %d times, want 1 despite the first callback failing", succeeded)
	}
}

// TestSendSmsStopsOnCancelledContext pins the documented behavior that a
// cancelled context leaves the remaining messages *unmodified* -- not failed,
// not backed off. They stay queued for the next run, which is what makes a
// campaign resumable after a restart.
func TestSendSmsStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	transport := &fakeBaseClient{newResponse: createdMessageResponse}
	sms := &fakeSms{client: restClient(transport)}

	sendSms(ctx, []Sms{sms})

	generated, succeeded, errored, backedOff := sms.counts()
	if generated+succeeded+errored+backedOff != 0 {
		t.Errorf("message was touched (generate %d, success %d, error %d, backoff %d) after context cancellation",
			generated, succeeded, errored, backedOff)
	}
	if transport.count() != 0 {
		t.Errorf("transport saw %d requests after cancellation, want 0", transport.count())
	}
}

// TestSendSmsStopsMidBatchOnCancel covers cancellation arriving partway
// through: messages already sent keep their result, and the untouched
// remainder stays queued.
func TestSendSmsStopsMidBatchOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := &fakeBaseClient{newResponse: createdMessageResponse}

	first := &fakeSms{client: restClient(transport)}
	second := &fakeSms{client: restClient(transport)}

	// canceller sits between the two messages in the batch: it is an Sms
	// whose Generate cancels the context, so the loop's next iteration sees
	// a cancelled context at exactly the point being tested.
	canceller := &cancellingSms{fakeSms: fakeSms{client: restClient(transport)}, cancel: cancel}

	sendSms(ctx, []Sms{first, canceller, second})

	if _, succeeded, _, _ := first.counts(); succeeded != 1 {
		t.Errorf("first message: Success called %d times, want 1 -- it completed before cancellation", succeeded)
	}
	generated, succeeded, errored, backedOff := second.counts()
	if generated+succeeded+errored+backedOff != 0 {
		t.Errorf("message after cancellation was touched (generate %d, success %d, error %d, backoff %d)",
			generated, succeeded, errored, backedOff)
	}
}

type cancellingSms struct {
	fakeSms
	cancel context.CancelFunc
}

func (s *cancellingSms) Generate(msg *TwilioMessage) error {
	err := s.fakeSms.Generate(msg)
	s.cancel()
	return err
}

func TestNewSmsWorkerQueueIsUsable(t *testing.T) {
	worker := NewSmsWorker()
	if worker.queue == nil {
		t.Fatal("NewSmsWorker left the queue nil; Queue would block forever")
	}
}

// TestSmsWorkerQueueReachesSend covers the worker's own job: hand a batch to
// Queue and it ends up in sendSms.
func TestSmsWorkerQueueReachesSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	worker := NewSmsWorker()
	go worker.Start(ctx)

	transport := &fakeBaseClient{newResponse: createdMessageResponse}
	sms := &fakeSms{client: restClient(transport)}
	worker.Queue([]Sms{sms})

	deadline := time.After(2 * time.Second)
	for {
		if _, succeeded, _, _ := sms.counts(); succeeded == 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("queued message never reached the send path")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestSmsWorkerStartReturnsOnCancel pins the shutdown path: Start must return
// when its context is cancelled, or the campaign service cannot exit cleanly
// on SIGTERM.
func TestSmsWorkerStartReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	worker := NewSmsWorker()

	returned := make(chan struct{})
	go func() {
		worker.Start(ctx)
		close(returned)
	}()

	cancel()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after its context was cancelled")
	}
}
