package smsworker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/s4l1hs/olta/pkg/campaign/config"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/smser"
)

// recordingSmser stands in for the Twilio-backed smser. The worker's whole
// job is deciding *which* messages get handed over and when, so recording the
// batches it queues is the entire observable contract.
type recordingSmser struct {
	mu      sync.Mutex
	batches [][]smser.Sms
	started chan struct{}
}

func (s *recordingSmser) Start(ctx context.Context) {
	if s.started != nil {
		close(s.started)
	}
	<-ctx.Done()
}

func (s *recordingSmser) Queue(sms []smser.Sms) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, sms)
}

func (s *recordingSmser) snapshot() [][]smser.Sms {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]smser.Sms, len(s.batches))
	copy(out, s.batches)
	return out
}

// total counts every message across every batch queued so far.
func (s *recordingSmser) total() int {
	count := 0
	for _, batch := range s.snapshot() {
		count += len(batch)
	}
	return count
}

// waitForTotal polls until the smser has seen want messages, because
// processCampaigns queues each campaign's batch from its own goroutine.
func (s *recordingSmser) waitForTotal(t *testing.T, want int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if s.total() >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("smser saw %d messages, want %d", s.total(), want)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

const recipientsPerGroup = 5

func setupTest(t *testing.T) {
	t.Helper()
	conf := &config.Config{
		DBName:   "sqlite3",
		DBPath:   ":memory:",
		TestFlag: true,
	}
	if err := models.Setup(conf); err != nil {
		t.Fatalf("failed creating database: %v", err)
	}

	group := models.Group{Name: "Test Group", UserId: 1}
	for i := 0; i < recipientsPerGroup; i++ {
		group.Targets = append(group.Targets, models.Target{
			BaseRecipient: models.BaseRecipient{
				Email:     fmt.Sprintf("+1555000000%d", i),
				FirstName: "First",
				LastName:  "Example",
			},
		})
	}
	if err := models.PostGroup(&group); err != nil {
		t.Fatalf("failed creating group: %v", err)
	}

	template := models.Template{Name: "Test SMS Template", UserId: 1}
	template.Subject = "Test subject"
	template.Text = "Hello {{.FirstName}}, visit {{.URL}}"
	if err := models.PostTemplate(&template); err != nil {
		t.Fatalf("failed creating template: %v", err)
	}

	sms := models.SMS{
		Name:             "Test SMS Profile",
		UserId:           1,
		TwilioAccountSid: "AC00000000000000000000000000000000",
		TwilioAuthToken:  "test-auth-token",
		SMSFrom:          "+15550009999",
	}
	if err := models.PostSMS(&sms); err != nil {
		t.Fatalf("failed creating sms profile: %v", err)
	}
}

// setupSMSCampaign creates an SMS campaign and unlocks its smslogs so the
// worker will pick them up, mirroring what the campaign service does once a
// campaign is launched.
func setupSMSCampaign(t *testing.T, name string) *models.Campaign {
	t.Helper()
	return postSMSCampaign(t, name, time.Time{})
}

// setupSpreadSMSCampaign creates a campaign whose messages are spread across
// the given window by Campaign.generateSendDate, so only the first is due
// immediately. That is the real scheduling path, rather than rewriting send
// dates behind the model's back.
func setupSpreadSMSCampaign(t *testing.T, name string, window time.Duration) *models.Campaign {
	t.Helper()
	return postSMSCampaign(t, name, time.Now().UTC().Add(window))
}

func postSMSCampaign(t *testing.T, name string, sendBy time.Time) *models.Campaign {
	t.Helper()

	template, err := models.GetTemplate(1, 1)
	if err != nil {
		t.Fatalf("failed loading template: %v", err)
	}
	sms, err := models.GetSMS(1, 1)
	if err != nil {
		t.Fatalf("failed loading sms profile: %v", err)
	}
	group, err := models.GetGroup(1, 1)
	if err != nil {
		t.Fatalf("failed loading group: %v", err)
	}

	campaign := models.Campaign{Name: name, UserId: 1}
	campaign.Template = template
	campaign.SMS = sms
	campaign.Groups = []models.Group{group}
	if !sendBy.IsZero() {
		campaign.LaunchDate = time.Now().UTC()
		campaign.SendByDate = sendBy
	}

	if err := models.PostSMSCampaign(&campaign, campaign.UserId); err != nil {
		t.Fatalf("failed creating sms campaign: %v", err)
	}

	logs, err := models.GetSmsLogsByCampaign(campaign.Id)
	if err != nil {
		t.Fatalf("failed loading smslogs: %v", err)
	}
	for _, log := range logs {
		if err := log.Unlock(); err != nil {
			t.Fatalf("failed unlocking smslog: %v", err)
		}
	}
	return &campaign
}

func TestNewUsesADefaultSmser(t *testing.T) {
	worker, err := New()
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defaultWorker, ok := worker.(*DefaultWorker)
	if !ok {
		t.Fatalf("New returned %T, want *DefaultWorker", worker)
	}
	if defaultWorker.smser == nil {
		t.Fatal("New left smser nil; Start would panic on a nil smser")
	}
}

func TestWithSmserOverridesTheDefault(t *testing.T) {
	replacement := &recordingSmser{}
	worker, err := New(func(w Worker) error {
		return WithSmser(replacement)(w.(*DefaultWorker))
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if got := worker.(*DefaultWorker).smser; got != replacement {
		t.Errorf("smser = %p, want the injected one %p", got, replacement)
	}
}

func TestNewPropagatesOptionErrors(t *testing.T) {
	optionErr := errors.New("option failed")
	worker, err := New(func(Worker) error { return optionErr })
	if !errors.Is(err, optionErr) {
		t.Errorf("New error = %v, want %v", err, optionErr)
	}
	if worker != nil {
		t.Errorf("New returned a worker (%v) alongside an error; a half-configured worker must never escape", worker)
	}
}

// TestProcessCampaignsGroupsBySendingProfile covers the batching contract the
// function's own comment states: smslogs are grouped by campaign so each
// batch shares one sending profile, rather than being handed over one at a
// time or all mixed together.
func TestProcessCampaignsGroupsBySendingProfile(t *testing.T) {
	setupTest(t)

	const campaigns = 3
	for i := 0; i < campaigns; i++ {
		setupSMSCampaign(t, fmt.Sprintf("Test SMS campaign - %d", i))
	}

	recorder := &recordingSmser{}
	worker := &DefaultWorker{smser: recorder}

	if err := worker.processCampaigns(time.Now().UTC()); err != nil {
		t.Fatalf("processCampaigns returned error: %v", err)
	}
	recorder.waitForTotal(t, campaigns*recipientsPerGroup)

	batches := recorder.snapshot()
	if len(batches) != campaigns {
		t.Fatalf("got %d batches, want one per campaign (%d)", len(batches), campaigns)
	}
	for i, batch := range batches {
		if len(batch) != recipientsPerGroup {
			t.Errorf("batch %d has %d messages, want %d", i, len(batch), recipientsPerGroup)
		}
	}
}

// TestProcessCampaignsLocksWhatItQueues pins the property that keeps a
// message from being sent twice: everything handed to the smser is marked as
// processing, so the next poll a minute later does not pick it up again.
func TestProcessCampaignsLocksWhatItQueues(t *testing.T) {
	setupTest(t)
	campaign := setupSMSCampaign(t, "Test SMS campaign - locking")

	recorder := &recordingSmser{}
	worker := &DefaultWorker{smser: recorder}

	if err := worker.processCampaigns(time.Now().UTC()); err != nil {
		t.Fatalf("processCampaigns returned error: %v", err)
	}
	recorder.waitForTotal(t, recipientsPerGroup)

	logs, err := models.GetSmsLogsByCampaign(campaign.Id)
	if err != nil {
		t.Fatalf("failed loading smslogs: %v", err)
	}
	for _, log := range logs {
		if !log.Processing {
			t.Errorf("smslog %d is not locked after being queued; the next poll would send it again", log.Id)
		}
	}

	// A second pass must find nothing: everything is locked.
	second := &recordingSmser{}
	secondWorker := &DefaultWorker{smser: second}
	if err := secondWorker.processCampaigns(time.Now().UTC()); err != nil {
		t.Fatalf("second processCampaigns returned error: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := second.total(); got != 0 {
		t.Errorf("second pass queued %d messages, want 0", got)
	}
}

// TestProcessCampaignsMovesQueuedCampaignsInProgress covers the status
// transition an operator watches in the dashboard.
func TestProcessCampaignsMovesQueuedCampaignsInProgress(t *testing.T) {
	setupTest(t)
	campaign := setupSMSCampaign(t, "Test SMS campaign - status")
	if err := campaign.UpdateStatus(models.CampaignQueued); err != nil {
		t.Fatalf("failed setting campaign status: %v", err)
	}

	recorder := &recordingSmser{}
	worker := &DefaultWorker{smser: recorder}
	if err := worker.processCampaigns(time.Now().UTC()); err != nil {
		t.Fatalf("processCampaigns returned error: %v", err)
	}
	recorder.waitForTotal(t, recipientsPerGroup)

	// The status update happens in the same goroutine that queues the batch,
	// so it is settled by the time the batch is visible -- but read it back
	// through the database rather than the in-memory struct.
	deadline := time.After(3 * time.Second)
	for {
		reloaded, err := models.GetCampaign(campaign.Id, campaign.UserId)
		if err != nil {
			t.Fatalf("failed reloading campaign: %v", err)
		}
		if reloaded.Status == models.CampaignInProgress {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("campaign status = %q, want %q", reloaded.Status, models.CampaignInProgress)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestProcessCampaignsWithNothingQueued covers the ordinary idle poll: the
// worker runs every minute whether or not there is anything to do.
func TestProcessCampaignsWithNothingQueued(t *testing.T) {
	setupTest(t)

	recorder := &recordingSmser{}
	worker := &DefaultWorker{smser: recorder}

	if err := worker.processCampaigns(time.Now().UTC()); err != nil {
		t.Fatalf("processCampaigns returned error on an empty queue: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := recorder.total(); got != 0 {
		t.Errorf("queued %d messages with nothing scheduled, want 0", got)
	}
}

// TestLaunchCampaignSkipsFutureMessages is the scheduling guarantee. A
// campaign with a send-by window spreads its messages over time; launching it
// must hand over only what is due now and leave the rest *unlocked* for a
// later poll. Locking a message it did not queue would strand it forever.
func TestLaunchCampaignSkipsFutureMessages(t *testing.T) {
	setupTest(t)
	// 5 recipients across 50 minutes puts them at +0, +10, +20, +30 and +40
	// minutes, so exactly one is due now.
	campaign := setupSpreadSMSCampaign(t, "Test SMS campaign - scheduling", 50*time.Minute)

	recorder := &recordingSmser{}
	worker := &DefaultWorker{smser: recorder}
	worker.LaunchCampaign(*campaign)

	recorder.waitForTotal(t, 1)
	time.Sleep(50 * time.Millisecond)
	if got := recorder.total(); got != 1 {
		t.Errorf("queued %d messages, want only the 1 that is due now", got)
	}

	logs, err := models.GetSmsLogsByCampaign(campaign.Id)
	if err != nil {
		t.Fatalf("failed reloading smslogs: %v", err)
	}
	now := time.Now().UTC()
	locked, future := 0, 0
	for _, log := range logs {
		if log.SendDate.After(now) {
			future++
			if log.Processing {
				t.Errorf("smslog %d scheduled for %s is still locked; it would never be picked up again",
					log.Id, log.SendDate)
			}
			continue
		}
		if log.Processing {
			locked++
		}
	}
	if future != recipientsPerGroup-1 {
		t.Errorf("got %d future-dated smslogs, want %d", future, recipientsPerGroup-1)
	}
	if locked != 1 {
		t.Errorf("got %d locked smslogs, want 1 (the one that was queued)", locked)
	}
}

// TestLaunchCampaignQueuesEverythingDue is the complement: with nothing
// scheduled ahead, every message goes at once.
func TestLaunchCampaignQueuesEverythingDue(t *testing.T) {
	setupTest(t)
	campaign := setupSMSCampaign(t, "Test SMS campaign - launch")

	recorder := &recordingSmser{}
	worker := &DefaultWorker{smser: recorder}
	worker.LaunchCampaign(*campaign)

	recorder.waitForTotal(t, recipientsPerGroup)
	batches := recorder.snapshot()
	if len(batches) != 1 {
		t.Fatalf("got %d batches, want 1: a launch queues the campaign in one go", len(batches))
	}
	if len(batches[0]) != recipientsPerGroup {
		t.Errorf("batch has %d messages, want %d", len(batches[0]), recipientsPerGroup)
	}
}
