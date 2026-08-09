package worker

import (
	"context"
	"sync"
	"time"

	log "github.com/s4l1hs/olta/pkg/campaign/logger"
	"github.com/s4l1hs/olta/pkg/campaign/mailer"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/sirupsen/logrus"
)

// Worker is an interface that defines the operations needed for a background worker
type Worker interface {
	Start()
	Shutdown() error
	LaunchCampaign(c models.Campaign)
	SendTestEmail(s *models.EmailRequest) error
}

// DefaultWorker is the background worker that handles watching for new campaigns and sending emails appropriately.
type DefaultWorker struct {
	mailer            mailer.Mailer
	minSendDelay      time.Duration
	maxSendDelay      time.Duration
	enableSpintax     bool
	enableRoleRouting bool
	ctx               context.Context
	cancel            context.CancelFunc
	started           chan struct{}
	done              chan struct{}
	startOnce         sync.Once
}

// New creates a new worker object to handle the creation of campaigns
func New(options ...func(*DefaultWorker) error) (Worker, error) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &DefaultWorker{
		ctx:     ctx,
		cancel:  cancel,
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}
	for _, opt := range options {
		if err := opt(w); err != nil {
			return nil, err
		}
	}
	if w.mailer == nil {
		w.mailer = mailer.NewMailWorker(
			mailer.WithSendDelay(w.minSendDelay, w.maxSendDelay),
			mailer.WithPersonalization(w.enableSpintax, w.enableRoleRouting),
		)
	}
	return w, nil
}

// WithSendDelay configures the default randomized interval between
// consecutive email dispatches.
func WithSendDelay(minimum, maximum time.Duration) func(*DefaultWorker) error {
	return func(w *DefaultWorker) error {
		if err := mailer.ValidateSendDelay(minimum, maximum); err != nil {
			return err
		}
		w.minSendDelay = minimum
		w.maxSendDelay = maximum
		return nil
	}
}

// WithPersonalization enables or disables rule-based message personalization.
func WithPersonalization(enableSpintax, enableRoleRouting bool) func(*DefaultWorker) error {
	return func(w *DefaultWorker) error {
		w.enableSpintax = enableSpintax
		w.enableRoleRouting = enableRoleRouting
		return nil
	}
}

// WithDeliveryOptions configures both send jitter and personalization without
// one worker option replacing the mailer configured by the other.
func WithDeliveryOptions(minimum, maximum time.Duration, enableSpintax, enableRoleRouting bool) func(*DefaultWorker) error {
	return func(w *DefaultWorker) error {
		if err := mailer.ValidateSendDelay(minimum, maximum); err != nil {
			return err
		}
		w.minSendDelay = minimum
		w.maxSendDelay = maximum
		w.enableSpintax = enableSpintax
		w.enableRoleRouting = enableRoleRouting
		return nil
	}
}

// WithMailer sets the mailer for a given worker.
// By default, workers use a standard, default mailworker.
func WithMailer(m mailer.Mailer) func(*DefaultWorker) error {
	return func(w *DefaultWorker) error {
		w.mailer = m
		return nil
	}
}

// processCampaigns loads maillogs scheduled to be sent before the provided
// time and sends them to the mailer.
func (w *DefaultWorker) processCampaigns(t time.Time) error {
	ms, err := models.GetQueuedMailLogs(t.UTC())
	if err != nil {
		log.Error(err)
		return err
	}
	// Lock the MailLogs (they will be unlocked after processing)
	err = models.LockMailLogs(ms, true)
	if err != nil {
		return err
	}
	campaignCache := make(map[int64]models.Campaign)
	// We'll group the maillogs by campaign ID to (roughly) group
	// them by sending profile. This lets the mailer re-use the Sender
	// instead of having to re-connect to the SMTP server for every
	// email.
	msg := make(map[int64][]mailer.Mail)
	for _, m := range ms {
		// We cache the campaign here to greatly reduce the time it takes to
		// generate the message (ref #1726)
		c, ok := campaignCache[m.CampaignId]
		if !ok {
			c, err = models.GetCampaignMailContext(m.CampaignId, m.UserId)
			if err != nil {
				return err
			}
			campaignCache[c.Id] = c
		}
		m.CacheCampaign(&c)
		msg[m.CampaignId] = append(msg[m.CampaignId], m)
	}

	// Next, we process each group of maillogs in parallel
	for cid, msc := range msg {
		go func(cid int64, msc []mailer.Mail) {
			c := campaignCache[cid]
			if c.Status == models.CampaignQueued {
				err := c.UpdateStatus(models.CampaignInProgress)
				if err != nil {
					log.Error(err)
					return
				}
			}
			log.WithFields(logrus.Fields{
				"num_emails": len(msc),
			}).Info("Sending emails to mailer for processing")
			w.mailer.Queue(msc)
		}(cid, msc)
	}
	return nil
}

// Start launches the worker to poll the database every minute for any pending maillogs
// that need to be processed.
func (w *DefaultWorker) Start() {
	w.startOnce.Do(func() {
		close(w.started)
		defer close(w.done)
		log.Info("Background Email Worker Started Successfully - Waiting for Campaigns")
		mailerDone := make(chan struct{})
		go func() {
			w.mailer.Start(w.ctx)
			close(mailerDone)
		}()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-w.ctx.Done():
				<-mailerDone
				return
			case t := <-ticker.C:
				if err := w.processCampaigns(t); err != nil {
					log.Error(err)
				}
			}
		}
	})
}

// Shutdown cancels active delay waits, waits for mail dispatch goroutines to
// stop, and unlocks persisted mail logs so campaign state can resume cleanly.
func (w *DefaultWorker) Shutdown() error {
	if w == nil {
		return nil
	}
	if w.cancel == nil {
		return models.UnlockAllMailLogs()
	}
	w.cancel()
	select {
	case <-w.started:
		<-w.done
	default:
	}
	return models.UnlockAllMailLogs()
}

// LaunchCampaign starts a campaign
func (w *DefaultWorker) LaunchCampaign(c models.Campaign) {
	ms, err := models.GetMailLogsByCampaign(c.Id)
	if err != nil {
		log.Error(err)
		return
	}
	models.LockMailLogs(ms, true)
	// This is required since you cannot pass a slice of values
	// that implements an interface as a slice of that interface.
	mailEntries := []mailer.Mail{}
	currentTime := time.Now().UTC()
	campaignMailCtx, err := models.GetCampaignMailContext(c.Id, c.UserId)
	if err != nil {
		log.Error(err)
		return
	}
	for _, m := range ms {
		// Only send the emails scheduled to be sent for the past minute to
		// respect the campaign scheduling options
		if m.SendDate.After(currentTime) {
			m.Unlock()
			continue
		}
		err = m.CacheCampaign(&campaignMailCtx)
		if err != nil {
			log.Error(err)
			return
		}
		mailEntries = append(mailEntries, m)
	}
	w.mailer.Queue(mailEntries)
}

// SendTestEmail sends a test email
func (w *DefaultWorker) SendTestEmail(s *models.EmailRequest) error {
	go func() {
		ms := []mailer.Mail{s}
		w.mailer.Queue(ms)
	}()
	return <-s.ErrorChan
}
