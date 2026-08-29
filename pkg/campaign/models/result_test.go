package models

import (
	"net/mail"
	"regexp"
	"time"

	"github.com/s4l1hs/olta/pkg/telemetry"
	"gopkg.in/check.v1"
)

func (s *ModelsSuite) TestGenerateResultId(c *check.C) {
	r := Result{}
	r.GenerateId(db)
	match, err := regexp.Match("[a-zA-Z0-9]{7}", []byte(r.RId))
	c.Assert(err, check.Equals, nil)
	c.Assert(match, check.Equals, true)
}

func (s *ModelsSuite) TestFormatAddress(c *check.C) {
	r := Result{
		BaseRecipient: BaseRecipient{
			FirstName: "John",
			LastName:  "Doe",
			Email:     "johndoe@example.com",
		},
	}
	expected := &mail.Address{
		Name:    "John Doe",
		Address: "johndoe@example.com",
	}
	c.Assert(r.FormatAddress(), check.Equals, expected.String())

	r = Result{
		BaseRecipient: BaseRecipient{Email: "johndoe@example.com"},
	}
	c.Assert(r.FormatAddress(), check.Equals, r.Email)
}

func (s *ModelsSuite) TestResultSendingStatus(ch *check.C) {
	c := s.createCampaignDependencies(ch)
	ch.Assert(PostCampaign(&c, c.UserId), check.Equals, nil)
	// This campaign wasn't scheduled, so we expect the status to
	// be sending
	for _, r := range c.Results {
		ch.Assert(r.Status, check.Equals, StatusSending)
		ch.Assert(r.ModifiedDate, check.Equals, c.CreatedDate)
	}
}
func (s *ModelsSuite) TestResultScheduledStatus(ch *check.C) {
	c := s.createCampaignDependencies(ch)
	c.LaunchDate = time.Now().UTC().Add(time.Hour * time.Duration(1))
	ch.Assert(PostCampaign(&c, c.UserId), check.Equals, nil)
	// This campaign wasn't scheduled, so we expect the status to
	// be sending
	for _, r := range c.Results {
		ch.Assert(r.Status, check.Equals, StatusScheduled)
		ch.Assert(r.ModifiedDate, check.Equals, c.CreatedDate)
	}
}

func (s *ModelsSuite) TestResultVariableStatus(ch *check.C) {
	c := s.createCampaignDependencies(ch)
	c.LaunchDate = time.Now().UTC()
	c.SendByDate = c.LaunchDate.Add(2 * time.Minute)
	ch.Assert(PostCampaign(&c, c.UserId), check.Equals, nil)

	// The campaign has a window smaller than our group size, so we expect some
	// emails to be sent immediately, while others will be scheduled
	for _, r := range c.Results {
		if r.SendDate.Before(c.CreatedDate) || r.SendDate.Equal(c.CreatedDate) {
			ch.Assert(r.Status, check.Equals, StatusSending)
		} else {
			ch.Assert(r.Status, check.Equals, StatusScheduled)
		}
	}
}

func (s *ModelsSuite) TestDuplicateResults(ch *check.C) {
	group := Group{Name: "Test Group"}
	group.Targets = []Target{
		Target{BaseRecipient: BaseRecipient{Email: "test1@example.com", FirstName: "First", LastName: "Example"}},
		Target{BaseRecipient: BaseRecipient{Email: "test1@example.com", FirstName: "Duplicate", LastName: "Duplicate"}},
		Target{BaseRecipient: BaseRecipient{Email: "test2@example.com", FirstName: "Second", LastName: "Example"}},
	}
	group.UserId = 1
	ch.Assert(PostGroup(&group), check.Equals, nil)

	// Add a template
	t := Template{Name: "Test Template"}
	t.Subject = "{{.RId}} - Subject"
	t.Text = "{{.RId}} - Text"
	t.HTML = "{{.RId}} - HTML"
	t.UserId = 1
	ch.Assert(PostTemplate(&t), check.Equals, nil)

	// Add a sending profile
	smtp := SMTP{Name: "Test Page"}
	smtp.UserId = 1
	smtp.Host = "example.com"
	smtp.FromAddress = "test@test.com"
	ch.Assert(PostSMTP(&smtp), check.Equals, nil)

	c := Campaign{Name: "Test campaign"}
	c.UserId = 1
	c.Template = t
	c.SMTP = smtp
	c.Groups = []Group{group}

	ch.Assert(PostCampaign(&c, c.UserId), check.Equals, nil)
	ch.Assert(len(c.Results), check.Equals, 2)
	ch.Assert(c.Results[0].Email, check.Equals, group.Targets[0].Email)
	ch.Assert(c.Results[1].Email, check.Equals, group.Targets[2].Email)
}

func (s *ModelsSuite) TestHandleEmailSentEmitsDeliveryTelemetry(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-email-sent", BaseRecipient: BaseRecipient{Email: "victim@example.com"}}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleEmailSent(), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Stage, check.Equals, telemetry.StageDelivery)
	ch.Assert(events[0].CampaignID, check.Equals, int64(1))
	ch.Assert(events[0].RID, check.Equals, "telemetry-email-sent")
}

func (s *ModelsSuite) TestHandleSMSSentEmitsDeliveryTelemetry(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-sms-sent", BaseRecipient: BaseRecipient{Email: "victim@example.com"}}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleSMSSent(), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Stage, check.Equals, telemetry.StageDelivery)
	ch.Assert(events[0].CampaignID, check.Equals, int64(1))
	ch.Assert(events[0].RID, check.Equals, "telemetry-sms-sent")
}

func (s *ModelsSuite) TestHandleEmailOpenedEmitsOpenTelemetry(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-email-opened", IP: "203.0.113.9", BaseRecipient: BaseRecipient{Email: "victim@example.com"}}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleEmailOpened(EventDetails{}), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Stage, check.Equals, telemetry.StageOpen)
	ch.Assert(events[0].Actor.IP, check.Equals, "203.0.113.9")
}

func (s *ModelsSuite) TestHandleEmailSentEmitsEmailMedium(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-medium-email-sent", BaseRecipient: BaseRecipient{Email: "victim@example.com"}}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleEmailSent(), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Detail["medium"], check.Equals, "email")
}

func (s *ModelsSuite) TestHandleSMSSentEmitsSMSMedium(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-medium-sms-sent", BaseRecipient: BaseRecipient{Email: "victim@example.com"}}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleSMSSent(), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Detail["medium"], check.Equals, "sms")
}

func (s *ModelsSuite) TestHandleEmailOpenedEmitsEmailMedium(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-medium-email-opened", BaseRecipient: BaseRecipient{Email: "victim@example.com"}, SMSTarget: false}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleEmailOpened(EventDetails{}), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Detail["medium"], check.Equals, "email")
}

func (s *ModelsSuite) TestHandleSMSOpenedEmitsSMSMedium(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-medium-sms-opened", BaseRecipient: BaseRecipient{Email: "victim@example.com"}, SMSTarget: true}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleSMSOpened(EventDetails{}), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Detail["medium"], check.Equals, "sms")
}

func (s *ModelsSuite) TestHandleSMSOpenedEmitsOpenTelemetry(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-sms-opened", BaseRecipient: BaseRecipient{Email: "victim@example.com"}}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleSMSOpened(EventDetails{}), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Stage, check.Equals, telemetry.StageOpen)
}

func (s *ModelsSuite) TestHandleEmailReportEmitsReportTelemetryWithNoTechnique(ch *check.C) {
	emitter := &captureEmitter{}
	SetTelemetryEmitter(emitter)
	defer SetTelemetryEmitter(nil)

	r := &Result{CampaignId: 1, RId: "telemetry-reported", BaseRecipient: BaseRecipient{Email: "victim@example.com"}}
	ch.Assert(db.Save(r).Error, check.Equals, nil)

	ch.Assert(r.HandleEmailReport(EventDetails{}), check.Equals, nil)

	events := emitter.all()
	ch.Assert(len(events), check.Equals, 1)
	ch.Assert(events[0].Stage, check.Equals, telemetry.StageReport)
	ch.Assert(len(events[0].Techniques), check.Equals, 0)
}
