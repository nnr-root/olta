package models

import (
	"net/mail"
	"regexp"
	"strings"
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

func (s *ModelsSuite) TestSetResultSessionMetadataUpdatesFields(ch *check.C) {
	c := s.createCampaign(ch)
	ch.Assert(len(c.Results) > 0, check.Equals, true)
	rid := c.Results[0].RId

	tag := "hot-lead"
	notes := "Escalated to blue team"
	status := SessionStatusTriaged
	updated, err := SetResultSessionMetadata(c.Id, c.UserId, rid, &tag, &notes, &status)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(updated.Tag, check.Equals, tag)
	ch.Assert(updated.Notes, check.Equals, notes)
	ch.Assert(updated.SessionStatus, check.Equals, status)

	reloaded, err := GetResult(rid)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(reloaded.Tag, check.Equals, tag)
	ch.Assert(reloaded.Notes, check.Equals, notes)
	ch.Assert(reloaded.SessionStatus, check.Equals, status)
}

// TestSetResultSessionMetadataPartialUpdateLeavesOtherFieldsAlone confirms
// a nil field pointer really does leave that column untouched, so the
// dashboard can save a single edited field (e.g. just the tag, on blur)
// without clobbering notes an operator is still typing in another control.
func (s *ModelsSuite) TestSetResultSessionMetadataPartialUpdateLeavesOtherFieldsAlone(ch *check.C) {
	c := s.createCampaign(ch)
	rid := c.Results[0].RId
	tag := "first-tag"
	notes := "first-notes"
	status := SessionStatusTriaged
	_, err := SetResultSessionMetadata(c.Id, c.UserId, rid, &tag, &notes, &status)
	ch.Assert(err, check.Equals, nil)

	onlyTag := "second-tag"
	updated, err := SetResultSessionMetadata(c.Id, c.UserId, rid, &onlyTag, nil, nil)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(updated.Tag, check.Equals, onlyTag)
	ch.Assert(updated.Notes, check.Equals, notes)
	ch.Assert(updated.SessionStatus, check.Equals, status)

	reloaded, err := GetResult(rid)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(reloaded.Tag, check.Equals, onlyTag)
	ch.Assert(reloaded.Notes, check.Equals, notes)
	ch.Assert(reloaded.SessionStatus, check.Equals, status)
}

func (s *ModelsSuite) TestSetResultSessionMetadataRejectsInvalidStatus(ch *check.C) {
	c := s.createCampaign(ch)
	rid := c.Results[0].RId
	bogus := "not-a-real-status"
	_, err := SetResultSessionMetadata(c.Id, c.UserId, rid, nil, nil, &bogus)
	ch.Assert(err, check.Equals, ErrInvalidSessionStatus)
}

func (s *ModelsSuite) TestSetResultSessionMetadataRejectsOversizedTag(ch *check.C) {
	c := s.createCampaign(ch)
	rid := c.Results[0].RId
	tooLong := strings.Repeat("a", MaxSessionTagLength+1)
	_, err := SetResultSessionMetadata(c.Id, c.UserId, rid, &tooLong, nil, nil)
	ch.Assert(err, check.Equals, ErrSessionTagTooLong)
}

func (s *ModelsSuite) TestSetResultSessionMetadataRejectsOversizedNotes(ch *check.C) {
	c := s.createCampaign(ch)
	rid := c.Results[0].RId
	tooLong := strings.Repeat("a", MaxSessionNotesLength+1)
	_, err := SetResultSessionMetadata(c.Id, c.UserId, rid, nil, &tooLong, nil)
	ch.Assert(err, check.Equals, ErrSessionNotesTooLong)
}

// TestSetResultSessionMetadataEnforcesCampaignOwnership is the IDOR check
// at the model layer: a uid that does not own the campaign must not be
// able to tag a session in it, even with a correct rid.
func (s *ModelsSuite) TestSetResultSessionMetadataEnforcesCampaignOwnership(ch *check.C) {
	c := s.createCampaign(ch)
	rid := c.Results[0].RId
	tag := "should-not-apply"
	_, err := SetResultSessionMetadata(c.Id, 999, rid, &tag, nil, nil)
	ch.Assert(err, check.Equals, ErrSessionNotFound)

	reloaded, err := GetResult(rid)
	ch.Assert(err, check.Equals, nil)
	ch.Assert(reloaded.Tag, check.Equals, "")
}

// TestSetResultSessionMetadataRejectsCrossCampaignRid confirms a valid rid
// from one campaign cannot be tagged by naming a *different* campaign the
// same operator happens to also own -- the rid has to actually belong to
// the campaign named in the request.
func (s *ModelsSuite) TestSetResultSessionMetadataRejectsCrossCampaignRid(ch *check.C) {
	a := s.createCampaign(ch)
	b := s.createCampaign(ch)

	rid := a.Results[0].RId
	tag := "should-not-apply"
	_, err := SetResultSessionMetadata(b.Id, b.UserId, rid, &tag, nil, nil)
	ch.Assert(err, check.Equals, ErrSessionNotFound)
}
