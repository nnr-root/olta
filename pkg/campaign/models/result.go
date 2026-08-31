package models

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/oschwald/maxminddb-golang"
	log "github.com/s4l1hs/olta/pkg/campaign/logger"
	feedclient "github.com/s4l1hs/olta/pkg/feed/client"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

type mmCity struct {
	GeoPoint mmGeoPoint `maxminddb:"location"`
}

type mmGeoPoint struct {
	Latitude  float64 `maxminddb:"latitude"`
	Longitude float64 `maxminddb:"longitude"`
}

// Result contains the fields for a result object,
// which is a representation of a target in a campaign.
//
// Tag, Notes, and SessionStatus are operator-facing metadata for triaging
// captured sessions in a multi-operator engagement (see
// SetResultSessionMetadata) -- distinct from Status, which tracks the
// recipient's position in the send/open/click/capture funnel. Every field
// gorm reads or writes here carries an explicit column tag: this struct
// already has one field (RId) whose default snake_case mapping ("r_id")
// happens to be correct only by chance of spelling, and a past migration
// elsewhere in this repo silently lost data to exactly that kind of
// mismatch, so nothing here is left to gorm's naming convention to get
// right on its own.
type Result struct {
	Id                int64     `json:"-" gorm:"column:id"`
	CampaignId        int64     `json:"-" gorm:"column:campaign_id"`
	UserId            int64     `json:"-" gorm:"column:user_id"`
	RId               string    `json:"id" gorm:"column:r_id"`
	Status            string    `json:"status" sql:"not null" gorm:"column:status"`
	IP                string    `json:"ip" gorm:"column:ip"`
	Latitude          float64   `json:"latitude" gorm:"column:latitude"`
	Longitude         float64   `json:"longitude" gorm:"column:longitude"`
	SendDate          time.Time `json:"send_date" gorm:"column:send_date"`
	Reported          bool      `json:"reported" sql:"not null" gorm:"column:reported"`
	ModifiedDate      time.Time `json:"modified_date" gorm:"column:modified_date"`
	TemplateVariantId int64     `json:"template_variant_id" gorm:"column:template_variant_id"`
	BaseRecipient
	SMSTarget     bool   `json:"sms_target" gorm:"column:sms_target"`
	Tag           string `json:"tag" gorm:"column:tag"`
	Notes         string `json:"notes" gorm:"column:notes"`
	SessionStatus string `json:"session_status" gorm:"column:session_status"`
}

// Session tagging status values. Operators set one of these through
// SetResultSessionMetadata; nothing else is accepted, so the dashboard's
// filter control can rely on a closed set rather than free text.
const (
	SessionStatusUntriaged = "untriaged"
	SessionStatusTriaged   = "triaged"
	SessionStatusHighValue = "high_value"
	SessionStatusReplayed  = "replayed"
	SessionStatusDiscarded = "discarded"
)

// SessionStatuses lists every valid SessionStatus value, in the order the
// dashboard should offer them.
var SessionStatuses = []string{
	SessionStatusUntriaged,
	SessionStatusTriaged,
	SessionStatusHighValue,
	SessionStatusReplayed,
	SessionStatusDiscarded,
}

func isValidSessionStatus(status string) bool {
	for _, valid := range SessionStatuses {
		if status == valid {
			return true
		}
	}
	return false
}

// Bounds for the operator free-text fields. These match the results.tag
// and results.notes column widths declared in the schema (see
// pkg/campaign/migrations); enforcing them here as well means a
// too-long value is rejected with a clear error instead of failing (or
// silently truncating, depending on driver/dialect) at the database.
const (
	MaxSessionTagLength   = 120
	MaxSessionNotesLength = 2000
)

type FeedEvent struct {
	Event   string `json:"event"`
	Time    string `json:"time"`
	Message string `json:"message"`
}

func (r *Result) NotifyEmailSent() error {
	c, _, err := feedclient.DialPublisher(conf.FeedURL)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Event = "Email Sent"
	fe.Message = "Email has been sent to victim: " + r.Email
	fe.Time = r.ModifiedDate.String()
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	if err != nil {
		return err
	}
	return err
}

func (r *Result) NotifySMSSent() error {
	c, _, err := feedclient.DialPublisher(conf.FeedURL)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Event = "SMS Sent"
	fe.Message = "SMS has been sent to victim: " + r.Email
	fe.Time = r.ModifiedDate.String()
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	if err != nil {
		return err
	}
	return err
}

// medium reports which channel delivered the lure, so telemetry can carry it
// as detail. SMS reuses the email spearphishing-link technique (Enterprise
// ATT&CK has no smishing sub-technique), so this is the only place the two
// channels are told apart.
func medium(smsTarget bool) string {
	if smsTarget {
		return "sms"
	}
	return "email"
}

func (r *Result) createEvent(status string, details interface{}) (*Event, error) {
	e := &Event{Email: r.Email, Message: status}
	if details != nil {
		dj, err := json.Marshal(details)
		if err != nil {
			return nil, err
		}
		e.Details = string(dj)
	}
	AddEvent(e, r.CampaignId)
	return e, nil
}

func (r *Result) HandleSMSSent() error {
	event, err := r.createEvent(EventSent, nil)
	if err != nil {
		return err
	}
	r.SendDate = event.Time
	r.Status = EventSent
	r.ModifiedDate = event.Time
	r.SMSTarget = true

	if conf.FeedEnabled {
		err = r.NotifySMSSent()
		if err != nil {
			log.Errorf("Error sending websocket message: %v", err)
		}
	}

	EmitTelemetry(
		telemetry.New(telemetry.StageDelivery, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink).
			WithCampaign(r.CampaignId, r.RId).
			WithDetail("medium", medium(r.SMSTarget)),
	)

	return db.Save(r).Error
}

// HandleEmailSent updates a Result to indicate that the email has been
// successfully sent to the remote SMTP server
func (r *Result) HandleEmailSent() error {
	event, err := r.createEvent(EventSent, nil)
	if err != nil {
		return err
	}
	r.SendDate = event.Time
	r.Status = EventSent
	r.ModifiedDate = event.Time
	r.SMSTarget = false

	if conf.FeedEnabled {
		err = r.NotifyEmailSent()
		if err != nil {
			log.Errorf("Error sending websocket message: %v", err)
		}
	}

	EmitTelemetry(
		telemetry.New(telemetry.StageDelivery, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink).
			WithCampaign(r.CampaignId, r.RId).
			WithDetail("medium", medium(r.SMSTarget)),
	)

	return db.Save(r).Error
}

// HandleEmailError updates a Result to indicate that there was an error when
// attempting to send the email to the remote SMTP server.
func (r *Result) HandleEmailError(err error) error {
	event, err := r.createEvent(EventSendingError, EventError{Error: err.Error()})
	if err != nil {
		return err
	}
	r.Status = Error
	r.ModifiedDate = event.Time
	return db.Save(r).Error
}

// HandleEmailBackoff updates a Result to indicate that the email received a
// temporary error and needs to be retried
func (r *Result) HandleEmailBackoff(err error, sendDate time.Time) error {
	event, err := r.createEvent(EventSendingError, EventError{Error: err.Error()})
	if err != nil {
		return err
	}
	r.Status = StatusRetry
	r.SendDate = sendDate
	r.ModifiedDate = event.Time
	return db.Save(r).Error
}

// HandleEmailOpened updates a Result in the case where the recipient opened the
// email.
func (r *Result) HandleEmailOpened(details EventDetails) error {
	event, err := r.createEvent(EventOpened, details)
	if err != nil {
		return err
	}
	EmitTelemetry(
		telemetry.New(telemetry.StageOpen, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink).
			WithCampaign(r.CampaignId, r.RId).
			WithActor(telemetry.Actor{IP: r.IP}).
			WithDetail("medium", medium(r.SMSTarget)),
	)
	// Don't update the status if the user already clicked the link
	// or submitted data to the campaign
	if r.Status == EventClicked || r.Status == EventDataSubmit {
		return nil
	}
	r.Status = EventOpened
	r.ModifiedDate = event.Time
	return db.Save(r).Error
}

func (r *Result) HandleSMSOpened(details EventDetails) error {
	event, err := r.createEvent(EventOpened, details)
	if err != nil {
		return err
	}
	EmitTelemetry(
		telemetry.New(telemetry.StageOpen, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink).
			WithCampaign(r.CampaignId, r.RId).
			WithActor(telemetry.Actor{IP: r.IP}).
			WithDetail("medium", medium(r.SMSTarget)),
	)
	// Don't update the status if the user already clicked the link
	// or submitted data to the campaign
	if r.Status == EventClicked || r.Status == EventDataSubmit {
		return nil
	}
	r.Status = EventOpened
	r.ModifiedDate = event.Time

	return db.Save(r).Error
}

// HandleClickedLink updates a Result in the case where the recipient clicked
// the link in an email.
func (r *Result) HandleClickedLink(details EventDetails) error {
	event, err := r.createEvent(EventClicked, details)
	if err != nil {
		return err
	}
	// Don't update the status if the user has already submitted data via the
	// landing page form.
	if r.Status == EventDataSubmit {
		return nil
	}
	r.Status = EventClicked
	r.ModifiedDate = event.Time
	return db.Save(r).Error
}

// HandleFormSubmit updates a Result in the case where the recipient submitted
// credentials to the form on a Landing Page.
func (r *Result) HandleFormSubmit(details EventDetails) error {
	event, err := r.createEvent(EventDataSubmit, details)
	if err != nil {
		return err
	}
	r.Status = EventDataSubmit
	r.ModifiedDate = event.Time
	return db.Save(r).Error
}

func (r *Result) HandleCapturedSession(details EventDetails) error {
	event, err := r.createEvent(EventCapturedSession, details)
	if err != nil {
		return err
	}
	r.Status = EventCapturedSession
	r.ModifiedDate = event.Time
	return db.Save(r).Error
}

// HandleEmailReport updates a Result in the case where they report a simulated
// phishing email using the HTTP handler.
func (r *Result) HandleEmailReport(details EventDetails) error {
	event, err := r.createEvent(EventReported, details)
	if err != nil {
		return err
	}
	r.Reported = true
	r.ModifiedDate = event.Time

	// The report stage carries no ATT&CK technique: a user reporting a
	// phish is a defender action, not an adversary behavior.
	EmitTelemetry(
		telemetry.New(telemetry.StageReport, telemetry.OutcomeAllowed).
			WithCampaign(r.CampaignId, r.RId),
	)

	return db.Save(r).Error
}

// UpdateGeo updates the latitude and longitude of the result in
// the database given an IP address
func (r *Result) UpdateGeo(addr string) error {
	// Open a connection to the maxmind db
	mmdb, err := maxminddb.Open("static/db/geolite2-city.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer mmdb.Close()
	ip := net.ParseIP(addr)
	var city mmCity
	// Get the record
	err = mmdb.Lookup(ip, &city)
	if err != nil {
		return err
	}
	// Update the database with the record information
	r.IP = addr
	r.Latitude = city.GeoPoint.Latitude
	r.Longitude = city.GeoPoint.Longitude
	return db.Save(r).Error
}

func generateResultId() (string, error) {
	const alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Generate a random length between 8 and 32
	length, err := rand.Int(rand.Reader, big.NewInt(25)) // Generates a number between 0 and 24
	if err != nil {
		return "", err
	}
	finalLength := int(length.Int64()) + 8 // Ensure length is between 8 and 32

	k := make([]byte, finalLength)
	for i := range k {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphaNum))))
		if err != nil {
			return "", err
		}
		k[i] = alphaNum[idx.Int64()]
	}
	return string(k), nil
}

// GenerateId generates a unique key to represent the result
// in the database
func (r *Result) GenerateId(tx *gorm.DB) error {
	// Keep trying until we generate a unique key (shouldn't take more than one or two iterations)
	for {
		rid, err := generateResultId()
		if err != nil {
			return err
		}
		r.RId = rid
		err = tx.Table("results").Where("r_id=?", r.RId).First(&Result{}).Error
		if err == gorm.ErrRecordNotFound {
			break
		}
	}
	return nil
}

// GetResult returns the Result object from the database
// given the ResultId
func GetResult(rid string) (Result, error) {
	r := Result{}
	err := db.Where("r_id=?", rid).First(&r).Error
	return r, err
}

// Sentinel errors from SetResultSessionMetadata, so the API handler can
// map them to the right HTTP status without matching error strings.
var (
	// ErrSessionNotFound covers both "no result with that RID" and "that
	// result exists but not under a campaign uid owns" -- deliberately
	// not distinguished any further than that, since telling those two
	// apart is exactly the information an IDOR probe against this
	// endpoint would be fishing for.
	ErrSessionNotFound      = errors.New("session not found")
	ErrInvalidSessionStatus = fmt.Errorf("status must be one of %v", SessionStatuses)
	ErrSessionTagTooLong    = fmt.Errorf("tag exceeds %d characters", MaxSessionTagLength)
	ErrSessionNotesTooLong  = fmt.Errorf("notes exceeds %d characters", MaxSessionNotesLength)
)

// SetResultSessionMetadata sets an operator's tag, notes, and/or status on
// one captured session (a Result row), scoped to a campaign uid owns. Each
// of tag, notes, and status is optional: a nil pointer leaves that field
// unchanged, so the dashboard can save a tag edit without clobbering notes
// an operator is still typing, and vice versa.
//
// Ownership is enforced the same way every other campaign-scoped model
// function enforces it (see GetCampaign): campaignID must belong to uid,
// and rid must belong to campaignID. Callers must pass a campaignID taken
// from the request's own authenticated context/route, never one read out
// of the request body, or this check is trivially bypassed.
func SetResultSessionMetadata(campaignID, uid int64, rid string, tag, notes, status *string) (Result, error) {
	var r Result
	if status != nil && !isValidSessionStatus(*status) {
		return r, ErrInvalidSessionStatus
	}
	if tag != nil && len(*tag) > MaxSessionTagLength {
		return r, ErrSessionTagTooLong
	}
	if notes != nil && len(*notes) > MaxSessionNotesLength {
		return r, ErrSessionNotesTooLong
	}

	if _, err := GetCampaign(campaignID, uid); err != nil {
		return r, ErrSessionNotFound
	}
	if err := db.Where("r_id = ? AND campaign_id = ?", rid, campaignID).First(&r).Error; err != nil {
		return r, ErrSessionNotFound
	}

	updates := map[string]interface{}{}
	if tag != nil {
		updates["tag"] = *tag
		r.Tag = *tag
	}
	if notes != nil {
		updates["notes"] = *notes
		r.Notes = *notes
	}
	if status != nil {
		updates["session_status"] = *status
		r.SessionStatus = *status
	}
	if len(updates) == 0 {
		return r, nil
	}
	// Updates with a map targets columns directly rather than through
	// gorm's field-name convention, so this write path does not depend on
	// the gorm:"column:..." tags on Result at all -- see the comment on
	// the struct for why that mapping is not trusted blindly here.
	if err := db.Model(&Result{}).Where("r_id = ? AND campaign_id = ?", rid, campaignID).Updates(updates).Error; err != nil {
		return r, err
	}
	return r, nil
}
