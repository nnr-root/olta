package feed

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

// tokenStore holds the currently accepted publisher and viewer tokens.
//
// Rotation is why this exists. Before it, a token lived in the process's
// environment and could only be changed by restarting olta-feed -- which
// drops every connected viewer and the proxy's publishing connection with
// them, in the middle of the engagement whose telemetry they were watching.
// A store that can be swapped atomically, holding more than one valid token
// at a time, makes the standard overlap rotation possible: add the new token,
// move clients across, remove the old one, with no restart and no dropped
// connection.
//
// Each side accepts a set rather than a single value for the same reason.
// During a rotation both the old and the new token have to work, or the
// overlap is not an overlap.
type tokenStore struct {
	publisher atomic.Pointer[[]string]
	viewer    atomic.Pointer[[]string]
	// path is the file the sets are reloaded from, empty when tokens came
	// only from configuration.
	path string
}

// tokenFile is the on-disk format: one list per role, so an operator can hold
// two publisher tokens valid at once without touching the viewer side.
type tokenFile struct {
	Publisher []string `json:"publisher"`
	Viewer    []string `json:"viewer"`
}

func newTokenStore(config Config) (*tokenStore, error) {
	store := &tokenStore{path: strings.TrimSpace(config.TokenFile)}
	store.set(nonEmpty(config.PublisherToken), nonEmpty(config.ViewerToken))
	if store.path == "" {
		return store, nil
	}
	if err := store.Reload(); err != nil {
		return nil, err
	}
	return store, nil
}

// Reload re-reads the token file, replacing both sets atomically.
//
// A failed reload leaves the current tokens in place and returns the error.
// That is the safe direction: a truncated or half-written file must not lock
// every client out of a running feed, and an operator who mistypes the new
// file finds out from the error rather than from an outage.
func (s *tokenStore) Reload() error {
	if s == nil || s.path == "" {
		return nil
	}
	contents, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read feed token file: %w", err)
	}
	var parsed tokenFile
	if err := json.Unmarshal(contents, &parsed); err != nil {
		return fmt.Errorf("parse feed token file: %w", err)
	}

	publisher := nonEmpty(parsed.Publisher...)
	viewer := nonEmpty(parsed.Viewer...)
	if len(publisher) == 0 || len(viewer) == 0 {
		return fmt.Errorf("feed token file must list at least one publisher and one viewer token")
	}
	if overlaps(publisher, viewer) {
		return fmt.Errorf("feed publisher and viewer tokens must be different")
	}
	s.set(publisher, viewer)
	return nil
}

func (s *tokenStore) set(publisher, viewer []string) {
	s.publisher.Store(&publisher)
	s.viewer.Store(&viewer)
}

// matchesPublisher reports whether candidate is an accepted publisher token.
// An empty set means authentication is disabled, which Run only permits for a
// loopback listener.
func (s *tokenStore) matchesPublisher(candidate string) bool {
	return matches(load(&s.publisher), candidate)
}

func (s *tokenStore) matchesViewer(candidate string) bool {
	return matches(load(&s.viewer), candidate)
}

func (s *tokenStore) publisherConfigured() bool { return len(load(&s.publisher)) > 0 }

func (s *tokenStore) viewerConfigured() bool { return len(load(&s.viewer)) > 0 }

func load(pointer *atomic.Pointer[[]string]) []string {
	if value := pointer.Load(); value != nil {
		return *value
	}
	return nil
}

// matches compares against every accepted token in constant time.
//
// Every candidate is compared against every token rather than returning on
// the first hit, so the time taken does not depend on which token matched or
// on how far down the set it sits.
func matches(accepted []string, candidate string) bool {
	if len(accepted) == 0 {
		return true
	}
	matched := 0
	for _, token := range accepted {
		if len(candidate) == len(token) &&
			subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
			matched = 1
		}
	}
	return matched == 1
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func overlaps(first, second []string) bool {
	for _, value := range first {
		for _, other := range second {
			if value == other {
				return true
			}
		}
	}
	return false
}
