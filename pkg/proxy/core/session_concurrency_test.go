package core

import (
	"sync"
	"testing"
)

// TestConcurrentSessionAccess drives session creation and lookup from many
// goroutines simultaneously, the same way concurrent connections landing on
// the proxy do in production (see the goproxy request handler around
// http_proxy.go:527). Before session_mtx was wired up to guard p.sessions,
// p.sids and p.last_sid, this reliably tripped Go's fatal
// "concurrent map writes" error (or the race detector) because two
// goroutines could index into the same map at once. Run with -race.
func TestConcurrentSessionAccess(t *testing.T) {
	proxy, _ := newTestHttpProxy(t)

	const goroutines = 64
	const sessionsPerGoroutine = 50

	ids := make([][]string, goroutines)
	for i := range ids {
		ids[i] = make([]string, sessionsPerGoroutine)
	}
	var idsMu sync.Mutex // guards the test's own bookkeeping slice, not proxy state

	var writers sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		g := g
		writers.Add(1)
		go func() {
			defer writers.Done()
			for i := 0; i < sessionsPerGoroutine; i++ {
				session, err := NewSession("testsite")
				if err != nil {
					t.Errorf("NewSession() error: %v", err)
					return
				}
				sid := proxy.addSession(session)
				if sid < 0 {
					t.Errorf("addSession() returned invalid index %d", sid)
				}
				idsMu.Lock()
				ids[g][i] = session.Id
				idsMu.Unlock()
			}
		}()
	}

	// Readers race against the writers for the whole duration, exercising
	// getSession, hasSession and getSessionIndex the way request handling
	// does concurrently with new sessions being registered.
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < goroutines/2; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				idsMu.Lock()
				id := ids[0][0]
				idsMu.Unlock()
				if id == "" {
					continue
				}
				_, _ = proxy.getSession(id)
				_ = proxy.hasSession(id)
				_, _ = proxy.getSessionIndex(id)
			}
		}()
	}

	writers.Wait()
	close(stop)
	readers.Wait()

	// Verify every session that was registered is retrievable and that the
	// map ended up with exactly the expected number of entries - i.e. no
	// writes were silently lost to a torn concurrent map operation.
	total := 0
	for g := 0; g < goroutines; g++ {
		for i := 0; i < sessionsPerGoroutine; i++ {
			id := ids[g][i]
			if id == "" {
				t.Fatalf("session id missing for goroutine %d index %d", g, i)
			}
			if _, ok := proxy.getSession(id); !ok {
				t.Errorf("session %s was not found after concurrent registration", id)
			}
			total++
		}
	}
	if total != goroutines*sessionsPerGoroutine {
		t.Fatalf("registered %d sessions, want %d", total, goroutines*sessionsPerGoroutine)
	}
}
