package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestConcurrentDSN(t *testing.T) {
	tests := map[string]string{
		"olta-campaign.db":      "file:olta-campaign.db?_busy_timeout=10000&_journal_mode=WAL",
		"file:olta.db?mode=rwc": "file:olta.db?mode=rwc&_busy_timeout=10000&_journal_mode=WAL",
		":memory:":              ":memory:",
	}
	for input, want := range tests {
		if got := ConcurrentDSN(input); got != want {
			t.Errorf("ConcurrentDSN(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestConcurrentWritersWaitInsteadOfFailingWithLockedDatabase(t *testing.T) {
	dsn := ConcurrentDSN(filepath.Join(t.TempDir(), "campaign.db"))
	first, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if _, err := first.Exec(`CREATE TABLE events (id INTEGER PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	transaction, err := first.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`INSERT INTO events(value) VALUES ('campaign')`); err != nil {
		t.Fatal(err)
	}

	writeResult := make(chan error, 1)
	go func() {
		_, err := second.Exec(`INSERT INTO events(value) VALUES ('proxy')`)
		writeResult <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatalf("concurrent writer returned an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent writer did not resume after the transaction committed")
	}
}
