package campaignstore

import (
	"path/filepath"
	"strings"
	"testing"
)

// These tests cover what is genuinely testable about dialect selection
// without a live MySQL server: driver routing (New reuses
// pkg/campaign/database's factory, so an unsupported driver name is
// rejected the same way it is for the campaign service), DSN validation
// that happens before any dial attempt, and -- for the SQLite path -- that
// the WAL/busy-timeout tuning previously built inline in this package
// still applies after routing through the shared connector.
//
// MySQL success (an actual connection, actual writes) is NOT exercised
// here: that requires a live MySQL server, which this environment does not
// have. gorm v1's Open pings the database as part of dialect setup, so even
// a syntactically valid MySQL DSN dials out; the MySQL test below turns
// that into a positive assertion instead (see
// TestNewMySQLDriverReachesMySQL).

// TestNewRejectsUnsupportedDriver verifies New surfaces the same "unsupported
// campaign database driver" error pkg/campaign/database.New returns, proving
// dialect selection is delegated rather than reimplemented here.
func TestNewRejectsUnsupportedDriver(t *testing.T) {
	_, err := New("postgres", "", "", "", false)
	if err == nil {
		t.Fatal("New with an unsupported driver must fail")
	}
	if !strings.Contains(err.Error(), "unsupported campaign database driver") {
		t.Fatalf("error = %q, want it to name the unsupported driver", err.Error())
	}
}

// TestNewMySQLRequiresDSN verifies the mysql driver path rejects an empty
// path/DSN before ever attempting to dial a server -- the same validation
// pkg/campaign/database.mysqlConnector.Open performs for the campaign
// service, reached here through the same connector.
func TestNewMySQLRequiresDSN(t *testing.T) {
	_, err := New("mysql", "", "", "", false)
	if err == nil {
		t.Fatal("New(\"mysql\", \"\", ...) must fail without a DSN")
	}
	if !strings.Contains(err.Error(), "DSN") {
		t.Fatalf("error = %q, want it to mention the missing DSN", err.Error())
	}
}

// TestNewMySQLDriverReachesMySQL verifies that selecting the mysql driver
// actually routes to the MySQL dialect instead of silently falling back to
// the old hardcoded sqlite3 behavior. gorm v1's Open pings the database as
// part of dialect setup, so this cannot succeed without a live server --
// but that ping itself is the proof: a DSN string is nonsense as a SQLite
// file path, so if the pre-fix code path were still active this call would
// either silently create a garbage file at that literal path or fail with
// an unrelated SQLite error. Instead it must fail with a MySQL connection
// error (dial/connection refused against 127.0.0.1:1, chosen so the
// refusal is immediate rather than a long OS-level timeout).
func TestNewMySQLDriverReachesMySQL(t *testing.T) {
	_, err := New("mysql", "user:pass@tcp(127.0.0.1:1)/olta_test", "", "", false)
	if err == nil {
		t.Fatal("New(\"mysql\", ...) unexpectedly succeeded without a live MySQL server")
	}
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "connect") && !strings.Contains(lower, "dial") && !strings.Contains(lower, "refused") {
		t.Fatalf("error = %q, want a MySQL connection error proving the mysql dialect was actually attempted (not a fallback to sqlite)", err.Error())
	}
}

// TestNewSQLiteDriverAliasesAgree verifies "" and the explicit "sqlite3"
// driver name select the same embedded default, matching
// pkg/campaign/database.New's own aliasing.
func TestNewSQLiteDriverAliasesAgree(t *testing.T) {
	for _, driver := range []string{"", "sqlite3"} {
		driver := driver
		t.Run("driver="+driver, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "olta.db")
			store, err := New(driver, path, "", "", false)
			if err != nil {
				t.Fatalf("New(%q, ...): %v", driver, err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Errorf("store.Close(): %v", err)
				}
			})
		})
	}
}

// TestNewSQLiteKeepsConcurrentDSNTuning verifies the SQLite path still opens
// through sqlitedsn.ConcurrentDSN after being routed through the shared
// connector -- WAL journal mode is observable on the opened connection, so
// this is a direct behavioral check that the refactor didn't silently drop
// the tuning the proxy depends on for campaign/proxy coexistence.
func TestNewSQLiteKeepsConcurrentDSNTuning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "olta.db")
	store, err := New("", path, "", "", false)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close(): %v", err)
		}
	}()

	var journalMode string
	if err := store.db.DB().QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal_mode = %q, want %q", journalMode, "wal")
	}
}

// TestNewSQLiteRejectsTLSCAPath verifies the SQLite connector still rejects
// a non-empty tlsCAPath exactly as pkg/campaign/database.sqliteConnector.Open
// does -- db_sslca_path only makes sense for the MySQL driver.
func TestNewSQLiteRejectsTLSCAPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "olta.db")
	_, err := New("", path, "/some/ca.pem", "", false)
	if err == nil {
		t.Fatal("New with a non-empty tlsCAPath on the sqlite3 driver must fail")
	}
}
