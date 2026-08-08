package database

import (
	"path/filepath"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/config"
)

func TestNewDefaultsToSQLite(t *testing.T) {
	connector, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if connector.Driver() != config.DefaultDatabaseDriver {
		t.Fatalf("driver = %q, want %q", connector.Driver(), config.DefaultDatabaseDriver)
	}

	db, err := connector.Open(filepath.Join(t.TempDir(), "campaign.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
}

func TestNewRequiresExplicitMySQLSelection(t *testing.T) {
	connector, err := New("mysql")
	if err != nil {
		t.Fatal(err)
	}
	if connector.Driver() != "mysql" {
		t.Fatalf("driver = %q, want mysql", connector.Driver())
	}
	if _, err := connector.Open("", ""); err == nil {
		t.Fatal("expected empty MySQL DSN to fail before connection")
	}
}

func TestNewRejectsUnknownDriver(t *testing.T) {
	if _, err := New("postgres"); err == nil {
		t.Fatal("expected unsupported driver error")
	}
}
