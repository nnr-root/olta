package migrations

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
)

func openSQLiteTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestApplyFreshSQLiteSchema(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("second Apply(): %v", err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version = %d, want %d", version, CurrentVersion)
	}

	var permissionMappings int
	if err := db.QueryRow(`SELECT COUNT(*) FROM role_permissions`).Scan(&permissionMappings); err != nil {
		t.Fatal(err)
	}
	if permissionMappings != 5 {
		t.Fatalf("role permission mappings = %d, want 5", permissionMappings)
	}
}

func TestApplyBaselinesCompleteLegacySQLiteSchema(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	if err := executeSchema(db, sqliteSchema); err != nil {
		t.Fatal(err)
	}
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("Apply() legacy baseline: %v", err)
	}
	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version = %d, want %d", version, CurrentVersion)
	}
}

func TestApplyRejectsIncompleteLegacySchema(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	err := Apply(db, "sqlite3")
	if err == nil || !strings.Contains(err.Error(), "legacy database is not at the final pre-Olta schema") {
		t.Fatalf("Apply() error = %v, want incomplete legacy schema error", err)
	}
}

func TestUnifiedSchemasContainAllRequiredTables(t *testing.T) {
	for dialect, schema := range map[string]string{"sqlite3": sqliteSchema, "mysql": mysqlSchema} {
		for table := range requiredSchema {
			if !strings.Contains(schema, table) {
				t.Errorf("%s schema does not mention required table %s", dialect, table)
			}
		}
	}
}

func TestApplyFreshMySQLSchema(t *testing.T) {
	dsn := os.Getenv("OLTA_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set OLTA_TEST_MYSQL_DSN to run the MySQL migration integration test")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("connect to MySQL: %v", err)
	}
	if err := Apply(db, "mysql"); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if err := Apply(db, "mysql"); err != nil {
		t.Fatalf("second Apply(): %v", err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version = %d, want %d", version, CurrentVersion)
	}
}
