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

func TestApplyMigratesVersionOneSQLiteSchema(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	legacySchema := schemaWithoutRecipientPersonalization(sqliteSchema)
	legacySchema = schemaWithoutSecretStorage(legacySchema)
	legacySchema = strings.Replace(legacySchema, ",\n    min_send_delay BIGINT NOT NULL DEFAULT 0,\n    max_send_delay BIGINT NOT NULL DEFAULT 0", "", 1)
	legacySchema = strings.Replace(legacySchema, ",\n    template_variant_id BIGINT NOT NULL DEFAULT 0", "", 1)
	variantTableStart := strings.Index(legacySchema, "CREATE TABLE IF NOT EXISTS campaign_template_variants")
	if variantTableStart == -1 {
		t.Fatal("variant table not found in current SQLite schema")
	}
	variantTableEnd := strings.Index(legacySchema[variantTableStart:], ");")
	if variantTableEnd == -1 {
		t.Fatal("variant table terminator not found in current SQLite schema")
	}
	variantTableEnd += variantTableStart + 2
	legacySchema = legacySchema[:variantTableStart] + legacySchema[variantTableEnd:]
	legacySchema = strings.ReplaceAll(legacySchema, "CREATE INDEX IF NOT EXISTS idx_campaign_template_variants_campaign_id ON campaign_template_variants(campaign_id);", "")
	legacySchema = strings.ReplaceAll(legacySchema, "CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_template_variants_position ON campaign_template_variants(campaign_id, position);", "")
	legacySchema = strings.ReplaceAll(legacySchema, "CREATE INDEX IF NOT EXISTS idx_results_template_variant_id ON results(template_variant_id);", "")

	if err := executeSchema(db, legacySchema); err != nil {
		t.Fatalf("apply version one fixture: %v", err)
	}
	if err := ensureVersionTable(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO campaigns (id, user_id, name, template_id, smtp_id) VALUES (42, 1, 'legacy', 7, 3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO results (campaign_id, user_id, r_id, status, reported, sms_target) VALUES (42, 1, 'legacy-result', 'Email/SMS Sent', 0, 0)`); err != nil {
		t.Fatal(err)
	}

	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("Apply() version one migration: %v", err)
	}
	if err := validate(db); err != nil {
		t.Fatalf("validate migrated schema: %v", err)
	}
	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version = %d, want %d", version, CurrentVersion)
	}
	var variantID int64
	if err := db.QueryRow(`SELECT id FROM campaign_template_variants WHERE campaign_id = 42 AND name = 'Variant A'`).Scan(&variantID); err != nil {
		t.Fatalf("query backfilled variant: %v", err)
	}
	var resultVariantID int64
	if err := db.QueryRow(`SELECT template_variant_id FROM results WHERE r_id = 'legacy-result'`).Scan(&resultVariantID); err != nil {
		t.Fatalf("query backfilled result: %v", err)
	}
	if resultVariantID != variantID {
		t.Fatalf("result variant ID = %d, want %d", resultVariantID, variantID)
	}
}

func TestApplyMigratesVersionTwoSQLiteSchema(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	versionTwoSchema := schemaWithoutRecipientPersonalization(sqliteSchema)
	versionTwoSchema = schemaWithoutSecretStorage(versionTwoSchema)
	if err := executeSchema(db, versionTwoSchema); err != nil {
		t.Fatalf("apply version two fixture: %v", err)
	}
	if err := ensureVersionTable(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id, email, position) VALUES (1, 'ada@example.com', 'Engineer')`); err != nil {
		t.Fatal(err)
	}

	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("Apply() version two migration: %v", err)
	}
	if err := validate(db); err != nil {
		t.Fatalf("validate migrated schema: %v", err)
	}
	var email, department string
	if err := db.QueryRow(`SELECT email, COALESCE(department, '') FROM targets WHERE id = 1`).Scan(&email, &department); err != nil {
		t.Fatal(err)
	}
	if email != "ada@example.com" || department != "" {
		t.Fatalf("migrated target = %q/%q, want preserved email and empty department", email, department)
	}
}

func TestApplyMigratesVersionThreeSQLiteSchema(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	versionThreeSchema := strings.ReplaceAll(sqliteSchema, ",\n    language VARCHAR(32)", "")
	versionThreeSchema = schemaWithoutSecretStorage(versionThreeSchema)
	if err := executeSchema(db, versionThreeSchema); err != nil {
		t.Fatalf("apply version three fixture: %v", err)
	}
	if err := ensureVersionTable(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id, email, position, department) VALUES (1, 'ada@example.com', 'Engineer', 'Software')`); err != nil {
		t.Fatal(err)
	}

	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("Apply() version three migration: %v", err)
	}
	var email, department, language string
	if err := db.QueryRow(`SELECT email, COALESCE(department, ''), COALESCE(language, '') FROM targets WHERE id = 1`).Scan(&email, &department, &language); err != nil {
		t.Fatal(err)
	}
	if email != "ada@example.com" || department != "Software" || language != "" {
		t.Fatalf("migrated target = %q/%q/%q, want preserved metadata and empty language", email, department, language)
	}
	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version = %d, want %d", version, CurrentVersion)
	}
}

func schemaWithoutRecipientPersonalization(schema string) string {
	return strings.ReplaceAll(schema, ",\n    department VARCHAR(255),\n    role VARCHAR(255),\n    company VARCHAR(255),\n    manager_name VARCHAR(255),\n    language VARCHAR(32)", "")
}

func schemaWithoutSecretStorage(schema string) string {
	schema = strings.Replace(schema, "\n    api_key_hash VARCHAR(64),", "", 1)
	schema = strings.ReplaceAll(schema, "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_key_hash ON users(api_key_hash);", "")
	return schema
}

func TestApplyMigratesVersionFourSQLiteSchema(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	versionFourSchema := schemaWithoutSecretStorage(sqliteSchema)
	if err := executeSchema(db, versionFourSchema); err != nil {
		t.Fatal(err)
	}
	if err := ensureVersionTable(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (username, api_key) VALUES ('operator', 'legacy-key')`); err != nil {
		t.Fatal(err)
	}
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	var hash sql.NullString
	if err := db.QueryRow(`SELECT api_key_hash FROM users WHERE username='operator'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash.Valid {
		t.Fatalf("migration should leave hash population to the model layer, got %q", hash.String)
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

func TestTelemetryEventsTableExistsOnFreshInstall(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version = %d, want %d", version, CurrentVersion)
	}
	if CurrentVersion != 6 {
		t.Fatalf("CurrentVersion = %d, want 6", CurrentVersion)
	}

	for _, column := range []string{
		"event_id", "timestamp", "stage", "outcome",
		"techniques", "campaign_id", "rid", "actor", "detail",
	} {
		var count int
		query := "SELECT COUNT(*) FROM pragma_table_info('telemetry_events') WHERE name = ?"
		if err := db.QueryRow(query, column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("telemetry_events is missing column %q", column)
		}
	}
}

func TestTelemetryEventsUpgradeFromVersionFive(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	// Rewind to v5 and drop the new table to simulate a pre-006 database.
	// currentVersion() takes MAX(version) over an insert-only log, so the
	// version-6 row recorded by the fresh Apply() above must be cleared
	// first or MAX() would still report 6 despite the table drop.
	if _, err := db.Exec("DROP TABLE telemetry_events"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM olta_schema_migrations"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 5); err != nil {
		t.Fatal(err)
	}

	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("upgrade v5 to v6: %v", err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != 6 {
		t.Fatalf("version after upgrade = %d, want 6", version)
	}
}
