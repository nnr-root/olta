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
	legacySchema := schemaBeforeSessionTagging(sqliteSchema)
	legacySchema = schemaWithoutRecipientPersonalization(legacySchema)
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
	versionTwoSchema := schemaBeforeSessionTagging(sqliteSchema)
	versionTwoSchema = schemaWithoutRecipientPersonalization(versionTwoSchema)
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
	versionThreeSchema := schemaBeforeSessionTagging(sqliteSchema)
	versionThreeSchema = strings.ReplaceAll(versionThreeSchema, ",\n    language VARCHAR(32)", "")
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
	versionFourSchema := schemaBeforeSessionTagging(sqliteSchema)
	versionFourSchema = schemaWithoutSecretStorage(versionFourSchema)
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
	if CurrentVersion != 8 {
		t.Fatalf("CurrentVersion = %d, want 8", CurrentVersion)
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
	// Rewind to v5 and drop everything migrations 6 and 7 added, to
	// simulate a pre-006 database. currentVersion() takes MAX(version)
	// over an insert-only log, so the version-7 row recorded by the fresh
	// Apply() above must be cleared first or MAX() would still report 7
	// despite the drops.
	if _, err := db.Exec("DROP TABLE telemetry_events"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP INDEX idx_results_tag"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP INDEX idx_results_session_status"); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"tag", "notes", "session_status"} {
		if _, err := db.Exec("ALTER TABLE results DROP COLUMN " + column); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("DELETE FROM olta_schema_migrations"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 5); err != nil {
		t.Fatal(err)
	}

	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("upgrade v5 to current: %v", err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version after upgrade = %d, want %d", version, CurrentVersion)
	}
}

// schemaWithoutSessionTagging strips the session tagging columns/indexes
// this migration adds from the full unified schema, producing a
// version-6-equivalent schema for upgrade testing. Mirrors
// schemaWithoutSecretStorage above.
func schemaWithoutSessionTagging(schema string) string {
	schema = strings.Replace(schema,
		"    template_variant_id BIGINT NOT NULL DEFAULT 0,\n    tag VARCHAR(120),\n    notes VARCHAR(2000),\n    session_status VARCHAR(32) NOT NULL DEFAULT 'untriaged'\n)",
		"    template_variant_id BIGINT NOT NULL DEFAULT 0\n)", 1)
	schema = strings.ReplaceAll(schema, "CREATE INDEX IF NOT EXISTS idx_results_tag ON results(tag);", "")
	schema = strings.ReplaceAll(schema, "CREATE INDEX IF NOT EXISTS idx_results_session_status ON results(session_status);", "")
	return schema
}

// schemaWithoutTelemetryScope strips the telemetry scope columns/indexes
// migration 008 adds from the full unified schema, producing a
// version-7-equivalent schema for upgrade testing. Mirrors
// schemaWithoutSessionTagging above.
func schemaWithoutTelemetryScope(schema string) string {
	schema = strings.Replace(schema,
		"    detail TEXT,\n    instance_id VARCHAR(32),\n    host VARCHAR(255)\n)",
		"    detail TEXT\n)", 1)
	schema = strings.ReplaceAll(schema, "CREATE INDEX IF NOT EXISTS idx_telemetry_events_instance_id ON telemetry_events(instance_id);", "")
	schema = strings.ReplaceAll(schema, "CREATE INDEX IF NOT EXISTS idx_telemetry_events_host ON telemetry_events(host);", "")
	return schema
}

// schemaBeforeSessionTagging produces a pre-007 schema: every later
// migration's additions stripped, so an upgrade test starting at version 6
// or earlier does not collide with a column the fresh schema already has.
func schemaBeforeSessionTagging(schema string) string {
	return schemaWithoutTelemetryScope(schemaWithoutSessionTagging(schema))
}

// TestSessionTaggingColumnsExistOnFreshInstall proves the fresh-install
// schema (001) and the numbered migration (007) agree: a brand new
// database gets the operator tagging columns on the results table without
// ever running migration 007 directly.
func TestSessionTaggingColumnsExistOnFreshInstall(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}

	for _, column := range []string{"tag", "notes", "session_status"} {
		var count int
		query := "SELECT COUNT(*) FROM pragma_table_info('results') WHERE name = ?"
		if err := db.QueryRow(query, column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("results is missing column %q", column)
		}
	}

	// session_status must default an existing row to "untriaged" rather
	// than an empty string, so a pre-existing captured session shows up
	// as untriaged in the dashboard filter instead of falling through it.
	if _, err := db.Exec(`INSERT INTO results (r_id, status) VALUES ('ridfresh', 'Captured Session')`); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(`SELECT session_status FROM results WHERE r_id='ridfresh'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "untriaged" {
		t.Fatalf("session_status default = %q, want untriaged", status)
	}
}

// TestSessionTaggingUpgradeFromVersionSix proves migration 007 brings an
// existing (pre-tagging) database up to the same shape a fresh install
// gets from 001, including the same default.
func TestSessionTaggingUpgradeFromVersionSix(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	versionSixSchema := schemaBeforeSessionTagging(sqliteSchema)
	if err := executeSchema(db, versionSixSchema); err != nil {
		t.Fatal(err)
	}
	if err := ensureVersionTable(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO results (r_id, status) VALUES ('ridlegacy', 'Captured Session')`); err != nil {
		t.Fatal(err)
	}

	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("upgrade v6 to current: %v", err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version after upgrade = %d, want %d", version, CurrentVersion)
	}

	var status string
	if err := db.QueryRow(`SELECT session_status FROM results WHERE r_id='ridlegacy'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "untriaged" {
		t.Fatalf("session_status for pre-existing row = %q, want untriaged", status)
	}
}

// TestTelemetryScopeColumnsExistOnFreshInstall proves the fresh-install
// schema (001) and the numbered migration (008) agree: a brand new database
// gets the scope columns on telemetry_events without replaying migrations.
func TestTelemetryScopeColumnsExistOnFreshInstall(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}

	for _, column := range []string{"instance_id", "host"} {
		var count int
		query := `SELECT COUNT(*) FROM pragma_table_info('telemetry_events') WHERE name = ?`
		if err := db.QueryRow(query, column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("fresh install is missing telemetry_events.%s", column)
		}
	}
}

// TestTelemetryScopeUpgradeFromVersionSeven proves migration 008 brings an
// existing database up to the same shape a fresh install gets from 001, and
// that rows written before the upgrade survive it with the new columns empty
// rather than the upgrade failing or inventing a value for them.
func TestTelemetryScopeUpgradeFromVersionSeven(t *testing.T) {
	db := openSQLiteTestDatabase(t)
	versionSevenSchema := schemaWithoutTelemetryScope(sqliteSchema)
	if err := executeSchema(db, versionSevenSchema); err != nil {
		t.Fatal(err)
	}
	if err := ensureVersionTable(db, "sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := recordVersion(db, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO telemetry_events (event_id, timestamp, stage, outcome)
		VALUES ('legacyevent0000000000000000000', '2026-08-01 00:00:00', 'cloak', 'blocked')`); err != nil {
		t.Fatal(err)
	}

	if err := Apply(db, "sqlite3"); err != nil {
		t.Fatalf("upgrade v7 to current: %v", err)
	}

	version, err := currentVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentVersion {
		t.Fatalf("version after upgrade = %d, want %d", version, CurrentVersion)
	}

	var instanceID, host sql.NullString
	query := `SELECT instance_id, host FROM telemetry_events WHERE event_id='legacyevent0000000000000000000'`
	if err := db.QueryRow(query).Scan(&instanceID, &host); err != nil {
		t.Fatal(err)
	}
	if instanceID.Valid || host.Valid {
		t.Fatalf("pre-existing row got instance_id=%v host=%v, want both null: the upgrade must not invent a scope for events recorded before it",
			instanceID, host)
	}
}
