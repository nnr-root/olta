// Package migrations owns the unified Olta campaign database schemas.
package migrations

import (
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
)

const CurrentVersion = 1

//go:embed sqlite/001_initial_olta_schema.sql
var sqliteSchema string

//go:embed mysql/001_initial_olta_schema.sql
var mysqlSchema string

var requiredSchema = map[string][]string{
	"users":            {"id", "username", "hash", "api_key", "role_id", "password_change_required", "account_locked", "last_login"},
	"templates":        {"id", "user_id", "name", "envelope_sender", "subject", "text", "html", "modified_date"},
	"attachments":      {"id", "template_id", "content", "type", "name"},
	"targets":          {"id", "first_name", "last_name", "email", "position"},
	"groups":           {"id", "user_id", "name", "modified_date"},
	"group_targets":    {"group_id", "target_id"},
	"smtp":             {"id", "user_id", "interface_type", "name", "host", "username", "password", "from_address", "modified_date", "ignore_cert_errors"},
	"headers":          {"id", "key", "value", "smtp_id"},
	"sms":              {"id", "user_id", "name", "twilio_account_sid", "twilio_auth_token", "sms_from", "modified_date"},
	"campaigns":        {"id", "user_id", "name", "created_date", "launch_date", "send_by_date", "completed_date", "template_id", "page_id", "status", "smtp_id", "sms_id", "url", "qr_size"},
	"results":          {"id", "campaign_id", "user_id", "r_id", "email", "first_name", "last_name", "position", "status", "ip", "latitude", "longitude", "send_date", "reported", "modified_date", "sms_target"},
	"events":           {"id", "campaign_id", "email", "time", "message", "details"},
	"mail_logs":        {"id", "campaign_id", "user_id", "send_date", "send_attempt", "r_id", "processing", "target"},
	"sms_logs":         {"id", "campaign_id", "user_id", "send_date", "send_attempt", "r_id", "processing", "target"},
	"email_requests":   {"id", "user_id", "template_id", "page_id", "first_name", "last_name", "email", "position", "url", "r_id", "from_address"},
	"roles":            {"id", "slug", "name", "description"},
	"permissions":      {"id", "slug", "name", "description"},
	"role_permissions": {"role_id", "permission_id"},
	"webhooks":         {"id", "name", "url", "secret", "is_active"},
	"imap":             {"user_id", "host", "port", "username", "password", "modified_date", "tls", "enabled", "folder", "restrict_domain", "delete_reported_campaign_email", "last_login", "imap_freq", "ignore_cert_errors"},
}

// Apply initializes a fresh database from one schema or baselines an existing
// database that already matches the complete Olta schema.
func Apply(db *sql.DB, dialect string) error {
	schema, err := schemaFor(dialect)
	if err != nil {
		return err
	}
	if err := ensureVersionTable(db, dialect); err != nil {
		return err
	}

	version, err := currentVersion(db)
	if err != nil {
		return err
	}
	if version > CurrentVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", version, CurrentVersion)
	}
	if version == CurrentVersion {
		return validate(db)
	}

	exists, err := tableExists(db, dialect, "users")
	if err != nil {
		return err
	}
	if exists {
		if err := validate(db); err != nil {
			return fmt.Errorf("legacy database is not at the final pre-Olta schema; migrate it with the previous release before upgrading: %w", err)
		}
		return recordVersion(db)
	}

	if err := executeSchema(db, schema); err != nil {
		return fmt.Errorf("apply unified Olta %s schema: %w", dialect, err)
	}
	if err := validate(db); err != nil {
		return err
	}
	return recordVersion(db)
}

func schemaFor(dialect string) (string, error) {
	switch dialect {
	case "sqlite3":
		return sqliteSchema, nil
	case "mysql":
		return mysqlSchema, nil
	default:
		return "", fmt.Errorf("unsupported database dialect %q", dialect)
	}
}

func ensureVersionTable(db *sql.DB, dialect string) error {
	statement := `CREATE TABLE IF NOT EXISTS olta_schema_migrations (version INTEGER NOT NULL)`
	if dialect == "mysql" {
		statement = "CREATE TABLE IF NOT EXISTS `olta_schema_migrations` (`version` BIGINT NOT NULL)"
	}
	_, err := db.Exec(statement)
	return err
}

func currentVersion(db *sql.DB) (int, error) {
	var version sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(version) FROM olta_schema_migrations`).Scan(&version); err != nil {
		return 0, err
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}

func recordVersion(db *sql.DB) error {
	_, err := db.Exec(`INSERT INTO olta_schema_migrations(version) VALUES (?)`, CurrentVersion)
	return err
}

func tableExists(db *sql.DB, dialect, table string) (bool, error) {
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`
	if dialect == "mysql" {
		query = `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?`
	}
	var count int
	if err := db.QueryRow(query, table).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func validate(db *sql.DB) error {
	for table, columns := range requiredSchema {
		query := fmt.Sprintf("SELECT %s FROM %s WHERE 1=0", joinIdentifiers(columns), quoteIdentifier(table))
		rows, err := db.Query(query)
		if err != nil {
			return fmt.Errorf("required table %s is missing or incomplete: %w", table, err)
		}
		rows.Close()
	}
	return nil
}

func joinIdentifiers(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = quoteIdentifier(value)
	}
	return strings.Join(quoted, ", ")
}

func quoteIdentifier(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "``") + "`"
}

func executeSchema(db *sql.DB, schema string) error {
	transaction, err := db.Begin()
	if err != nil {
		return err
	}
	for _, statement := range splitStatements(schema) {
		if _, err := transaction.Exec(statement); err != nil {
			_ = transaction.Rollback()
			return err
		}
	}
	return transaction.Commit()
}

func splitStatements(schema string) []string {
	lines := strings.Split(schema, "\n")
	clean := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			clean = append(clean, line)
		}
	}
	parts := strings.Split(strings.Join(clean, "\n"), ";")
	statements := make([]string, 0, len(parts))
	for _, part := range parts {
		if statement := strings.TrimSpace(part); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}
