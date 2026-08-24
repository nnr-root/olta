// Package migrations owns the unified Olta campaign database schemas.
package migrations

import (
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
)

const CurrentVersion = 5

//go:embed sqlite/001_initial_olta_schema.sql
var sqliteSchema string

//go:embed mysql/001_initial_olta_schema.sql
var mysqlSchema string

//go:embed sqlite/002_campaign_jitter_variants.sql
var sqliteCampaignJitterVariants string

//go:embed mysql/002_campaign_jitter_variants.sql
var mysqlCampaignJitterVariants string

//go:embed sqlite/003_recipient_personalization.sql
var sqliteRecipientPersonalization string

//go:embed mysql/003_recipient_personalization.sql
var mysqlRecipientPersonalization string

//go:embed sqlite/004_recipient_language.sql
var sqliteRecipientLanguage string

//go:embed mysql/004_recipient_language.sql
var mysqlRecipientLanguage string

//go:embed sqlite/005_secret_storage.sql
var sqliteSecretStorage string

//go:embed mysql/005_secret_storage.sql
var mysqlSecretStorage string

var requiredSchema = map[string][]string{
	"users":                      {"id", "username", "hash", "api_key", "api_key_hash", "role_id", "password_change_required", "account_locked", "last_login"},
	"templates":                  {"id", "user_id", "name", "envelope_sender", "subject", "text", "html", "modified_date"},
	"attachments":                {"id", "template_id", "content", "type", "name"},
	"targets":                    {"id", "first_name", "last_name", "email", "position", "department", "role", "company", "manager_name", "language"},
	"groups":                     {"id", "user_id", "name", "modified_date"},
	"group_targets":              {"group_id", "target_id"},
	"smtp":                       {"id", "user_id", "interface_type", "name", "host", "username", "password", "from_address", "modified_date", "ignore_cert_errors"},
	"headers":                    {"id", "key", "value", "smtp_id"},
	"sms":                        {"id", "user_id", "name", "twilio_account_sid", "twilio_auth_token", "sms_from", "modified_date"},
	"campaigns":                  {"id", "user_id", "name", "created_date", "launch_date", "send_by_date", "completed_date", "template_id", "page_id", "status", "smtp_id", "sms_id", "url", "qr_size", "min_send_delay", "max_send_delay"},
	"campaign_template_variants": {"id", "campaign_id", "template_id", "name", "position"},
	"results":                    {"id", "campaign_id", "user_id", "r_id", "email", "first_name", "last_name", "position", "department", "role", "company", "manager_name", "language", "status", "ip", "latitude", "longitude", "send_date", "reported", "modified_date", "sms_target", "template_variant_id"},
	"events":                     {"id", "campaign_id", "email", "time", "message", "details"},
	"mail_logs":                  {"id", "campaign_id", "user_id", "send_date", "send_attempt", "r_id", "processing", "target"},
	"sms_logs":                   {"id", "campaign_id", "user_id", "send_date", "send_attempt", "r_id", "processing", "target"},
	"email_requests":             {"id", "user_id", "template_id", "page_id", "first_name", "last_name", "email", "position", "department", "role", "company", "manager_name", "language", "url", "r_id", "from_address"},
	"roles":                      {"id", "slug", "name", "description"},
	"permissions":                {"id", "slug", "name", "description"},
	"role_permissions":           {"role_id", "permission_id"},
	"webhooks":                   {"id", "name", "url", "secret", "is_active"},
	"imap":                       {"user_id", "host", "port", "username", "password", "modified_date", "tls", "enabled", "folder", "restrict_domain", "delete_reported_campaign_email", "last_login", "imap_freq", "ignore_cert_errors"},
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
		if version == 0 {
			if err := validate(db); err == nil {
				return recordVersion(db, CurrentVersion)
			}
			if err := validateAgainst(db, legacyRequiredSchema()); err != nil {
				return fmt.Errorf("legacy database is not at the final pre-Olta schema; migrate it with the previous release before upgrading: %w", err)
			}
			if err := recordVersion(db, 1); err != nil {
				return err
			}
			version = 1
		}
	} else {
		if err := executeSchema(db, schema); err != nil {
			return fmt.Errorf("apply unified Olta %s schema: %w", dialect, err)
		}
		if err := validate(db); err != nil {
			return err
		}
		return recordVersion(db, CurrentVersion)
	}

	for version < CurrentVersion {
		nextVersion := version + 1
		migration, migrationErr := migrationFor(dialect, nextVersion)
		if migrationErr != nil {
			return migrationErr
		}
		if err := executeSchema(db, migration); err != nil {
			return fmt.Errorf("apply Olta %s schema migration %d: %w", dialect, nextVersion, err)
		}
		if err := recordVersion(db, nextVersion); err != nil {
			return err
		}
		version = nextVersion
	}
	if err := validate(db); err != nil {
		return err
	}
	return nil
}

func migrationFor(dialect string, version int) (string, error) {
	switch {
	case dialect == "sqlite3" && version == 2:
		return sqliteCampaignJitterVariants, nil
	case dialect == "mysql" && version == 2:
		return mysqlCampaignJitterVariants, nil
	case dialect == "sqlite3" && version == 3:
		return sqliteRecipientPersonalization, nil
	case dialect == "mysql" && version == 3:
		return mysqlRecipientPersonalization, nil
	case dialect == "sqlite3" && version == 4:
		return sqliteRecipientLanguage, nil
	case dialect == "mysql" && version == 4:
		return mysqlRecipientLanguage, nil
	case dialect == "sqlite3" && version == 5:
		return sqliteSecretStorage, nil
	case dialect == "mysql" && version == 5:
		return mysqlSecretStorage, nil
	case dialect != "sqlite3" && dialect != "mysql":
		return "", fmt.Errorf("unsupported database dialect %q", dialect)
	default:
		return "", fmt.Errorf("campaign schema migration %d is unavailable", version)
	}
}

func legacyRequiredSchema() map[string][]string {
	legacy := make(map[string][]string, len(requiredSchema)-1)
	for table, columns := range requiredSchema {
		if table == "campaign_template_variants" {
			continue
		}
		filtered := make([]string, 0, len(columns))
		for _, column := range columns {
			if (table == "campaigns" && (column == "min_send_delay" || column == "max_send_delay")) ||
				(table == "results" && column == "template_variant_id") ||
				((table == "targets" || table == "results" || table == "email_requests") &&
					(column == "department" || column == "role" || column == "company" || column == "manager_name" || column == "language")) ||
				(table == "users" && column == "api_key_hash") {
				continue
			}
			filtered = append(filtered, column)
		}
		legacy[table] = filtered
	}
	return legacy
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

func recordVersion(db *sql.DB, version int) error {
	_, err := db.Exec(`INSERT INTO olta_schema_migrations(version) VALUES (?)`, version)
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
	return validateAgainst(db, requiredSchema)
}

func validateAgainst(db *sql.DB, schema map[string][]string) error {
	for table, columns := range schema {
		query := fmt.Sprintf("SELECT %s FROM %s WHERE 1=0", joinIdentifiers(columns), quoteIdentifier(table))
		rows, err := db.Query(query)
		if err != nil {
			return fmt.Errorf("required table %s is missing or incomplete: %w", table, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close schema validation rows for %s: %w", table, err)
		}
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
