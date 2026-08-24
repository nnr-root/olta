package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/s4l1hs/olta/pkg/campaign/secrets"
)

func apiKeyHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func storedUser(user User) (User, error) {
	copyUser := user
	copyUser.ApiKeyHash = apiKeyHash(user.ApiKey)
	protected, err := secrets.Encrypt(user.ApiKey)
	if err != nil {
		return User{}, err
	}
	copyUser.ApiKey = protected
	return copyUser, nil
}

func openUser(user *User) error {
	value, err := secrets.Decrypt(user.ApiKey)
	if err != nil {
		return err
	}
	user.ApiKey = value
	return nil
}

func storedSMTP(value SMTP) (SMTP, error) {
	protected, err := secrets.Encrypt(value.Password)
	value.Password = protected
	return value, err
}

func openSMTP(value *SMTP) error {
	plaintext, err := secrets.Decrypt(value.Password)
	value.Password = plaintext
	return err
}

func storedSMS(value SMS) (SMS, error) {
	protected, err := secrets.Encrypt(value.TwilioAuthToken)
	value.TwilioAuthToken = protected
	return value, err
}

func openSMS(value *SMS) error {
	plaintext, err := secrets.Decrypt(value.TwilioAuthToken)
	value.TwilioAuthToken = plaintext
	return err
}

func storedIMAP(value IMAP) (IMAP, error) {
	protected, err := secrets.Encrypt(value.Password)
	value.Password = protected
	return value, err
}

func openIMAP(value *IMAP) error {
	plaintext, err := secrets.Decrypt(value.Password)
	value.Password = plaintext
	return err
}

func storedWebhook(value Webhook) (Webhook, error) {
	protected, err := secrets.Encrypt(value.Secret)
	value.Secret = protected
	return value, err
}

func openWebhook(value *Webhook) error {
	plaintext, err := secrets.Decrypt(value.Secret)
	value.Secret = plaintext
	return err
}

func storedEvent(value Event) (Event, error) {
	protected, err := secrets.Encrypt(value.Details)
	value.Details = protected
	return value, err
}

func openEvent(value *Event) error {
	plaintext, err := secrets.Decrypt(value.Details)
	value.Details = plaintext
	return err
}

type protectedColumn struct {
	table, id, value string
}

// protectStoredSecrets upgrades legacy plaintext values in place after the
// schema migration. The operation is idempotent and also verifies that the
// configured key can open existing encrypted values.
func protectStoredSecrets() error {
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	rollback := func(err error) error {
		_ = tx.Rollback().Error
		return err
	}

	if err := protectAPIKeys(tx); err != nil {
		return rollback(err)
	}
	if !secrets.Enabled() {
		return tx.Commit().Error
	}
	columns := []protectedColumn{
		{table: "smtp", id: "id", value: "password"},
		{table: "sms", id: "id", value: "twilio_auth_token"},
		{table: "webhooks", id: "id", value: "secret"},
		{table: "imap", id: "user_id", value: "password"},
		{table: "events", id: "id", value: "details"},
	}
	for _, column := range columns {
		if err := protectColumn(tx, column); err != nil {
			return rollback(err)
		}
	}
	return tx.Commit().Error
}

func protectAPIKeys(tx *gorm.DB) error {
	type row struct {
		ID     int64
		APIKey string `gorm:"column:api_key"`
	}
	var rows []row
	if err := tx.Table("users").Select("id, api_key").Scan(&rows).Error; err != nil {
		return err
	}
	for _, item := range rows {
		plaintext, err := secrets.Decrypt(item.APIKey)
		if err != nil {
			return fmt.Errorf("decrypt users.api_key for id %d: %w", item.ID, err)
		}
		protected, err := secrets.Encrypt(plaintext)
		if err != nil {
			return err
		}
		if err := tx.Table("users").Where("id=?", item.ID).Updates(map[string]interface{}{
			"api_key":      protected,
			"api_key_hash": apiKeyHash(plaintext),
		}).Error; err != nil {
			return err
		}
	}
	return nil
}

func protectColumn(tx *gorm.DB, column protectedColumn) error {
	type row struct {
		ID    int64
		Value string
	}
	var rows []row
	query := fmt.Sprintf("SELECT `%s` AS id, `%s` AS value FROM `%s` WHERE `%s` IS NOT NULL AND `%s` != ''", column.id, column.value, column.table, column.value, column.value)
	if err := tx.Raw(query).Scan(&rows).Error; err != nil {
		return err
	}
	for _, item := range rows {
		plaintext, err := secrets.Decrypt(item.Value)
		if err != nil {
			return fmt.Errorf("decrypt %s.%s for id %d: %w", column.table, column.value, item.ID, err)
		}
		protected, err := secrets.Encrypt(plaintext)
		if err != nil {
			return err
		}
		if protected != item.Value {
			if err := tx.Table(column.table).Where(column.id+"=?", item.ID).UpdateColumn(column.value, protected).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
