package models

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/config"
	"github.com/s4l1hs/olta/pkg/campaign/secrets"
)

func TestOperationalSecretsAreEncryptedAndRedacted(t *testing.T) {
	previousKey := os.Getenv(secrets.MasterKeyEnvironment)
	t.Setenv(secrets.MasterKeyEnvironment, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	t.Cleanup(func() {
		_ = os.Setenv(secrets.MasterKeyEnvironment, previousKey)
		_, _ = secrets.ConfigureFromEnvironment()
	})

	if err := Setup(&config.Config{DBName: "sqlite3", DBPath: ":memory:"}); err != nil {
		t.Fatal(err)
	}
	profile := SMTP{
		UserId:      1,
		Name:        "encrypted-profile",
		Host:        "smtp.example:587",
		FromAddress: "sender@example.com",
		Username:    "operator",
		Password:    "smtp-secret",
	}
	if err := PostSMTP(&profile); err != nil {
		t.Fatal(err)
	}

	var storedPassword string
	if err := db.Table("smtp").Select("password").Where("id=?", profile.Id).Row().Scan(&storedPassword); err != nil {
		t.Fatal(err)
	}
	if !secrets.IsEncrypted(storedPassword) || strings.Contains(storedPassword, profile.Password) {
		t.Fatalf("password was not encrypted at rest: %q", storedPassword)
	}
	reloaded, err := GetSMTP(profile.Id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Password != profile.Password {
		t.Fatalf("decrypted password = %q", reloaded.Password)
	}
	encoded, err := json.Marshal(reloaded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), profile.Password) || strings.Contains(string(encoded), "password") {
		t.Fatalf("API JSON exposed the password: %s", encoded)
	}

	admin, err := GetUser(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GetUserByAPIKey(admin.ApiKey); err != nil {
		t.Fatalf("hashed API-key lookup failed: %v", err)
	}
	var storedKey, storedHash string
	if err := db.Table("users").Select("api_key").Where("id=1").Row().Scan(&storedKey); err != nil {
		t.Fatal(err)
	}
	if err := db.Table("users").Select("api_key_hash").Where("id=1").Row().Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if !secrets.IsEncrypted(storedKey) || storedHash != apiKeyHash(admin.ApiKey) {
		t.Fatalf("API key storage is not protected: encrypted=%v hash=%q", secrets.IsEncrypted(storedKey), storedHash)
	}
}
