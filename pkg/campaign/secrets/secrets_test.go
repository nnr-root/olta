package secrets

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	t.Setenv(MasterKeyEnvironment, key)
	if _, err := ConfigureFromEnvironment(); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := Encrypt("sensitive-value")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ciphertext, prefix) || strings.Contains(ciphertext, "sensitive-value") {
		t.Fatalf("unexpected ciphertext %q", ciphertext)
	}
	plaintext, err := Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "sensitive-value" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestEncryptedValueFailsClosedWithoutKey(t *testing.T) {
	t.Setenv(MasterKeyEnvironment, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := ConfigureFromEnvironment(); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := Encrypt("sensitive-value")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(MasterKeyEnvironment, "")
	if _, err := ConfigureFromEnvironment(); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(ciphertext); err == nil {
		t.Fatal("Decrypt() succeeded without a key")
	}
}

func TestLegacyPlaintextCompatibility(t *testing.T) {
	t.Setenv(MasterKeyEnvironment, "")
	if _, err := ConfigureFromEnvironment(); err != nil {
		t.Fatal(err)
	}
	got, err := Encrypt("legacy")
	if err != nil || got != "legacy" {
		t.Fatalf("Encrypt() = %q, %v", got, err)
	}
	got, err = Decrypt("legacy")
	if err != nil || got != "legacy" {
		t.Fatalf("Decrypt() = %q, %v", got, err)
	}
}
