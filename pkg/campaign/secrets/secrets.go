// Package secrets provides authenticated encryption for sensitive campaign data.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	MasterKeyEnvironment = "OLTA_MASTER_KEY"
	prefix               = "olta:v1:"
	keySize              = 32
)

var state struct {
	sync.RWMutex
	key []byte
}

// ConfigureFromEnvironment loads the 256-bit master key. The key may be
// base64, hex, or a raw 32-byte value. An empty value disables encryption for
// backward-compatible local development.
func ConfigureFromEnvironment() (bool, error) {
	value := strings.TrimSpace(os.Getenv(MasterKeyEnvironment))
	if value == "" {
		state.Lock()
		state.key = nil
		state.Unlock()
		return false, nil
	}
	key, err := decodeKey(value)
	if err != nil {
		return false, err
	}
	state.Lock()
	state.key = append([]byte(nil), key...)
	state.Unlock()
	return true, nil
}

func decodeKey(value string) ([]byte, error) {
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		hex.DecodeString,
	}
	for _, decode := range decoders {
		if key, err := decode(value); err == nil && len(key) == keySize {
			return key, nil
		}
	}
	if len(value) == keySize {
		return []byte(value), nil
	}
	return nil, fmt.Errorf("%s must contain exactly 32 bytes encoded as base64, hex, or raw text", MasterKeyEnvironment)
}

func currentKey() []byte {
	state.RLock()
	defer state.RUnlock()
	return append([]byte(nil), state.key...)
}

// Enabled reports whether encryption has been configured.
func Enabled() bool {
	return len(currentKey()) == keySize
}

// Derive returns deterministic key material scoped by label. It allows
// cookies and CSRF protection to remain stable across restarts and instances
// without storing additional secrets. The boolean is false when no master key
// is configured.
func Derive(label string, size int) ([]byte, bool) {
	key := currentKey()
	if len(key) == 0 || size <= 0 {
		return nil, false
	}
	result := make([]byte, 0, size)
	var previous []byte
	for counter := byte(1); len(result) < size; counter++ {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(previous)
		_, _ = mac.Write([]byte(label))
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		result = append(result, previous...)
	}
	return result[:size], true
}

// IsEncrypted reports whether value uses the supported encrypted envelope.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, prefix)
}

// Encrypt encrypts plaintext with AES-256-GCM. Empty strings and already
// encrypted envelopes are returned unchanged.
func Encrypt(plaintext string) (string, error) {
	if plaintext == "" || IsEncrypted(plaintext) {
		return plaintext, nil
	}
	key := currentKey()
	if len(key) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(prefix))
	return prefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypt opens an encrypted envelope. Legacy plaintext values are returned
// unchanged. Encrypted values fail closed when the master key is unavailable.
func Decrypt(value string) (string, error) {
	if value == "" || !IsEncrypted(value) {
		return value, nil
	}
	key := currentKey()
	if len(key) == 0 {
		return "", errors.New("encrypted campaign secret cannot be opened without OLTA_MASTER_KEY")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted campaign secret: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize() {
		return "", errors.New("encrypted campaign secret is truncated")
	}
	nonce, ciphertext := payload[:gcm.NonceSize()], payload[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(prefix))
	if err != nil {
		return "", errors.New("encrypted campaign secret authentication failed")
	}
	return string(plaintext), nil
}
