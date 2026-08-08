package models

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateQRCodeInMemory(t *testing.T) {
	encoded, name, err := generateQRCode("https://example.test/campaign", "256")
	if err != nil {
		t.Fatalf("generateQRCode(): %v", err)
	}
	if !strings.HasPrefix(name, "qr-") || !strings.HasSuffix(name, ".png") {
		t.Fatalf("name = %q, want qr-*.png", name)
	}
	png, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode QR code: %v", err)
	}
	if len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal("generated payload is not a PNG")
	}
}

func TestGenerateQRCodeRejectsInvalidSize(t *testing.T) {
	if _, _, err := generateQRCode("https://example.test", "invalid"); err == nil {
		t.Fatal("generateQRCode() accepted an invalid size")
	}
}
