package models

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/skip2/go-qrcode"
)

// generateQRCode generates a QR code in memory and returns its base64 payload
// plus a stable content-ID filename for use in campaign messages.
func generateQRCode(content string, stringSize string) (string, string, error) {
	size, err := strconv.Atoi(stringSize)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert QR code size to int: %w", err)
	}

	qrCode, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate QR code: %w", err)
	}
	qrCode.DisableBorder = true

	png, err := qrCode.PNG(size)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode QR code: %w", err)
	}

	digest := sha256.Sum256([]byte(content))
	name := fmt.Sprintf("qr-%x.png", digest[:8])
	return base64.StdEncoding.EncodeToString(png), name, nil
}
