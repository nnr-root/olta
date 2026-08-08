package models

import (
	"fmt"
	"strconv"

	"github.com/s4l1hs/olta/pkg/campaign/quishing"
)

// generateQRCode generates a QR code in memory and returns its base64 payload
// plus a stable content-ID filename for use in campaign messages.
func generateQRCode(content string, stringSize string) (string, string, error) {
	size, err := strconv.Atoi(stringSize)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert QR code size to int: %w", err)
	}

	generated, err := quishing.NewService().Generate(content, quishing.Options{
		Size:            size,
		ErrorCorrection: quishing.Medium,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate QR code: %w", err)
	}
	return generated.Base64, generated.Attachment.ContentID, nil
}
