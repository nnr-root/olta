// Package quishing generates recipient tracking QR codes entirely in memory.
package quishing

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"image/color"
	"net/url"
	"strconv"
	"strings"

	"github.com/skip2/go-qrcode"
)

const (
	DefaultSize = 256
	MinSize     = 64
	MaxSize     = 2048

	DefaultBackgroundColor = "#FFFFFF"
	DefaultForegroundColor = "#000000"
)

// ErrorCorrection identifies the QR error-recovery level.
type ErrorCorrection string

const (
	Low    ErrorCorrection = "Low"
	Medium ErrorCorrection = "Medium"
	High   ErrorCorrection = "High"
)

// Options controls the appearance and resilience of a generated QR code.
// Colors accept #RGB or #RRGGBB notation, as well as black and white.
type Options struct {
	Size            int             `json:"size"`
	BackgroundColor string          `json:"background_color"`
	ForegroundColor string          `json:"foreground_color"`
	ErrorCorrection ErrorCorrection `json:"error_correction"`
}

// InlineAttachment contains the in-memory MIME data needed to embed a QR code
// in an email. ContentID does not include surrounding angle brackets.
type InlineAttachment struct {
	Filename    string
	ContentID   string
	ContentType string
	Data        []byte
	Base64      string
}

// Image is a generated PNG and its email- and browser-friendly encodings.
type Image struct {
	PNG        []byte
	Base64     string
	DataURI    string
	Attachment InlineAttachment
	Options    Options
}

// InlineHTML returns an img tag referencing the generated MIME attachment.
func (i Image) InlineHTML() string {
	return fmt.Sprintf(`<img alt="QR code" src="cid:%s">`, html.EscapeString(i.Attachment.ContentID))
}

// Service generates QR images without writing temporary files.
type Service struct{}

// NewService creates an in-memory QR generation service.
func NewService() *Service {
	return &Service{}
}

// DefaultOptions returns the defaults used for omitted option values.
func DefaultOptions() Options {
	return Options{
		Size:            DefaultSize,
		BackgroundColor: DefaultBackgroundColor,
		ForegroundColor: DefaultForegroundColor,
		ErrorCorrection: Medium,
	}
}

// Generate converts an absolute HTTP(S) tracking URL into an in-memory PNG,
// Base64 payload, data URI, and inline MIME attachment.
func (s *Service) Generate(targetURL string, options Options) (Image, error) {
	if s == nil {
		return Image{}, errors.New("quishing: nil generation service")
	}
	if err := validateURL(targetURL); err != nil {
		return Image{}, err
	}

	normalized, background, foreground, recovery, err := normalizeOptions(options)
	if err != nil {
		return Image{}, err
	}

	code, err := qrcode.New(targetURL, recovery)
	if err != nil {
		return Image{}, fmt.Errorf("quishing: create QR code: %w", err)
	}
	code.BackgroundColor = background
	code.ForegroundColor = foreground

	pngData, err := code.PNG(normalized.Size)
	if err != nil {
		return Image{}, fmt.Errorf("quishing: encode PNG: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(pngData)
	filename := attachmentName(targetURL, normalized)
	attachment := InlineAttachment{
		Filename:    filename,
		ContentID:   filename,
		ContentType: "image/png",
		Data:        pngData,
		Base64:      encoded,
	}

	return Image{
		PNG:        pngData,
		Base64:     encoded,
		DataURI:    "data:image/png;base64," + encoded,
		Attachment: attachment,
		Options:    normalized,
	}, nil
}

func validateURL(targetURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return fmt.Errorf("quishing: invalid target URL: %w", err)
	}
	if parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("quishing: target URL must be an absolute HTTP(S) URL")
	}
	return nil
}

func normalizeOptions(options Options) (Options, color.RGBA, color.RGBA, qrcode.RecoveryLevel, error) {
	defaults := DefaultOptions()
	if options.Size == 0 {
		options.Size = defaults.Size
	}
	if options.Size < MinSize || options.Size > MaxSize {
		return Options{}, color.RGBA{}, color.RGBA{}, 0, fmt.Errorf("quishing: size must be between %d and %d pixels", MinSize, MaxSize)
	}
	if strings.TrimSpace(options.BackgroundColor) == "" {
		options.BackgroundColor = defaults.BackgroundColor
	}
	if strings.TrimSpace(options.ForegroundColor) == "" {
		options.ForegroundColor = defaults.ForegroundColor
	}

	background, canonicalBackground, err := parseColor(options.BackgroundColor)
	if err != nil {
		return Options{}, color.RGBA{}, color.RGBA{}, 0, fmt.Errorf("quishing: invalid background color: %w", err)
	}
	foreground, canonicalForeground, err := parseColor(options.ForegroundColor)
	if err != nil {
		return Options{}, color.RGBA{}, color.RGBA{}, 0, fmt.Errorf("quishing: invalid foreground color: %w", err)
	}
	if background == foreground {
		return Options{}, color.RGBA{}, color.RGBA{}, 0, errors.New("quishing: foreground and background colors must differ")
	}
	options.BackgroundColor = canonicalBackground
	options.ForegroundColor = canonicalForeground

	recovery, canonicalCorrection, err := parseErrorCorrection(options.ErrorCorrection)
	if err != nil {
		return Options{}, color.RGBA{}, color.RGBA{}, 0, err
	}
	options.ErrorCorrection = canonicalCorrection
	return options, background, foreground, recovery, nil
}

func parseErrorCorrection(level ErrorCorrection) (qrcode.RecoveryLevel, ErrorCorrection, error) {
	switch strings.ToLower(strings.TrimSpace(string(level))) {
	case "", "medium":
		return qrcode.Medium, Medium, nil
	case "low":
		return qrcode.Low, Low, nil
	case "high":
		return qrcode.High, High, nil
	default:
		return 0, "", fmt.Errorf("quishing: unsupported error correction level %q", level)
	}
}

func parseColor(value string) (color.RGBA, string, error) {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(trimmed) {
	case "black":
		return color.RGBA{A: 0xff}, DefaultForegroundColor, nil
	case "white":
		return color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}, DefaultBackgroundColor, nil
	}

	hex := strings.TrimPrefix(trimmed, "#")
	if len(hex) == 3 {
		hex = strings.Repeat(hex[0:1], 2) + strings.Repeat(hex[1:2], 2) + strings.Repeat(hex[2:3], 2)
	}
	if len(hex) != 6 {
		return color.RGBA{}, "", errors.New("expected #RGB or #RRGGBB")
	}
	value64, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return color.RGBA{}, "", errors.New("expected #RGB or #RRGGBB")
	}
	parsed := color.RGBA{
		R: uint8(value64 >> 16),
		G: uint8(value64 >> 8),
		B: uint8(value64),
		A: 0xff,
	}
	return parsed, fmt.Sprintf("#%06X", value64), nil
}

func attachmentName(targetURL string, options Options) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s", targetURL, options.Size, options.BackgroundColor, options.ForegroundColor, options.ErrorCorrection)))
	return fmt.Sprintf("qr-%x.png", digest[:8])
}
