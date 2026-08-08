package quishing

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
	"text/template"
)

func TestGenerateURLToBase64AndInlineAttachment(t *testing.T) {
	generated, err := NewService().Generate("https://example.test/track?rid=recipient-1", Options{})
	if err != nil {
		t.Fatalf("Generate(): %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(generated.Base64)
	if err != nil {
		t.Fatalf("decode Base64: %v", err)
	}
	if !bytes.Equal(decoded, generated.PNG) {
		t.Fatal("Base64 payload does not match generated PNG")
	}
	if !bytes.Equal(generated.Attachment.Data, generated.PNG) {
		t.Fatal("inline attachment does not contain generated PNG")
	}
	if generated.Attachment.Base64 != generated.Base64 {
		t.Fatal("inline attachment Base64 does not match generated image")
	}
	if generated.Attachment.ContentType != "image/png" {
		t.Fatalf("content type = %q, want image/png", generated.Attachment.ContentType)
	}
	if !strings.HasPrefix(generated.DataURI, "data:image/png;base64,") {
		t.Fatalf("data URI = %q, want PNG data URI", generated.DataURI)
	}
	if len(decoded) < 8 || string(decoded[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal("generated payload is not a PNG")
	}
}

func TestGenerateCustomOptions(t *testing.T) {
	generated, err := NewService().Generate("https://example.test/track?rid=recipient-2", Options{
		Size:            320,
		BackgroundColor: "#abc",
		ForegroundColor: "#123456",
		ErrorCorrection: High,
	})
	if err != nil {
		t.Fatalf("Generate(): %v", err)
	}
	if generated.Options.Size != 320 {
		t.Fatalf("size = %d, want 320", generated.Options.Size)
	}
	if generated.Options.BackgroundColor != "#AABBCC" {
		t.Fatalf("background = %q, want #AABBCC", generated.Options.BackgroundColor)
	}
	if generated.Options.ForegroundColor != "#123456" {
		t.Fatalf("foreground = %q, want #123456", generated.Options.ForegroundColor)
	}
	if generated.Options.ErrorCorrection != High {
		t.Fatalf("error correction = %q, want High", generated.Options.ErrorCorrection)
	}

	config, err := png.DecodeConfig(bytes.NewReader(generated.PNG))
	if err != nil {
		t.Fatalf("decode PNG config: %v", err)
	}
	if config.Width != 320 || config.Height != 320 {
		t.Fatalf("PNG dimensions = %dx%d, want 320x320", config.Width, config.Height)
	}
}

func TestErrorCorrectionLevels(t *testing.T) {
	for _, level := range []ErrorCorrection{Low, Medium, High} {
		t.Run(string(level), func(t *testing.T) {
			generated, err := NewService().Generate("https://example.test/track", Options{ErrorCorrection: level})
			if err != nil {
				t.Fatalf("Generate(): %v", err)
			}
			if generated.Options.ErrorCorrection != level {
				t.Fatalf("error correction = %q, want %q", generated.Options.ErrorCorrection, level)
			}
		})
	}
}

func TestInlineHTMLTemplateTag(t *testing.T) {
	generated, err := NewService().Generate("https://example.test/track?rid=recipient-3", Options{})
	if err != nil {
		t.Fatalf("Generate(): %v", err)
	}
	tmpl, err := template.New("email").Parse(`<div>{{.QRCode}}</div>`)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	var rendered bytes.Buffer
	err = tmpl.Execute(&rendered, struct{ QRCode string }{QRCode: generated.InlineHTML()})
	if err != nil {
		t.Fatalf("execute template: %v", err)
	}
	if !strings.Contains(rendered.String(), `src="cid:`+generated.Attachment.ContentID+`"`) {
		t.Fatalf("rendered template = %q, want inline content ID", rendered.String())
	}
}

func TestGenerateRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		options Options
	}{
		{name: "relative URL", url: "/track"},
		{name: "small size", url: "https://example.test", options: Options{Size: MinSize - 1}},
		{name: "large size", url: "https://example.test", options: Options{Size: MaxSize + 1}},
		{name: "bad color", url: "https://example.test", options: Options{ForegroundColor: "purple"}},
		{name: "same colors", url: "https://example.test", options: Options{ForegroundColor: "white"}},
		{name: "bad correction", url: "https://example.test", options: Options{ErrorCorrection: "Maximum"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewService().Generate(test.url, test.options); err == nil {
				t.Fatal("Generate() error = nil, want validation error")
			}
		})
	}
}
