package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQRCodePreview(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/quishing/preview", strings.NewReader(`{
		"url":"https://example.test/track?rid=preview",
		"size":320,
		"background_color":"#f0f0f0",
		"foreground_color":"#102030",
		"error_correction":"High"
	}`))
	response := httptest.NewRecorder()

	new(Server).QRCodePreview(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}

	var preview QRCodePreviewResponse
	if err := json.NewDecoder(response.Body).Decode(&preview); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(preview.Base64)
	if err != nil {
		t.Fatalf("decode QR Base64: %v", err)
	}
	if len(decoded) < 8 || !bytes.Equal(decoded[:8], []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("preview response is not a PNG")
	}
	if preview.Options.Size != 320 {
		t.Fatalf("size = %d, want 320", preview.Options.Size)
	}
	if preview.ContentType != "image/png" {
		t.Fatalf("content type = %q, want image/png", preview.ContentType)
	}
}

func TestQRCodePreviewRejectsInvalidRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid JSON", body: `{`},
		{name: "relative URL", body: `{"url":"/track"}`},
		{name: "invalid options", body: `{"url":"https://example.test","size":12}`},
		{name: "multiple values", body: `{"url":"https://example.test"} {}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/quishing/preview", strings.NewReader(test.body))
			response := httptest.NewRecorder()

			new(Server).QRCodePreview(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
		})
	}
}
