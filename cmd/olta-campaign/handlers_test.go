package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	campaignapi "github.com/s4l1hs/olta/pkg/campaign/controllers/api"
)

func TestPersonalizerPreviewRoute(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/personalizer/preview", strings.NewReader(`{
  "subject":"{Hello|Hi} {{.FirstName}}",
  "text":"{Review|Open} {{.Department}} at {{.PhishingURL}}",
  "context":{"FirstName":"Ada","Department":"Engineering","PhishingURL":"https://training.example.test"}
}`))
	response := httptest.NewRecorder()
	campaignapi.NewPreviewHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var preview campaignapi.PersonalizerPreviewResponse
	if err := json.NewDecoder(response.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	if len(preview.Variations) != 5 {
		t.Fatalf("variation count = %d, want 5", len(preview.Variations))
	}
	for _, variation := range preview.Variations {
		if !strings.Contains(variation.Subject, "Ada") || strings.Contains(variation.Subject, "{") {
			t.Fatalf("invalid variation: %+v", variation)
		}
	}
}

func TestTemplateEditorIncludesLivePreviewControls(t *testing.T) {
	page, err := os.ReadFile("templates/templates.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		`id="personalizer-preview-panel"`,
		`id="evaluate-variations"`,
		`id="bitb-preview-theme"`,
		`id="bitb-preview-frame"`,
		`sandbox="allow-scripts"`,
		`personalizer_preview.js`,
		`value="win11-light"`,
		`value="win11-dark"`,
		`value="macos-light"`,
		`value="macos-dark"`,
		`value="linux-gnome"`,
	} {
		if !strings.Contains(string(page), marker) {
			t.Errorf("template editor does not contain %q", marker)
		}
	}

	script, err := os.ReadFile("static/js/src/app/personalizer_preview.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		`/v1/personalizer/preview`,
		`/v1/bitb/preview`,
		`setTimeout(evaluateVariations, 350)`,
	} {
		if !strings.Contains(string(script), marker) {
			t.Errorf("preview script does not contain %q", marker)
		}
	}
}

func TestBITBPreviewRoute(t *testing.T) {
	for _, theme := range []string{"win11-light", "win11-dark", "macos-light", "macos-dark", "linux-gnome"} {
		t.Run(theme, func(t *testing.T) {
			body := `{"url":"https://login.example.test/","title":"Sign in","theme":"` + theme + `","content":"<form>Login</form>"}`
			request := httptest.NewRequest(http.MethodPost, "/api/v1/bitb/preview", strings.NewReader(body))
			response := httptest.NewRecorder()
			campaignapi.NewPreviewHandler().ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			var preview campaignapi.BITBPreviewResponse
			if err := json.NewDecoder(response.Body).Decode(&preview); err != nil {
				t.Fatal(err)
			}
			if string(preview.Theme) != theme || !strings.Contains(preview.HTML, `data-theme="`+theme+`"`) || !strings.Contains(preview.HTML, "Login") {
				t.Fatalf("invalid BITB preview for %s: %+v", theme, preview)
			}
		})
	}
}
