package bitb

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderFrameInjectsParameters(t *testing.T) {
	frame := NewFrame("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=consent&label=<unsafe>")
	frame.Theme = ThemeWindows11
	frame.Title = "Microsoft <Account>"

	rendered, err := RenderFrame(frame)
	if err != nil {
		t.Fatalf("RenderFrame() error = %v", err)
	}
	html := string(rendered)
	for _, expected := range []string{
		`data-theme="windows11"`,
		`login.microsoftonline.com`,
		`aria-label="Connection is secure"`,
		AssetBasePath + "bitb.js",
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("rendered frame does not contain %q", expected)
		}
	}
	if strings.Contains(html, "<unsafe>") || strings.Contains(html, "Microsoft <Account>") {
		t.Fatal("rendered frame contains unescaped dynamic HTML")
	}
}

func TestRenderFrameRejectsInvalidParameters(t *testing.T) {
	if _, err := Render("javascript:alert(1)"); err == nil {
		t.Fatal("Render() accepted a non-HTTP URL")
	}
	if _, err := RenderTheme("https://example.com", Theme("solaris")); err == nil {
		t.Fatal("RenderTheme() accepted an unsupported theme")
	}
}

func TestRenderLinuxTheme(t *testing.T) {
	rendered, err := RenderTheme("https://example.com", ThemeLinux)
	if err != nil {
		t.Fatalf("RenderTheme() error = %v", err)
	}
	if !strings.Contains(string(rendered), `data-theme="linux"`) || !strings.Contains(string(rendered), "linux.css") {
		t.Fatal("RenderTheme() did not render the Linux theme")
	}
}

func TestEmbeddedAssets(t *testing.T) {
	assets, err := Assets()
	if err != nil {
		t.Fatalf("Assets() error = %v", err)
	}
	for _, name := range []string{"bitb.css", "windows11.css", "macos.css", "linux.css", "bitb.js"} {
		contents, readErr := fs.ReadFile(assets, name)
		if readErr != nil {
			t.Fatalf("read embedded asset %q: %v", name, readErr)
		}
		if len(contents) == 0 {
			t.Errorf("embedded asset %q is empty", name)
		}
	}

	css, err := CSS(ThemeAuto)
	if err != nil {
		t.Fatalf("CSS() error = %v", err)
	}
	if !strings.Contains(string(css), `data-theme="windows11"`) ||
		!strings.Contains(string(css), `data-theme="macos"`) ||
		!strings.Contains(string(css), `data-theme="linux"`) {
		t.Error("auto CSS does not include all OS themes")
	}
	javascript, err := JavaScript()
	if err != nil {
		t.Fatalf("JavaScript() error = %v", err)
	}
	if !strings.Contains(string(javascript), "pointerdown") || !strings.Contains(string(javascript), "data-bitb-close") {
		t.Error("embedded JavaScript does not contain drag and close behavior")
	}
	if !strings.Contains(string(javascript), `return "linux"`) {
		t.Error("embedded JavaScript does not detect Linux platforms")
	}
}

func TestHandlerServesEmbeddedAsset(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/bitb.js", nil)
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("Handler() status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "olta:bitb:") {
		t.Error("Handler() response does not contain the embedded script")
	}
}
