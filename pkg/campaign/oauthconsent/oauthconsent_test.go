package oauthconsent

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderInjectsOAuthMetadata(t *testing.T) {
	metadata := NewMetadata(
		"Contoso Portal",
		"Contoso <Security>",
		[]string{"profile", "offline_access", "Custom.Read"},
		"https://portal.example.test/oauth/callback?source=campaign&step=4",
	)
	rendered, err := Render(metadata)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	html := string(rendered)
	for _, expected := range []string{
		"Contoso Portal",
		"Read your basic profile",
		"Maintain access to data",
		"Custom.Read",
		"portal.example.test",
		`data-oauth-accept`,
		`data-oauth-cancel`,
		AssetBasePath + "oauthconsent.js",
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("rendered consent prompt does not contain %q", expected)
		}
	}
	if strings.Contains(html, "Contoso <Security>") || strings.Contains(html, "source=campaign&step=4") {
		t.Fatal("rendered consent prompt contains unescaped OAuth metadata")
	}
}

func TestParseScopeList(t *testing.T) {
	got := ParseScopeList("openid, profile; offline_access")
	if len(got) != 3 {
		t.Fatalf("ParseScopeList() returned %d scopes, want 3", len(got))
	}
	scopes := Scopes(got)
	if scopes[0].Name != "Sign you in" || scopes[2].Name != "Maintain access to data" {
		t.Fatalf("Scopes() returned unexpected presentation: %#v", scopes)
	}
}

func TestRenderRejectsInvalidMetadata(t *testing.T) {
	if _, err := Render(NewMetadata("", "Publisher", nil, "https://example.test/callback")); err == nil {
		t.Fatal("Render() accepted an empty application name")
	}
	if _, err := Render(NewMetadata("App", "Publisher", nil, "javascript:alert(1)")); err == nil {
		t.Fatal("Render() accepted a non-HTTP redirect URI")
	}
}

func TestEmbeddedAssets(t *testing.T) {
	assets, err := Assets()
	if err != nil {
		t.Fatalf("Assets() error = %v", err)
	}
	for _, name := range []string{"oauthconsent.css", "oauthconsent.js"} {
		contents, readErr := fs.ReadFile(assets, name)
		if readErr != nil {
			t.Fatalf("read embedded asset %q: %v", name, readErr)
		}
		if len(contents) == 0 {
			t.Errorf("embedded asset %q is empty", name)
		}
	}
	javascript, err := JavaScript()
	if err != nil {
		t.Fatalf("JavaScript() error = %v", err)
	}
	if !strings.Contains(string(javascript), "olta:oauthconsent:") {
		t.Error("embedded JavaScript does not dispatch consent events")
	}
}

func TestHandlerServesEmbeddedAsset(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/oauthconsent.css", nil)
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("Handler() status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), ".olta-oauth-consent") {
		t.Error("Handler() response does not contain the embedded stylesheet")
	}
}
