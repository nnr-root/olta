package controllers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestCampaignComponentAssetRoutes(t *testing.T) {
	router := mux.NewRouter()
	registerCampaignComponentAssets(router)

	tests := []struct {
		path     string
		contains string
	}{
		{path: "/static/components/bitb/bitb.js", contains: "data-bitb-window"},
		{path: "/static/components/oauthconsent/oauthconsent.css", contains: ".olta-oauth-consent"},
	}
	for _, test := range tests {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", test.path, response.Code, http.StatusOK)
			continue
		}
		if !strings.Contains(response.Body.String(), test.contains) {
			t.Errorf("GET %s did not contain %q", test.path, test.contains)
		}
	}
}
