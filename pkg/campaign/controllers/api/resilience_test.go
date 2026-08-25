package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/models"
)

func TestResilienceEndpointRequiresAuth(t *testing.T) {
	ctx := setupTest(t)

	request := httptest.NewRequest(http.MethodGet, "/api/campaigns/1/resilience", nil)
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestResilienceEndpointReturnsReport(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	request := httptest.NewRequest(http.MethodGet, "/api/campaigns/1/resilience", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ctx.apiKey))
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var payload struct {
		CampaignID int64 `json:"campaign_id"`
		Funnel     []struct {
			Stage    string `json:"stage"`
			Measured bool   `json:"measured"`
		} `json:"funnel"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CampaignID != 1 {
		t.Fatalf("campaign_id = %d, want 1", payload.CampaignID)
	}
	if len(payload.Funnel) != 8 {
		t.Fatalf("funnel has %d stages, want 8", len(payload.Funnel))
	}
}

// TestResilienceEndpointRequiresOwnership confirms the endpoint mirrors
// (as *Server) Campaign's ownership check: a campaign owned by another user
// resolves as not found, never as the caller's own data.
func TestResilienceEndpointRequiresOwnership(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	other := createUnpriviledgedUser(t, models.RoleUser)

	request := httptest.NewRequest(http.MethodGet, "/api/campaigns/1/resilience", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", other.ApiKey))
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s, want %d", recorder.Code, recorder.Body.String(), http.StatusNotFound)
	}
}

func TestNavigatorLayerIsWellFormed(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	request := httptest.NewRequest(http.MethodGet, "/api/campaigns/1/resilience/navigator", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ctx.apiKey))
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var layer struct {
		Versions struct {
			Navigator string `json:"navigator"`
			Layer     string `json:"layer"`
		} `json:"versions"`
		Domain     string `json:"domain"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       int    `json:"score"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}
	if layer.Domain != "enterprise-attack" {
		t.Fatalf("domain = %q, want enterprise-attack", layer.Domain)
	}
	if layer.Versions.Layer == "" {
		t.Fatal("layer version is required by Navigator")
	}
	if len(layer.Techniques) == 0 {
		t.Fatal("layer contains no techniques")
	}
	for _, technique := range layer.Techniques {
		if technique.TechniqueID == "" {
			t.Fatal("a technique entry has an empty techniqueID")
		}
	}
}
