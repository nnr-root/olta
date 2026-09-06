package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/models"
)

func TestPurgeRequiresAuth(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	request := httptest.NewRequest(http.MethodPost, "/api/campaigns/1/purge?confirm=PURGE", nil)
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

// TestPurgeRequiresConfirmation is the guard that matters: an irreversible
// operation must not be reachable by an accidental request.
func TestPurgeRequiresConfirmation(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	for _, target := range []string{
		"/api/campaigns/1/purge",
		"/api/campaigns/1/purge?confirm=",
		"/api/campaigns/1/purge?confirm=yes",
		"/api/campaigns/1/purge?confirm=purge",
	} {
		request := httptest.NewRequest(http.MethodPost, target, nil)
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ctx.apiKey))
		recorder := httptest.NewRecorder()
		ctx.apiServer.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", target, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "cannot be undone") {
			t.Errorf("%s: response does not say what the operation does: %s", target, recorder.Body.String())
		}
	}

	// Nothing was purged by any of the rejected attempts.
	campaign, err := models.GetCampaignResults(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range campaign.Results {
		if result.Email == "purged@invalid" {
			t.Fatal("a rejected purge request still cleared data")
		}
	}
}

func TestPurgeAnonymizesTheCampaign(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	request := httptest.NewRequest(http.MethodPost, "/api/campaigns/1/purge?confirm=PURGE", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ctx.apiKey))
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var summary struct {
		CampaignID int64  `json:"campaign_id"`
		Results    int64  `json:"results"`
		Scope      string `json:"scope"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.CampaignID != 1 {
		t.Errorf("campaign_id = %d, want 1", summary.CampaignID)
	}
	if summary.Results == 0 {
		t.Error("no results were purged")
	}
	if summary.Scope == "" {
		t.Error("scope is empty; an irreversible operation must state what it did")
	}

	campaign, err := models.GetCampaignResults(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range campaign.Results {
		if result.Email != "purged@invalid" || result.FirstName != "" {
			t.Errorf("result still carries personal data: %+v", result.BaseRecipient)
		}
		if result.RId == "" || result.Status == "" {
			t.Errorf("purge destroyed the engagement's shape: rid=%q status=%q", result.RId, result.Status)
		}
	}
}

// TestPurgeRequiresOwnership mirrors every other campaign endpoint: another
// user's campaign resolves as not found, and the ownership check runs before
// anything is written.
func TestPurgeRequiresOwnership(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	unauthorizedUser := createUnpriviledgedUser(t, models.RoleUser)

	request := httptest.NewRequest(http.MethodPost, "/api/campaigns/1/purge?confirm=PURGE", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", unauthorizedUser.ApiKey))
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}

	campaign, err := models.GetCampaignResults(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range campaign.Results {
		if result.Email == "purged@invalid" {
			t.Fatal("another user's campaign was purged")
		}
	}
}
