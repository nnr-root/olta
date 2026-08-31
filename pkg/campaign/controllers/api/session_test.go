package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/auth"
	"github.com/s4l1hs/olta/pkg/campaign/models"
)

// firstResultRID returns the RID of the first result on campaign id,
// owned by uid, so tests can exercise SessionTag against a real row.
func firstResultRID(t *testing.T, id, uid int64) string {
	t.Helper()
	cr, err := models.GetCampaignResults(id, uid)
	if err != nil {
		t.Fatalf("error getting campaign results: %v", err)
	}
	if len(cr.Results) == 0 {
		t.Fatal("campaign has no results to tag")
	}
	return cr.Results[0].RId
}

func buildSessionTagRequest(t *testing.T, campaignID int64, rid string, body map[string]interface{}) *http.Request {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("error marshaling request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut,
		fmt.Sprintf("/api/campaigns/%d/results/%s/session", campaignID, rid),
		bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestSessionTagRequiresAuth(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)
	rid := firstResultRID(t, 1, 1)

	req := buildSessionTagRequest(t, 1, rid, map[string]interface{}{"tag": "hot-lead"})
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestSessionTagSetsFields(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)
	rid := firstResultRID(t, 1, 1)

	req := buildSessionTagRequest(t, 1, rid, map[string]interface{}{
		"tag":    "hot-lead",
		"notes":  "Escalated to blue team",
		"status": models.SessionStatusTriaged,
	})
	req.Header.Set("Authorization", "Bearer "+ctx.apiKey)
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var result models.Result
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Tag != "hot-lead" || result.Notes != "Escalated to blue team" || result.SessionStatus != models.SessionStatusTriaged {
		t.Fatalf("unexpected result payload: %+v", result)
	}

	reloaded, err := models.GetResult(rid)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Tag != "hot-lead" || reloaded.Notes != "Escalated to blue team" || reloaded.SessionStatus != models.SessionStatusTriaged {
		t.Fatalf("session metadata did not persist: %+v", reloaded)
	}
}

func TestSessionTagRejectsInvalidStatus(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)
	rid := firstResultRID(t, 1, 1)

	req := buildSessionTagRequest(t, 1, rid, map[string]interface{}{"status": "not-a-real-status"})
	req.Header.Set("Authorization", "Bearer "+ctx.apiKey)
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

// TestSessionTagRejectsUnownedCampaign is the IDOR check: an authenticated
// operator must not be able to tag a session in a campaign they do not
// own by guessing its ID, even with a valid, correctly-owned API key.
func TestSessionTagRejectsUnownedCampaign(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)
	rid := firstResultRID(t, 1, 1)

	role, err := models.GetRoleBySlug(models.RoleUser)
	if err != nil {
		t.Fatalf("error getting standard role: %v", err)
	}
	other := models.User{Username: "otherop", Hash: ctx.admin.Hash, RoleID: role.ID, ApiKey: auth.GenerateSecureKey(auth.APIKeyLength)}
	if err := models.PutUser(&other); err != nil {
		t.Fatalf("error creating second operator: %v", err)
	}

	req := buildSessionTagRequest(t, 1, rid, map[string]interface{}{"tag": "should-not-apply"})
	req.Header.Set("Authorization", "Bearer "+other.ApiKey)
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}

	reloaded, err := models.GetResult(rid)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Tag != "" {
		t.Fatalf("tag = %q, want untouched by an unowned request", reloaded.Tag)
	}
}

func TestSessionTagPartialUpdate(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)
	rid := firstResultRID(t, 1, 1)

	req := buildSessionTagRequest(t, 1, rid, map[string]interface{}{"tag": "first", "notes": "keep-me", "status": models.SessionStatusTriaged})
	req.Header.Set("Authorization", "Bearer "+ctx.apiKey)
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	req = buildSessionTagRequest(t, 1, rid, map[string]interface{}{"tag": "second"})
	req.Header.Set("Authorization", "Bearer "+ctx.apiKey)
	recorder = httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	reloaded, err := models.GetResult(rid)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Tag != "second" {
		t.Fatalf("tag = %q, want %q", reloaded.Tag, "second")
	}
	if reloaded.Notes != "keep-me" {
		t.Fatalf("notes = %q, want untouched %q", reloaded.Notes, "keep-me")
	}
	if reloaded.SessionStatus != models.SessionStatusTriaged {
		t.Fatalf("session_status = %q, want untouched %q", reloaded.SessionStatus, models.SessionStatusTriaged)
	}
}
