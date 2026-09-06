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

func TestDetectionsEndpointRequiresAuth(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	for _, path := range []string{"/api/campaigns/1/detections", "/api/campaigns/1/detections/sigma"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		recorder := httptest.NewRecorder()
		ctx.apiServer.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, recorder.Code)
		}
	}
}

func TestDetectionsEndpointReturnsPack(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	request := httptest.NewRequest(http.MethodGet, "/api/campaigns/1/detections", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ctx.apiKey))
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var payload struct {
		CampaignID int64 `json:"campaign_id"`
		Indicators struct {
			Hostnames []string `json:"hostnames"`
			Subjects  []string `json:"subjects"`
		} `json:"indicators"`
		Rules []struct {
			ID    string `json:"id"`
			Sigma string `json:"sigma"`
		} `json:"rules"`
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CampaignID != 1 {
		t.Fatalf("campaign_id = %d, want 1", payload.CampaignID)
	}
	if payload.Scope == "" {
		t.Error("scope is empty; the pack must state what it is and is not")
	}
	for _, rule := range payload.Rules {
		if rule.ID == "" || rule.Sigma == "" {
			t.Errorf("rule is incomplete: %+v", rule)
		}
	}
}

// TestDetectionsSigmaIsADownload covers the export path: an operator drops
// this straight into a rule repository, so it has to arrive as a file rather
// than render in the browser.
func TestDetectionsSigmaIsADownload(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	request := httptest.NewRequest(http.MethodGet, "/api/campaigns/1/detections/sigma", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ctx.apiKey))
	recorder := httptest.NewRecorder()
	ctx.apiServer.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/yaml") {
		t.Errorf("Content-Type = %q, want application/yaml", got)
	}
	disposition := recorder.Header().Get("Content-Disposition")
	if !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, "olta-campaign-1-sigma.yml") {
		t.Errorf("Content-Disposition = %q", disposition)
	}
	if !strings.HasPrefix(recorder.Body.String(), "# Olta detection pack") {
		t.Errorf("body is not a Sigma bundle:\n%s", recorder.Body.String())
	}
}

// TestDetectionsEndpointRequiresOwnership mirrors the resilience endpoint:
// another user's campaign resolves as not found, never as the caller's data.
func TestDetectionsEndpointRequiresOwnership(t *testing.T) {
	ctx := setupTest(t)
	createTestData(t)

	unauthorizedUser := createUnpriviledgedUser(t, models.RoleUser)

	for _, path := range []string{"/api/campaigns/1/detections", "/api/campaigns/1/detections/sigma"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", unauthorizedUser.ApiKey))
		recorder := httptest.NewRecorder()
		ctx.apiServer.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404 for another user's campaign", path, recorder.Code)
		}
	}
}

// TestExtractAddress covers the translation a mail rule depends on: a log's
// sender field carries the bare address, so a rule matching a full
// "Display Name <a@b>" header value would never fire.
func TestExtractAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		{"payroll@acme-corp.example", "payroll@acme-corp.example"},
		{"Payroll Team <payroll@acme-corp.example>", "payroll@acme-corp.example"},
		{"  Payroll <payroll@acme-corp.example>  ", "payroll@acme-corp.example"},
		{`"Payroll, Team" <payroll@acme-corp.example>`, "payroll@acme-corp.example"},
		{"", ""},
		{"Payroll Team", ""},
		{"<>", ""},
	}
	for _, testCase := range cases {
		if got := extractAddress(testCase.in); got != testCase.want {
			t.Errorf("extractAddress(%q) = %q, want %q", testCase.in, got, testCase.want)
		}
	}
}

// TestCampaignSubjectsIncludeEveryVariant is the A/B case: a mail rule that
// matched only the primary subject would under-report delivery for every
// recipient who received a different variant.
func TestCampaignSubjectsIncludeEveryVariant(t *testing.T) {
	campaign := models.Campaign{
		Template: models.Template{Subject: "Payroll update required"},
		TemplateVariants: []models.CampaignTemplateVariant{
			{Template: models.Template{Subject: "Action needed: payroll"}},
			{Template: models.Template{Subject: "   "}},
		},
	}

	subjects := campaignSubjects(campaign)
	if len(subjects) != 2 {
		t.Fatalf("subjects = %v, want the two non-empty ones", subjects)
	}
	for _, want := range []string{"Payroll update required", "Action needed: payroll"} {
		found := false
		for _, subject := range subjects {
			if subject == want {
				found = true
			}
		}
		if !found {
			t.Errorf("subject %q missing from %v", want, subjects)
		}
	}
}

func TestCampaignSendersIncludeProfileAndTemplate(t *testing.T) {
	campaign := models.Campaign{
		SMTP:     models.SMTP{FromAddress: "Sender <no-reply@acme-corp.example>"},
		Template: models.Template{EnvelopeSender: "payroll@acme-corp.example"},
	}

	senders := campaignSenders(campaign)
	if len(senders) != 2 {
		t.Fatalf("senders = %v, want both the profile and the envelope sender", senders)
	}
	if senders[0] != "no-reply@acme-corp.example" {
		t.Errorf("senders[0] = %q, want the bare address", senders[0])
	}
}
