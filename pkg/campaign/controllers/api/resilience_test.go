package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// TestNavigatorLayerAggregatesSharedTechniques is the regression test for
// B4: Delivery, Open, and Lure all map to T1566.002, and an earlier version
// of ResilienceNavigator emitted one entry per (stage, technique) pair.
// Navigator applies techniques[] entries sequentially, so only the
// last-processed stage survived on screen -- Delivery and Open were present
// in the JSON but invisible after Navigator loaded it. Every distinct
// techniqueID must now appear exactly once, and the shared T1566.002 entry
// must name all three contributing stages so none of them is hidden.
func TestNavigatorLayerAggregatesSharedTechniques(t *testing.T) {
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
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Comment     string `json:"comment"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}

	seen := map[string]string{}
	for _, technique := range layer.Techniques {
		if previous, duplicate := seen[technique.TechniqueID]; duplicate {
			t.Fatalf("techniqueID %q appears more than once: comments %q and %q", technique.TechniqueID, previous, technique.Comment)
		}
		seen[technique.TechniqueID] = technique.Comment
	}

	comment, ok := seen["T1566.002"]
	if !ok {
		t.Fatal("layer has no T1566.002 entry")
	}
	for _, stage := range []string{"delivery", "open", "lure"} {
		if !strings.Contains(comment, stage) {
			t.Fatalf("T1566.002 comment = %q, want it to mention stage %q", comment, stage)
		}
	}
}

// TestCampaignHostsParsesTheLureURL covers the translation that makes host
// scoping work. A campaign's URL is operator-entered, so the shapes it
// actually arrives in -- with or without a scheme, port, path or trailing
// dot -- all have to reduce to the same hostname the proxy stamped on its
// events, or the scoping silently matches nothing.
func TestCampaignHostsParsesTheLureURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want []string
	}{
		{"https url", "https://login.example.com/account", []string{"login.example.com"}},
		{"http url with port", "http://login.example.com:8080/", []string{"login.example.com"}},
		{"mixed case", "https://Login.Example.COM/", []string{"login.example.com"}},
		{"no scheme", "login.example.com/account", []string{"login.example.com"}},
		{"bare hostname", "login.example.com", []string{"login.example.com"}},
		{"trailing dot", "https://login.example.com./", []string{"login.example.com"}},
		{"surrounding space", "  https://login.example.com/  ", []string{"login.example.com"}},
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := campaignHosts(models.Campaign{URL: testCase.url})
			if len(got) != len(testCase.want) {
				t.Fatalf("campaignHosts(%q) = %v, want %v", testCase.url, got, testCase.want)
			}
			for i := range got {
				if got[i] != testCase.want[i] {
					t.Errorf("campaignHosts(%q)[%d] = %q, want %q", testCase.url, i, got[i], testCase.want[i])
				}
			}
		})
	}
}

// TestCampaignHostsNeverReturnsAnEmptyEntry is the hazard test. An
// empty-string entry would reach the report's "host IN (?) OR host = ”"
// clause and match every event whose host was never recorded, quietly
// undoing the scoping for every campaign with an unusable URL.
func TestCampaignHostsNeverReturnsAnEmptyEntry(t *testing.T) {
	for _, raw := range []string{"", "   ", "://", "http://", "/just/a/path"} {
		for _, host := range campaignHosts(models.Campaign{URL: raw}) {
			if host == "" {
				t.Errorf("campaignHosts(%q) returned an empty hostname entry", raw)
			}
		}
	}
}

// TestCampaignScopeUsesNowForAnInFlightCampaign pins the upper bound: a
// campaign that has not completed has a zero CompletedDate, and using it
// unconditionally would put the window's end in year 1 and exclude every
// unattributed event ever recorded.
func TestCampaignScopeUsesNowForAnInFlightCampaign(t *testing.T) {
	launch := time.Now().Add(-time.Hour)
	scope := campaignScope(models.Campaign{LaunchDate: launch, URL: "https://login.example.com/"})

	if !scope.Start.Equal(launch) {
		t.Errorf("Start = %v, want the launch date %v", scope.Start, launch)
	}
	if scope.End.Before(launch) {
		t.Errorf("End = %v, want a bound after the launch date for an in-flight campaign", scope.End)
	}
	if len(scope.Hosts) != 1 || scope.Hosts[0] != "login.example.com" {
		t.Errorf("Hosts = %v, want the campaign's own hostname", scope.Hosts)
	}
}

// TestCampaignScopeUsesCompletedDateWhenFinished is the complement.
func TestCampaignScopeUsesCompletedDateWhenFinished(t *testing.T) {
	launch := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	completed := launch.Add(2 * time.Hour)
	scope := campaignScope(models.Campaign{LaunchDate: launch, CompletedDate: completed})

	if !scope.End.Equal(completed) {
		t.Errorf("End = %v, want the completed date %v", scope.End, completed)
	}
	if scope.Hosts != nil {
		t.Errorf("Hosts = %v, want nil for a campaign with no URL", scope.Hosts)
	}
}
