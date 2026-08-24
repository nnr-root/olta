package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/dialer"
	"github.com/s4l1hs/olta/pkg/campaign/models"
)

func makeImportRequest(t *testing.T, ctx *testContext, allowedHosts []string, url string) *httptest.ResponseRecorder {
	t.Helper()
	orig := dialer.DefaultDialer.AllowedHosts()
	if err := dialer.SetAllowedHosts(allowedHosts); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dialer.SetAllowedHosts(orig); err != nil {
			t.Error(err)
		}
	}()
	req := httptest.NewRequest(http.MethodPost, "/api/import/site",
		bytes.NewBuffer([]byte(fmt.Sprintf(`
			{
				"url" : "%s"
			}
		`, url))))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	ctx.apiServer.ImportSite(response, req)
	return response
}

func TestDefaultDeniedImport(t *testing.T) {
	ctx := setupTest(t)
	metadataURL := "http://169.254.169.254/latest/meta-data/"
	response := makeImportRequest(t, ctx, []string{}, metadataURL)
	expectedCode := http.StatusBadRequest
	if response.Code != expectedCode {
		t.Fatalf("incorrect status code received. expected %d got %d", expectedCode, response.Code)
	}
	got := &models.Response{}
	err := json.NewDecoder(response.Body).Decode(got)
	if err != nil {
		t.Fatalf("error decoding body: %v", err)
	}
	if !strings.Contains(got.Message, "upstream connection denied") {
		t.Fatalf("incorrect response error provided: %s", got.Message)
	}
}

func TestDefaultAllowedImport(t *testing.T) {
	ctx := setupTest(t)
	h := "<html><head></head><body><img src=\"/test.png\"/></body></html>"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, h)
	}))
	defer ts.Close()
	response := makeImportRequest(t, ctx, []string{}, ts.URL)
	expectedCode := http.StatusOK
	if response.Code != expectedCode {
		t.Fatalf("incorrect status code received. expected %d got %d", expectedCode, response.Code)
	}
}

func TestCustomDeniedImport(t *testing.T) {
	ctx := setupTest(t)
	h := "<html><head></head><body><img src=\"/test.png\"/></body></html>"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, h)
	}))
	defer ts.Close()
	response := makeImportRequest(t, ctx, []string{"192.168.1.1"}, ts.URL)
	expectedCode := http.StatusBadRequest
	if response.Code != expectedCode {
		t.Fatalf("incorrect status code received. expected %d got %d", expectedCode, response.Code)
	}
	got := &models.Response{}
	err := json.NewDecoder(response.Body).Decode(got)
	if err != nil {
		t.Fatalf("error decoding body: %v", err)
	}
	if !strings.Contains(got.Message, "upstream connection denied") {
		t.Fatalf("incorrect response error provided: %s", got.Message)
	}
}
