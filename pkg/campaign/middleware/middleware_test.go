package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/s4l1hs/olta/pkg/campaign/config"
	ctx "github.com/s4l1hs/olta/pkg/campaign/context"
	"github.com/s4l1hs/olta/pkg/campaign/models"
)

var successHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("success"))
})

type testContext struct {
	apiKey string
}

func setupTest(t *testing.T) *testContext {
	conf := &config.Config{
		DBName: "sqlite3",
		DBPath: ":memory:",
	}
	err := models.Setup(conf)
	if err != nil {
		t.Fatalf("Failed creating database: %v", err)
	}
	// Get the API key to use for these tests
	u, err := models.GetUser(1)
	if err != nil {
		t.Fatalf("error getting user: %v", err)
	}
	ctx := &testContext{}
	ctx.apiKey = u.ApiKey
	return ctx
}

// MiddlewarePermissionTest maps an expected HTTP Method to an expected HTTP
// status code
type MiddlewarePermissionTest map[string]int

// TestEnforceViewOnly ensures that only users with the ModifyObjects
// permission have the ability to send non-GET requests.
func TestEnforceViewOnly(t *testing.T) {
	setupTest(t)
	permissionTests := map[string]MiddlewarePermissionTest{
		models.RoleAdmin: MiddlewarePermissionTest{
			http.MethodGet:     http.StatusOK,
			http.MethodHead:    http.StatusOK,
			http.MethodOptions: http.StatusOK,
			http.MethodPost:    http.StatusOK,
			http.MethodPut:     http.StatusOK,
			http.MethodDelete:  http.StatusOK,
		},
		models.RoleUser: MiddlewarePermissionTest{
			http.MethodGet:     http.StatusOK,
			http.MethodHead:    http.StatusOK,
			http.MethodOptions: http.StatusOK,
			http.MethodPost:    http.StatusOK,
			http.MethodPut:     http.StatusOK,
			http.MethodDelete:  http.StatusOK,
		},
	}
	for r, checks := range permissionTests {
		role, err := models.GetRoleBySlug(r)
		if err != nil {
			t.Fatalf("error getting role by slug: %v", err)
		}

		for method, expected := range checks {
			req := httptest.NewRequest(method, "/", nil)
			response := httptest.NewRecorder()

			req = ctx.Set(req, "user", models.User{
				Role:   role,
				RoleID: role.ID,
			})

			EnforceViewOnly(successHandler).ServeHTTP(response, req)
			got := response.Code
			if got != expected {
				t.Fatalf("incorrect status code received. expected %d got %d", expected, got)
			}
		}
	}
}

func TestRequirePermission(t *testing.T) {
	setupTest(t)
	middleware := RequirePermission(models.PermissionModifySystem)
	handler := middleware(successHandler)

	permissionTests := map[string]int{
		models.RoleUser:  http.StatusForbidden,
		models.RoleAdmin: http.StatusOK,
	}

	for role, expected := range permissionTests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		response := httptest.NewRecorder()
		// Test that with the requested permission, the request succeeds
		role, err := models.GetRoleBySlug(role)
		if err != nil {
			t.Fatalf("error getting role by slug: %v", err)
		}
		req = ctx.Set(req, "user", models.User{
			Role:   role,
			RoleID: role.ID,
		})
		handler.ServeHTTP(response, req)
		got := response.Code
		if got != expected {
			t.Fatalf("incorrect status code received. expected %d got %d", expected, got)
		}
	}
}

func TestRequireAPIKey(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	// Test that making a request without an API key is denied
	RequireAPIKey(successHandler).ServeHTTP(response, req)
	expected := http.StatusUnauthorized
	got := response.Code
	if got != expected {
		t.Fatalf("incorrect status code received. expected %d got %d", expected, got)
	}
}

func TestCORSHeaders(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://admin.example")
	response := httptest.NewRecorder()
	RequireAPIKeyWithOrigins([]string{"https://admin.example"})(successHandler).ServeHTTP(response, req)
	expected := "POST, GET, OPTIONS, PUT, DELETE"
	got := response.Result().Header.Get("Access-Control-Allow-Methods")
	if got != expected {
		t.Fatalf("incorrect cors options received. expected %s got %s", expected, got)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "https://admin.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestCORSRejectsUnlistedOrigin(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	RequireAPIKeyWithOrigins([]string{"https://admin.example"})(successHandler).ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestInvalidAPIKey(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	query := req.URL.Query()
	query.Set("api_key", "bogus-api-key")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	RequireAPIKey(successHandler).ServeHTTP(response, req)
	expected := http.StatusUnauthorized
	got := response.Code
	if got != expected {
		t.Fatalf("incorrect status code received. expected %d got %d", expected, got)
	}
}

func TestBearerToken(t *testing.T) {
	testCtx := setupTest(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testCtx.apiKey))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	RequireAPIKey(successHandler).ServeHTTP(response, req)
	expected := http.StatusOK
	got := response.Code
	if got != expected {
		t.Fatalf("incorrect status code received. expected %d got %d", expected, got)
	}
}

func TestQueryAPIKeyIsRejected(t *testing.T) {
	testCtx := setupTest(t)
	req := httptest.NewRequest(http.MethodGet, "/?api_key="+testCtx.apiKey, nil)
	response := httptest.NewRecorder()
	RequireAPIKey(successHandler).ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestTrustedProxyHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.RemoteAddr))
	})

	trustedRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	trustedRequest.RemoteAddr = "127.0.0.1:1234"
	trustedRequest.Header.Set("X-Forwarded-For", "203.0.113.10")
	trustedResponse := httptest.NewRecorder()
	TrustedProxyHeaders([]string{"127.0.0.1"}, handler).ServeHTTP(trustedResponse, trustedRequest)
	if trustedResponse.Body.String() != "203.0.113.10" {
		t.Fatalf("trusted proxy client = %q", trustedResponse.Body.String())
	}

	untrustedRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	untrustedRequest.RemoteAddr = "192.0.2.10:1234"
	untrustedRequest.Header.Set("X-Forwarded-For", "203.0.113.10")
	untrustedResponse := httptest.NewRecorder()
	TrustedProxyHeaders([]string{"127.0.0.1"}, handler).ServeHTTP(untrustedResponse, untrustedRequest)
	if untrustedResponse.Body.String() != "192.0.2.10:1234" {
		t.Fatalf("untrusted proxy client = %q", untrustedResponse.Body.String())
	}
}

func TestPasswordResetRequired(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = ctx.Set(req, "user", models.User{
		PasswordChangeRequired: true,
	})
	response := httptest.NewRecorder()
	RequireLogin(successHandler).ServeHTTP(response, req)
	gotStatus := response.Code
	expectedStatus := http.StatusTemporaryRedirect
	if gotStatus != expectedStatus {
		t.Fatalf("incorrect status code received. expected %d got %d", expectedStatus, gotStatus)
	}
	expectedLocation := "/reset_password?next=%2F"
	gotLocation := response.Header().Get("Location")
	if gotLocation != expectedLocation {
		t.Fatalf("incorrect location header received. expected %s got %s", expectedLocation, gotLocation)
	}
}

func TestApplySecurityHeaders(t *testing.T) {
	expected := map[string]string{
		"Content-Security-Policy": "object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	ApplySecurityHeaders(successHandler).ServeHTTP(response, req)
	for header, value := range expected {
		got := response.Header().Get(header)
		if got != value {
			t.Fatalf("incorrect security header received for %s: expected %s got %s", header, value, got)
		}
	}
}
