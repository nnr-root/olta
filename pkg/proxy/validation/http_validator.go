package validation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxMetadataResponse = 1 << 20

// Validator checks one captured session event.
type Validator interface {
	Validate(context.Context, Event) Result
}

// HTTPValidator replays only the captured cookies applicable to the target
// host. It never serializes tokens into the returned Result.
type HTTPValidator struct {
	client *http.Client
	now    func() time.Time
}

// NewHTTPValidator creates a validator. Redirects are intentionally not
// followed so authentication redirects can be classified.
func NewHTTPValidator(client *http.Client) *HTTPValidator {
	if client == nil {
		client = &http.Client{}
	} else {
		copyClient := *client
		client = &copyClient
	}
	if client.CheckRedirect == nil {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &HTTPValidator{client: client, now: time.Now}
}

// Validate performs a bounded GET request and applies conservative status
// classification. Redirects to login/auth pages and 401/403 responses are
// invalid; successful 2xx responses are valid; ambiguous responses are unknown.
func (validator *HTTPValidator) Validate(ctx context.Context, event Event) Result {
	result := baseResult(event, validator.now())
	target, err := url.Parse(event.TargetURL)
	if err != nil || !target.IsAbs() || (target.Scheme != "http" && target.Scheme != "https") {
		result.Status = StatusError
		result.Detail = "invalid validation target"
		return result
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		result.Status = StatusError
		result.Detail = "failed to build validation request"
		return result
	}
	request.Header.Set("Accept", "application/json,text/html;q=0.9,*/*;q=0.1")
	request.Header.Set("User-Agent", "Olta-Session-Validator/1.0")
	matchingCookies := 0
	for domain, cookies := range event.Cookies {
		if !domainMatches(target.Hostname(), domain) {
			continue
		}
		for name, token := range cookies {
			if token == nil || token.Value == "" {
				continue
			}
			cookieName := token.Name
			if cookieName == "" {
				cookieName = name
			}
			path := token.Path
			if path == "" {
				path = "/"
			}
			request.AddCookie(&http.Cookie{
				Name:     cookieName,
				Value:    token.Value,
				Path:     path,
				Secure:   target.Scheme == "https",
				HttpOnly: token.HttpOnly,
			})
			matchingCookies++
		}
	}
	if matchingCookies == 0 {
		result.Detail = "no cookies apply to validation target"
		return result
	}

	response, err := validator.client.Do(request)
	if err != nil {
		result.Status = StatusError
		result.Detail = "validation request failed"
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	extractResponseMetadata(response, &result.Identity)

	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		result.Status = StatusValid
		result.Detail = "target accepted the captured session"
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		result.Status = StatusInvalid
		result.Detail = "target rejected the captured session"
	case response.StatusCode >= 300 && response.StatusCode < 400:
		location := strings.ToLower(response.Header.Get("Location"))
		if strings.Contains(location, "login") || strings.Contains(location, "signin") || strings.Contains(location, "auth") {
			result.Status = StatusInvalid
			result.Detail = "target redirected to authentication"
		} else {
			result.Detail = "target returned an ambiguous redirect"
		}
	case response.StatusCode >= 500:
		result.Status = StatusError
		result.Detail = "target was unavailable during validation"
	default:
		result.Detail = fmt.Sprintf("target returned HTTP %d", response.StatusCode)
	}
	return result
}

func domainMatches(host, rawDomain string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	domain := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rawDomain)), "."), ".")
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func extractResponseMetadata(response *http.Response, identity *Identity) {
	if identity == nil || !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "json") {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxMetadataResponse))
		return
	}
	var payload map[string]interface{}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxMetadataResponse))
	if err := decoder.Decode(&payload); err != nil {
		return
	}
	if identity.Username == "" {
		identity.Username = jsonString(payload, "username", "userPrincipalName", "email")
	}
	if identity.TenantID == "" {
		identity.TenantID = jsonString(payload, "tenant_id", "tenantId", "tenant")
	}
	if identity.Organization == "" {
		identity.Organization = jsonString(payload, "organization", "organization_id", "org_id", "org")
	}
}

func jsonString(payload map[string]interface{}, keys ...string) string {
	for _, wanted := range keys {
		for key, value := range payload {
			if !strings.EqualFold(key, wanted) {
				continue
			}
			if text, ok := value.(string); ok {
				return strings.TrimSpace(text)
			}
		}
	}
	return ""
}
