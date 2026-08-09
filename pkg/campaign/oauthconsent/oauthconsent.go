// Package oauthconsent renders OAuth 2.0 and OpenID Connect consent UI
// components for authorized campaign simulations.
package oauthconsent

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// AssetBasePath is the URL prefix used by rendered consent components.
const AssetBasePath = "/static/components/oauthconsent/"

var (
	// ErrApplicationNameRequired indicates missing application branding.
	ErrApplicationNameRequired = errors.New("OAuth application name is required")
	// ErrRedirectURIInvalid indicates a non-absolute or non-HTTP redirect URI.
	ErrRedirectURIInvalid = errors.New("OAuth redirect URI must be an absolute HTTP or HTTPS URL")
)

//go:embed assets/*.css assets/*.js templates/*.html
var componentFiles embed.FS

// Scope describes one permission presented by the consent prompt.
type Scope struct {
	Name        string
	Description string
}

// Metadata contains the customizable OAuth client information displayed by a
// consent component.
type Metadata struct {
	ApplicationName string
	PublisherName   string
	RequestedScopes []Scope
	RedirectURI     string
	LogoURL         string
	AssetsBaseURL   string
}

type consentView struct {
	Metadata
	ApplicationInitial string
	RedirectHost       string
}

var knownScopes = map[string]Scope{
	"openid":            {Name: "Sign you in", Description: "Allow this application to identify you."},
	"profile":           {Name: "Read your basic profile", Description: "View your name, photo, and basic account information."},
	"email":             {Name: "View your email address", Description: "View the primary email address on your account."},
	"offline_access":    {Name: "Maintain access to data", Description: "Access permitted data when you are not actively using the application."},
	"offline access":    {Name: "Maintain access to data", Description: "Access permitted data when you are not actively using the application."},
	"user.read":         {Name: "Read user profile", Description: "View your full user profile."},
	"read user profile": {Name: "Read user profile", Description: "View your full user profile."},
}

// NewMetadata builds consent metadata from common OAuth configuration values.
func NewMetadata(applicationName, publisherName string, scopes []string, redirectURI string) Metadata {
	return Metadata{
		ApplicationName: applicationName,
		PublisherName:   publisherName,
		RequestedScopes: Scopes(scopes),
		RedirectURI:     redirectURI,
		AssetsBaseURL:   AssetBasePath,
	}
}

// ParseScopeList accepts a comma- or semicolon-separated scope list for use in
// campaign template helpers.
func ParseScopeList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' })
}

// Scopes converts OAuth scope identifiers or friendly permission names into
// presentation-ready scope entries.
func Scopes(values []string) []Scope {
	scopes := make([]Scope, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if known, ok := knownScopes[strings.ToLower(value)]; ok {
			scopes = append(scopes, known)
			continue
		}
		scopes = append(scopes, Scope{
			Name:        value,
			Description: "Allow this application to use the requested permission.",
		})
	}
	return scopes
}

// Render creates a consent prompt from the supplied metadata. Dynamic values
// are escaped by html/template before the returned component is marked safe.
func Render(metadata Metadata) (template.HTML, error) {
	if strings.TrimSpace(metadata.ApplicationName) == "" {
		return "", ErrApplicationNameRequired
	}
	redirect, err := validateRedirectURI(metadata.RedirectURI)
	if err != nil {
		return "", err
	}
	if metadata.AssetsBaseURL == "" {
		metadata.AssetsBaseURL = AssetBasePath
	}
	if !strings.HasSuffix(metadata.AssetsBaseURL, "/") {
		metadata.AssetsBaseURL += "/"
	}
	initial, _ := utf8.DecodeRuneInString(strings.TrimSpace(metadata.ApplicationName))
	view := consentView{
		Metadata:           metadata,
		ApplicationInitial: strings.ToUpper(string(initial)),
		RedirectHost:       redirect.Hostname(),
	}

	tmpl, err := template.ParseFS(componentFiles, "templates/consent.html")
	if err != nil {
		return "", fmt.Errorf("parse OAuth consent template: %w", err)
	}
	var output strings.Builder
	if err := tmpl.ExecuteTemplate(&output, "consent.html", view); err != nil {
		return "", fmt.Errorf("render OAuth consent template: %w", err)
	}
	return template.HTML(output.String()), nil
}

// CSS returns the embedded responsive consent component styles.
func CSS() ([]byte, error) {
	contents, err := componentFiles.ReadFile("assets/oauthconsent.css")
	if err != nil {
		return nil, fmt.Errorf("read embedded OAuth consent CSS: %w", err)
	}
	return contents, nil
}

// JavaScript returns the embedded accept/cancel event behavior.
func JavaScript() ([]byte, error) {
	contents, err := componentFiles.ReadFile("assets/oauthconsent.js")
	if err != nil {
		return nil, fmt.Errorf("read embedded OAuth consent JavaScript: %w", err)
	}
	return contents, nil
}

// Assets exposes the immutable embedded asset filesystem.
func Assets() (fs.FS, error) {
	assets, err := fs.Sub(componentFiles, "assets")
	if err != nil {
		return nil, fmt.Errorf("open embedded OAuth consent assets: %w", err)
	}
	return assets, nil
}

// Handler serves the embedded assets without a runtime filesystem dependency.
func Handler() http.Handler {
	assets, err := Assets()
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "OAuth consent assets unavailable", http.StatusInternalServerError)
		})
	}
	return http.FileServer(http.FS(assets))
}

func validateRedirectURI(rawURI string) (*url.URL, error) {
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, ErrRedirectURIInvalid
	}
	return parsed, nil
}
