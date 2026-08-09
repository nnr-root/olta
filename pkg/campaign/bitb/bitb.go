// Package bitb renders browser-in-the-browser components for authorized
// campaign simulations.
package bitb

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
)

// AssetBasePath is the URL prefix used by rendered BITB components.
const AssetBasePath = "/static/components/bitb/"

// Theme identifies the simulated operating-system window chrome.
type Theme string

const (
	// ThemeAuto selects a theme in the browser from the visitor's platform.
	ThemeAuto Theme = "auto"
	// ThemeWindows11 renders Windows 11-style window chrome.
	ThemeWindows11 Theme = "windows11"
	// ThemeMacOS renders macOS-style window chrome.
	ThemeMacOS Theme = "macos"
	// ThemeLinux renders Ubuntu/GNOME-style window chrome.
	ThemeLinux          Theme = "linux"
	ThemeWindows11Light Theme = "win11-light"
	ThemeWindows11Dark  Theme = "win11-dark"
	ThemeMacOSLight     Theme = "macos-light"
	ThemeMacOSDark      Theme = "macos-dark"
	ThemeLinuxGNOME     Theme = "linux-gnome"
)

var (
	// ErrUnsupportedTheme indicates that a frame requested an unknown theme.
	ErrUnsupportedTheme = errors.New("unsupported BITB theme")
	// ErrInvalidURL indicates that the simulated address is not an absolute
	// HTTP or HTTPS URL.
	ErrInvalidURL = errors.New("BITB address must be an absolute HTTP or HTTPS URL")
)

//go:embed assets/*.css assets/*.js templates/*.html
var componentFiles embed.FS

// Frame configures a simulated browser pop-up.
type Frame struct {
	URL           string
	Title         string
	Theme         Theme
	Content       template.HTML
	AssetsBaseURL string
}

type frameView struct {
	Frame
	DisplayURL string
	Secure     bool
	SSLStatus  string
}

// NewFrame creates a frame with responsive, OS-aware defaults.
func NewFrame(rawURL string) Frame {
	return Frame{
		URL:           rawURL,
		Theme:         ThemeAuto,
		AssetsBaseURL: AssetBasePath,
	}
}

// Render creates an automatically themed BITB frame.
func Render(rawURL string) (template.HTML, error) {
	return RenderFrame(NewFrame(rawURL))
}

// RenderTheme creates a BITB frame with a specific OS theme.
func RenderTheme(rawURL string, theme Theme) (template.HTML, error) {
	frame := NewFrame(rawURL)
	frame.Theme = theme
	return RenderFrame(frame)
}

// RenderFrame renders a fully configured BITB frame. Values are escaped by
// html/template; Content is the only intentionally trusted HTML field.
func RenderFrame(frame Frame) (template.HTML, error) {
	parsedURL, err := validateURL(frame.URL)
	if err != nil {
		return "", err
	}
	if err := validateTheme(frame.Theme); err != nil {
		return "", err
	}
	if frame.AssetsBaseURL == "" {
		frame.AssetsBaseURL = AssetBasePath
	}
	if !strings.HasSuffix(frame.AssetsBaseURL, "/") {
		frame.AssetsBaseURL += "/"
	}
	if frame.Title == "" {
		frame.Title = parsedURL.Hostname()
	}

	view := frameView{
		Frame:      frame,
		DisplayURL: parsedURL.String(),
		Secure:     parsedURL.Scheme == "https",
		SSLStatus:  "Connection is not secure",
	}
	if view.Secure {
		view.SSLStatus = "Connection is secure"
	}

	tmpl, err := template.ParseFS(componentFiles, "templates/frame.html")
	if err != nil {
		return "", fmt.Errorf("parse BITB template: %w", err)
	}
	var output strings.Builder
	if err := tmpl.ExecuteTemplate(&output, "frame.html", view); err != nil {
		return "", fmt.Errorf("render BITB template: %w", err)
	}
	return template.HTML(output.String()), nil
}

// CSS returns the embedded styles required for the selected theme. Auto
// includes all OS themes so the browser-side detector can select one.
func CSS(theme Theme) ([]byte, error) {
	if err := validateTheme(theme); err != nil {
		return nil, err
	}
	files := []string{"assets/bitb.css"}
	switch theme {
	case ThemeAuto:
		files = append(files, "assets/windows11.css", "assets/macos.css", "assets/linux.css")
	case ThemeWindows11, ThemeWindows11Light, ThemeWindows11Dark:
		files = append(files, "assets/windows11.css")
	case ThemeMacOS, ThemeMacOSLight, ThemeMacOSDark:
		files = append(files, "assets/macos.css")
	case ThemeLinux, ThemeLinuxGNOME:
		files = append(files, "assets/linux.css")
	}
	var output strings.Builder
	for _, name := range files {
		contents, err := componentFiles.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read embedded BITB asset %q: %w", name, err)
		}
		output.Write(contents)
		output.WriteByte('\n')
	}
	return []byte(output.String()), nil
}

// JavaScript returns the embedded drag, close, and OS-detection behavior.
func JavaScript() ([]byte, error) {
	contents, err := componentFiles.ReadFile("assets/bitb.js")
	if err != nil {
		return nil, fmt.Errorf("read embedded BITB JavaScript: %w", err)
	}
	return contents, nil
}

// Assets exposes the immutable embedded asset filesystem.
func Assets() (fs.FS, error) {
	assets, err := fs.Sub(componentFiles, "assets")
	if err != nil {
		return nil, fmt.Errorf("open embedded BITB assets: %w", err)
	}
	return assets, nil
}

// Handler serves the embedded assets without a runtime filesystem dependency.
func Handler() http.Handler {
	assets, err := Assets()
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "BITB assets unavailable", http.StatusInternalServerError)
		})
	}
	return http.FileServer(http.FS(assets))
}

func validateTheme(theme Theme) error {
	switch theme {
	case ThemeAuto, ThemeWindows11, ThemeMacOS, ThemeLinux,
		ThemeWindows11Light, ThemeWindows11Dark, ThemeMacOSLight,
		ThemeMacOSDark, ThemeLinuxGNOME:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedTheme, theme)
	}
}

func validateURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, ErrInvalidURL
	}
	return parsed, nil
}
