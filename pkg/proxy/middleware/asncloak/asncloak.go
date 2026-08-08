package asncloak

import (
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Action controls how a matching request is handled.
type Action string

const (
	ActionRedirect Action = "redirect"
	ActionBlock    Action = "block"
)

// Config controls matching and enforcement.
type Config struct {
	Enabled             bool
	Provider            Provider
	Action              Action
	RedirectURL         string
	BlockStatus         int
	InspectHeaders      bool
	TrustProxyHeaders   bool
	SuspiciousUserAgent []string
	RequiredHeaders     []string
	MissingHeaderLimit  int
}

// Match describes the first rule that classified a request.
type Match struct {
	Rule    string
	Detail  string
	IP      netip.Addr
	Network *Network
}

// Middleware evaluates requests without network I/O or mutable shared state.
type Middleware struct {
	config Config
}

var defaultSuspiciousUserAgents = []string{
	"bot", "crawler", "spider", "headlesschrome", "phantomjs", "selenium",
	"playwright", "puppeteer", "proofpoint", "urlscan", "safelinks",
	"barracuda", "palo alto", "curl/", "wget/", "python-requests",
	"go-http-client", "okhttp/", "java/",
}

var defaultRequiredHeaders = []string{"Accept", "Accept-Language", "Accept-Encoding"}

// New validates config and constructs middleware. A nil Provider uses the
// package's local default CIDR table.
func New(config Config) (*Middleware, error) {
	if config.Action == "" {
		config.Action = ActionRedirect
	}
	switch config.Action {
	case ActionRedirect:
		if config.RedirectURL == "" {
			config.RedirectURL = "https://www.google.com/"
		}
		target, err := url.Parse(config.RedirectURL)
		if err != nil || !target.IsAbs() || (target.Scheme != "http" && target.Scheme != "https") {
			return nil, fmt.Errorf("cloaker redirect URL must be an absolute HTTP(S) URL")
		}
	case ActionBlock:
		if config.BlockStatus == 0 {
			config.BlockStatus = http.StatusNotFound
		}
		if config.BlockStatus != http.StatusNotFound && config.BlockStatus != http.StatusForbidden {
			return nil, fmt.Errorf("cloaker block status must be 403 or 404")
		}
	default:
		return nil, fmt.Errorf("unknown cloaker action %q", config.Action)
	}

	if config.Provider == nil {
		provider, err := NewDefaultProvider()
		if err != nil {
			return nil, fmt.Errorf("initialize default CIDR provider: %w", err)
		}
		config.Provider = provider
	}
	if config.SuspiciousUserAgent == nil {
		config.SuspiciousUserAgent = append([]string(nil), defaultSuspiciousUserAgents...)
	}
	if config.RequiredHeaders == nil {
		config.RequiredHeaders = append([]string(nil), defaultRequiredHeaders...)
	}
	if config.MissingHeaderLimit == 0 {
		config.MissingHeaderLimit = len(config.RequiredHeaders)
	}
	if config.MissingHeaderLimit < 0 || config.MissingHeaderLimit > len(config.RequiredHeaders) {
		return nil, fmt.Errorf("cloaker missing-header limit must be between 0 and %d", len(config.RequiredHeaders))
	}
	return &Middleware{config: config}, nil
}

// Evaluate returns the first network, user-agent, header, or protocol match.
func (middleware *Middleware) Evaluate(request *http.Request) (Match, bool) {
	if middleware == nil || !middleware.config.Enabled || request == nil {
		return Match{}, false
	}

	for _, address := range middleware.clientAddresses(request) {
		if network, found := middleware.config.Provider.Lookup(address); found {
			return Match{
				Rule:    "network",
				Detail:  network.Organization,
				IP:      address,
				Network: &network,
			}, true
		}
	}

	if !middleware.config.InspectHeaders {
		return Match{}, false
	}
	userAgent := strings.ToLower(strings.TrimSpace(request.UserAgent()))
	if userAgent == "" {
		return Match{Rule: "user-agent", Detail: "missing user-agent"}, true
	}
	for _, marker := range middleware.config.SuspiciousUserAgent {
		if marker != "" && strings.Contains(userAgent, strings.ToLower(marker)) {
			return Match{Rule: "user-agent", Detail: marker}, true
		}
	}

	missing := make([]string, 0, len(middleware.config.RequiredHeaders))
	for _, header := range middleware.config.RequiredHeaders {
		if strings.TrimSpace(request.Header.Get(header)) == "" {
			missing = append(missing, header)
		}
	}
	if middleware.config.MissingHeaderLimit > 0 && len(missing) >= middleware.config.MissingHeaderLimit {
		return Match{Rule: "headers", Detail: "missing " + strings.Join(missing, ", ")}, true
	}

	// Modern graphical browsers do not originate HTTP/1.0 requests. Treating a
	// browser-identifying UA over a legacy protocol as anomalous catches simple
	// replay clients while leaving normal HTTP/1.1, HTTP/2, and HTTP/3 intact.
	if request.ProtoMajor == 1 && request.ProtoMinor == 0 && looksLikeBrowser(userAgent) {
		return Match{Rule: "protocol", Detail: "browser user-agent over HTTP/1.0"}, true
	}
	return Match{}, false
}

func (middleware *Middleware) clientAddresses(request *http.Request) []netip.Addr {
	if middleware.config.TrustProxyHeaders {
		for _, value := range request.Header.Values("X-Forwarded-For") {
			for _, part := range strings.Split(value, ",") {
				if address, ok := parseAddress(part); ok {
					return []netip.Addr{address}
				}
			}
		}
		for _, header := range []string{"X-Real-IP", "X-Client-IP", "Connecting-IP", "True-Client-IP", "Client-IP"} {
			if address, ok := parseAddress(request.Header.Get(header)); ok {
				return []netip.Addr{address}
			}
		}
	}
	if address, ok := parseAddress(request.RemoteAddr); ok {
		return []netip.Addr{address}
	}
	return nil
}

func parseAddress(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap(), true
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		if address, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
			return address.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func looksLikeBrowser(userAgent string) bool {
	return strings.Contains(userAgent, "mozilla/") ||
		strings.Contains(userAgent, "chrome/") ||
		strings.Contains(userAgent, "safari/") ||
		strings.Contains(userAgent, "firefox/") ||
		strings.Contains(userAgent, "edg/")
}

// Response builds the enforcement response used by proxy integrations.
func (middleware *Middleware) Response(request *http.Request) *http.Response {
	status := middleware.config.BlockStatus
	body := http.StatusText(status) + "\n"
	header := make(http.Header)
	if middleware.config.Action == ActionRedirect {
		status = http.StatusFound
		body = "<a href=\"" + html.EscapeString(middleware.config.RedirectURL) + "\">Found</a>.\n"
		header.Set("Location", middleware.config.RedirectURL)
		header.Set("Content-Type", "text/html; charset=utf-8")
	} else {
		header.Set("Content-Type", "text/plain; charset=utf-8")
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
}

// Handler wraps downstream with request classification and enforcement.
func (middleware *Middleware) Handler(downstream http.Handler) http.Handler {
	if downstream == nil {
		downstream = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, matched := middleware.Evaluate(request); !matched {
			downstream.ServeHTTP(writer, request)
			return
		}
		response := middleware.Response(request)
		for name, values := range response.Header {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		writer.WriteHeader(response.StatusCode)
		_, _ = io.Copy(writer, response.Body)
		_ = response.Body.Close()
	})
}
