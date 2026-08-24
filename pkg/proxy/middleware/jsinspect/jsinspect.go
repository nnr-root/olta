// Package jsinspect provides a small client-side environment assertion and
// the HTTP helpers needed to inject and receive it.
package jsinspect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/s4l1hs/olta/pkg/telemetry"
)

// Action controls how a suspicious client assertion is handled.
type Action string

const (
	ActionRedirect Action = "redirect"
	ActionBlock    Action = "block"

	defaultEndpoint  = "/_assets/js/v.js"
	maxAssertionSize = 4096
)

var (
	headPattern             = regexp.MustCompile(`(?i)<head(?:\s[^>]*)?>`)
	softwareRendererPattern = regexp.MustCompile(`(?i)(swiftshader|llvmpipe|mesa)`)
)

// Config controls script generation and enforcement behavior.
type Config struct {
	Enabled     bool
	Endpoint    string
	Action      Action
	RedirectURL string

	// Emitter receives a verify event for every parsed assertion. Nil
	// disables emission.
	Emitter telemetry.Emitter
}

// Assertion is the compact client environment signal emitted by Script.
type Assertion struct {
	Version          int    `json:"version"`
	WebDriver        bool   `json:"webdriver"`
	Headless         bool   `json:"headless"`
	Phantom          bool   `json:"phantom"`
	Renderer         string `json:"renderer"`
	SoftwareRenderer bool   `json:"software_renderer"`
	CanvasConsistent bool   `json:"canvas_consistent"`
}

// Suspicious reports whether an assertion indicates browser automation or a
// software-rendered environment. The renderer is checked again server-side so
// clients cannot create an internally contradictory assertion accidentally.
func (assertion Assertion) Suspicious() bool {
	return assertion.WebDriver || assertion.Headless || assertion.Phantom ||
		assertion.SoftwareRenderer || softwareRendererPattern.MatchString(assertion.Renderer) ||
		!assertion.CanvasConsistent
}

// Middleware injects and receives client environment assertions.
type Middleware struct {
	config Config
	script []byte
}

// New validates config and constructs the middleware.
func New(config Config) (*Middleware, error) {
	if config.Endpoint == "" {
		config.Endpoint = defaultEndpoint
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.IsAbs() || !strings.HasPrefix(endpoint.Path, "/") || endpoint.Path == "/" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("js inspect endpoint must be an absolute path without a query or fragment")
	}
	config.Endpoint = endpoint.EscapedPath()

	if config.Action == "" {
		config.Action = ActionRedirect
	}
	switch config.Action {
	case ActionRedirect:
		if config.RedirectURL == "" {
			config.RedirectURL = "https://www.google.com/"
		}
		target, parseErr := url.Parse(config.RedirectURL)
		if parseErr != nil || !target.IsAbs() || (target.Scheme != "http" && target.Scheme != "https") {
			return nil, fmt.Errorf("js inspect redirect URL must be an absolute HTTP(S) URL")
		}
	case ActionBlock:
	default:
		return nil, fmt.Errorf("unknown js inspect action %q", config.Action)
	}

	middleware := &Middleware{config: config}
	middleware.script = []byte(generateScript(config.Endpoint))
	return middleware, nil
}

// Endpoint returns the internal assertion route.
func (middleware *Middleware) Endpoint() string {
	if middleware == nil {
		return ""
	}
	return middleware.config.Endpoint
}

// Script returns a copy of the generated client verification script.
func (middleware *Middleware) Script() []byte {
	if middleware == nil {
		return nil
	}
	return append([]byte(nil), middleware.script...)
}

// InjectHTML inserts the verification script immediately after the first head
// start tag. Non-HTML fragments without a head and already-injected pages are
// returned unchanged.
func (middleware *Middleware) InjectHTML(body []byte) []byte {
	if middleware == nil || !middleware.config.Enabled || len(body) == 0 || bytes.Contains(body, []byte(`data-olta-js-inspect`)) {
		return body
	}
	location := headPattern.FindIndex(body)
	if location == nil {
		return body
	}
	injection := make([]byte, 0, len(middleware.script)+43)
	injection = append(injection, `<script data-olta-js-inspect>`...)
	injection = append(injection, middleware.script...)
	injection = append(injection, `</script>`...)

	result := make([]byte, 0, len(body)+len(injection))
	result = append(result, body[:location[1]]...)
	result = append(result, injection...)
	result = append(result, body[location[1]:]...)
	return result
}

// ParseAssertion parses and validates a JSON assertion from reader.
func ParseAssertion(reader io.Reader) (Assertion, error) {
	if reader == nil {
		return Assertion{}, fmt.Errorf("missing assertion")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, maxAssertionSize+1))
	decoder.DisallowUnknownFields()
	var assertion Assertion
	if err := decoder.Decode(&assertion); err != nil {
		return Assertion{}, fmt.Errorf("decode assertion: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Assertion{}, fmt.Errorf("decode assertion: trailing data")
	}
	if assertion.Version != 1 {
		return Assertion{}, fmt.Errorf("unsupported assertion version %d", assertion.Version)
	}
	if len(assertion.Renderer) > 512 {
		return Assertion{}, fmt.Errorf("renderer exceeds 512 bytes")
	}
	return assertion, nil
}

// HandleRequest handles the configured verification endpoint. The boolean is
// false when the request should continue through the normal proxy pipeline.
func (middleware *Middleware) HandleRequest(request *http.Request) (*http.Response, bool) {
	if middleware == nil || !middleware.config.Enabled || request == nil || request.URL == nil || request.URL.EscapedPath() != middleware.config.Endpoint {
		return nil, false
	}

	var (
		assertion Assertion
		err       error
	)
	switch request.Method {
	case http.MethodPost:
		assertion, err = ParseAssertion(request.Body)
	case http.MethodGet:
		encoded := request.URL.Query().Get("assertion")
		var payload []byte
		if encoded == "" {
			err = fmt.Errorf("missing assertion")
		} else if payload, err = base64.RawURLEncoding.DecodeString(encoded); err == nil {
			assertion, err = ParseAssertion(bytes.NewReader(payload))
		}
	default:
		response := textResponse(request, http.StatusMethodNotAllowed, "Method Not Allowed\n")
		response.Header.Set("Allow", "GET, POST")
		return response, true
	}
	if err != nil {
		return textResponse(request, http.StatusBadRequest, "Bad Request\n"), true
	}
	if assertion.Suspicious() {
		middleware.emitVerify(request, assertion, telemetry.OutcomeBlocked)
		return middleware.enforcementResponse(request), true
	}
	middleware.emitVerify(request, assertion, telemetry.OutcomeAllowed)
	return emptyResponse(request, http.StatusNoContent), true
}

func (middleware *Middleware) emitVerify(request *http.Request, assertion Assertion, outcome telemetry.Outcome) {
	if middleware.config.Emitter == nil {
		return
	}
	if outcome == telemetry.OutcomeBlocked && middleware.config.Action == ActionRedirect {
		outcome = telemetry.OutcomeRedirected
	}

	middleware.config.Emitter.Emit(
		telemetry.New(telemetry.StageVerify, outcome, telemetry.TechniqueSandboxEvasion).
			WithActor(telemetry.Actor{
				IP:        clientIP(request),
				UserAgent: request.UserAgent(),
			}).
			WithDetail("webdriver", assertion.WebDriver).
			WithDetail("headless", assertion.Headless).
			WithDetail("phantom", assertion.Phantom).
			WithDetail("software_renderer", assertion.SoftwareRenderer).
			WithDetail("canvas_consistent", assertion.CanvasConsistent).
			WithDetail("renderer", assertion.Renderer),
	)
}

func clientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func (middleware *Middleware) enforcementResponse(request *http.Request) *http.Response {
	if middleware.config.Action == ActionRedirect {
		body := "<a href=\"" + html.EscapeString(middleware.config.RedirectURL) + "\">Found</a>.\n"
		response := response(request, http.StatusFound, "text/html; charset=utf-8", body)
		response.Header.Set("Location", middleware.config.RedirectURL)
		return response
	}
	return textResponse(request, http.StatusForbidden, "Forbidden\n")
}

func emptyResponse(request *http.Request, status int) *http.Response {
	return response(request, status, "", "")
}

func textResponse(request *http.Request, status int, body string) *http.Response {
	return response(request, status, "text/plain; charset=utf-8", body)
}

func response(request *http.Request, status int, contentType string, body string) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	header.Set("Cache-Control", "no-store")
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

func generateScript(endpoint string) string {
	endpointJSON, _ := json.Marshal(endpoint)
	return `(function(){try{var a={version:1,webdriver:navigator.webdriver===true,headless:false,phantom:false,renderer:"",software_renderer:false,canvas_consistent:true};var u=(navigator.userAgent||"").toLowerCase();a.headless=u.indexOf("headless")!==-1||("_Selenium_IDE_Recorder" in window)||("__webdriver_script_fn" in document);a.phantom=!!(window.callPhantom||window._phantom);try{var c=document.createElement("canvas"),g=c.getContext("webgl")||c.getContext("experimental-webgl");if(g){var x=g.getExtension("WEBGL_debug_renderer_info");a.renderer=String(x?g.getParameter(x.UNMASKED_RENDERER_WEBGL):g.getParameter(g.RENDERER)||"");a.software_renderer=/(swiftshader|llvmpipe|mesa)/i.test(a.renderer)}}catch(e){a.canvas_consistent=false}try{var c1=document.createElement("canvas"),c2=document.createElement("canvas"),d1=c1.getContext("2d"),d2=c2.getContext("2d");c1.width=c2.width=64;c1.height=c2.height=16;d1.font=d2.font="12px sans-serif";d1.fillText("olta",2,12);d2.fillText("olta",2,12);var p1=c1.toDataURL(),p2=c2.toDataURL();a.canvas_consistent=p1.length>32&&p1===p2}catch(e){a.canvas_consistent=false}var j=JSON.stringify(a),bad=a.webdriver||a.headless||a.phantom||a.software_renderer||!a.canvas_consistent,e=` + string(endpointJSON) + `;if(bad){var b=btoa(unescape(encodeURIComponent(j))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");location.replace(e+"?assertion="+encodeURIComponent(b))}else if(navigator.sendBeacon){navigator.sendBeacon(e,new Blob([j],{type:"application/json"}))}else{fetch(e,{method:"POST",headers:{"Content-Type":"application/json"},body:j,credentials:"same-origin",keepalive:true})}}catch(e){}})();`
}
