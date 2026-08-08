// Package utls provides an HTTP transport that emulates browser TLS client
// hellos while retaining connection pooling for HTTP/1.1 and HTTP/2.
package utls

import (
	context "context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tlsclient "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	ChromeProfileName  = "Chrome"
	FirefoxProfileName = "Firefox"
	SafariProfileName  = "Safari"
	RandomProfileName  = "Random"
)

// ClientProfile selects the uTLS ClientHello used for a connection.
// Implementations must be safe for concurrent use.
type ClientProfile interface {
	Name() string
	ClientHelloID() tlsclient.ClientHelloID
}

type fixedProfile struct {
	name string
	id   tlsclient.ClientHelloID
}

func (p fixedProfile) Name() string                           { return p.name }
func (p fixedProfile) ClientHelloID() tlsclient.ClientHelloID { return p.id }

type randomProfile struct{}

func (randomProfile) Name() string { return RandomProfileName }

func (randomProfile) ClientHelloID() tlsclient.ClientHelloID {
	max := big.NewInt(int64(len(modernClientHelloIDs)))
	if selected, err := cryptorand.Int(cryptorand.Reader, max); err == nil {
		return modernClientHelloIDs[selected.Int64()]
	}

	// crypto/rand failures are exceptionally rare. The atomic fallback keeps
	// profile selection safe and varying without making connection setup fail.
	selected := atomic.AddUint64(&fallbackProfileIndex, 1)
	return modernClientHelloIDs[selected%uint64(len(modernClientHelloIDs))]
}

var (
	// Chrome emulates the current Chrome ClientHello known by uTLS.
	Chrome ClientProfile = fixedProfile{name: ChromeProfileName, id: tlsclient.HelloChrome_Auto}
	// Firefox emulates the current Firefox ClientHello known by uTLS.
	Firefox ClientProfile = fixedProfile{name: FirefoxProfileName, id: tlsclient.HelloFirefox_Auto}
	// Safari emulates uTLS's current iOS Safari ClientHello.
	Safari ClientProfile = fixedProfile{name: SafariProfileName, id: tlsclient.HelloIOS_Auto}
	// Random selects one of the modern browser presets for every new connection.
	Random ClientProfile = randomProfile{}

	modernClientHelloIDs = []tlsclient.ClientHelloID{
		tlsclient.HelloChrome_Auto,
		tlsclient.HelloFirefox_Auto,
		tlsclient.HelloIOS_Auto,
	}
	fallbackProfileIndex uint64
)

// ParseClientProfile resolves a profile name case-insensitively. Unknown and
// empty names use Chrome so callers of NewUTLSTransport always receive a usable
// transport.
func ParseClientProfile(name string) ClientProfile {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case strings.ToLower(FirefoxProfileName):
		return Firefox
	case strings.ToLower(SafariProfileName):
		return Safari
	case strings.ToLower(RandomProfileName):
		return Random
	default:
		return Chrome
	}
}

// Transport is a concurrent-safe HTTP/1.1 and HTTP/2 RoundTripper backed by
// uTLS. It pools connections separately for each origin and negotiated
// protocol.
type Transport struct {
	profile ClientProfile
	timeout time.Duration
	dialer  net.Dialer

	dialMu      sync.RWMutex
	dialContext func(context.Context, string, string) (net.Conn, error)

	http1   *http.Transport
	origins sync.Map
}

type originTransport struct {
	parent *Transport
	addr   string

	mu           sync.Mutex
	roundTripper http.RoundTripper
}

// NewUTLSTransport creates a browser-profiled outbound transport. The timeout
// covers TCP connection setup and the TLS handshake. A non-positive timeout
// leaves those operations governed by the request context.
func NewUTLSTransport(profile string, timeout time.Duration) http.RoundTripper {
	t := &Transport{
		profile: ParseClientProfile(profile),
		timeout: timeout,
		dialer: net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		},
	}
	t.http1 = t.newHTTP1Transport("")
	return t
}

// HTTP1Transport returns a concrete net/http transport configured with the
// same uTLS dialer. It is useful for integrations whose API requires
// *http.Transport rather than http.RoundTripper.
func (t *Transport) HTTP1Transport() *http.Transport {
	return t.newHTTP1Transport("http/1.1")
}

// SetDialContext replaces the TCP dial path, for example when routing through
// an upstream proxy. Passing nil restores direct network dialing.
func (t *Transport) SetDialContext(dial func(context.Context, string, string) (net.Conn, error)) {
	t.dialMu.Lock()
	t.dialContext = dial
	t.dialMu.Unlock()
	t.resetIdleConnections()
}

// SetDial adapts a context-free dial function for upstream dialers that do not
// implement context.Context cancellation. Passing nil restores direct dialing.
func (t *Transport) SetDial(dial func(string, string) (net.Conn, error)) {
	if dial == nil {
		t.SetDialContext(nil)
		return
	}
	t.SetDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}
		resultCh := make(chan result, 1)
		go func() {
			conn, err := dial(network, addr)
			resultCh <- result{conn: conn, err: err}
		}()

		select {
		case result := <-resultCh:
			return result.conn, result.err
		case <-ctx.Done():
			go func() {
				result := <-resultCh
				if result.conn != nil {
					_ = result.conn.Close()
				}
			}()
			return nil, ctx.Err()
		}
	})
}

// CloseIdleConnections closes idle HTTP/1.1 and HTTP/2 connections.
func (t *Transport) CloseIdleConnections() {
	t.resetIdleConnections()
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("utls: nil HTTP request or URL")
	}

	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		return t.http1.RoundTrip(req)
	case "https":
		addr, err := canonicalAddr(req)
		if err != nil {
			return nil, err
		}
		originKey := "https://" + addr
		originValue, _ := t.origins.LoadOrStore(originKey, &originTransport{parent: t, addr: addr})
		return originValue.(*originTransport).RoundTrip(req)
	default:
		return nil, fmt.Errorf("utls: unsupported URL scheme %q", req.URL.Scheme)
	}
}

func (o *originTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	o.mu.Lock()
	if o.roundTripper != nil {
		roundTripper := o.roundTripper
		o.mu.Unlock()
		return roundTripper.RoundTrip(req)
	}
	defer o.mu.Unlock()

	conn, protocol, err := o.parent.dialTLS(req.Context(), "tcp", o.addr, "")
	if err != nil {
		return nil, err
	}
	initialConn := conn
	claimed := false
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !claimed {
			if addr != o.addr {
				return nil, alpnNetError(addr, fmt.Errorf("preconnected TLS address %q does not match %q", o.addr, addr))
			}
			claimed = true
			return initialConn, nil
		}
		conn, _, err := o.parent.dialTLS(ctx, network, addr, protocol)
		return conn, err
	}

	switch protocol {
	case "h2":
		o.roundTripper = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialTLS(ctx, network, addr)
			},
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		}
	case "http/1.1":
		o.roundTripper = o.parent.newHTTP1TransportWithDial("http/1.1", dialTLS)
	default:
		_ = initialConn.Close()
		return nil, alpnNetError(o.addr, fmt.Errorf("unsupported negotiated ALPN protocol %q", protocol))
	}

	resp, err := o.roundTripper.RoundTrip(req)
	if !claimed {
		_ = initialConn.Close()
	}
	return resp, err
}

func (t *Transport) newHTTP1Transport(expectedProtocol string) *http.Transport {
	return t.newHTTP1TransportWithDial(expectedProtocol, func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, _, err := t.dialTLS(ctx, network, addr, expectedProtocol)
		return conn, err
	})
}

func (t *Transport) newHTTP1TransportWithDial(expectedProtocol string, dialTLS func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           t.dialTCP,
		DialTLSContext:        dialTLS,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   t.timeout,
		ExpectContinueTimeout: time.Second,
	}
}

func (t *Transport) dialTLS(ctx context.Context, network, addr, expectedProtocol string) (net.Conn, string, error) {
	dialCtx, cancel := withOptionalTimeout(ctx, t.timeout)
	defer cancel()

	plainConn, err := t.dialTCP(dialCtx, network, addr)
	if err != nil {
		return nil, "", wrapNetError("dial", network, addr, err)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = plainConn.Close()
		return nil, "", wrapNetError("tls handshake", network, addr, err)
	}
	tlsConn := tlsclient.UClient(plainConn, &tlsclient.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Preserve goproxy's existing outbound TLS behavior.
		NextProtos:         []string{"h2", "http/1.1"},
	}, t.profile.ClientHelloID())
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = plainConn.Close()
		return nil, "", wrapNetError("tls handshake", network, addr, err)
	}

	protocol := tlsConn.ConnectionState().NegotiatedProtocol
	if protocol == "" {
		protocol = "http/1.1"
	}
	if protocol != "h2" && protocol != "http/1.1" {
		_ = tlsConn.Close()
		return nil, "", alpnNetError(addr, fmt.Errorf("unsupported negotiated ALPN protocol %q", protocol))
	}
	if expectedProtocol != "" && protocol != expectedProtocol {
		_ = tlsConn.Close()
		return nil, "", alpnNetError(addr, fmt.Errorf("negotiated ALPN protocol %q; expected %q", protocol, expectedProtocol))
	}
	return tlsConn, protocol, nil
}

func (t *Transport) dialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	t.dialMu.RLock()
	dial := t.dialContext
	t.dialMu.RUnlock()
	if dial != nil {
		return dial(ctx, network, addr)
	}
	return t.dialer.DialContext(ctx, network, addr)
}

func (t *Transport) resetIdleConnections() {
	if t.http1 != nil {
		t.http1.CloseIdleConnections()
	}
	t.origins.Range(func(key, value any) bool {
		origin := value.(*originTransport)
		origin.mu.Lock()
		if closer, ok := origin.roundTripper.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
		origin.mu.Unlock()
		t.origins.Delete(key)
		return true
	})
}

func canonicalAddr(req *http.Request) (string, error) {
	host := req.URL.Hostname()
	if host == "" {
		return "", errors.New("utls: HTTPS request has no host")
	}
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), nil
}

func withOptionalTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func wrapNetError(op, network, addr string, err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return err
	}
	return &net.OpError{Op: op, Net: network, Addr: stringAddr(addr), Err: err}
}

func alpnNetError(addr string, err error) error {
	return &net.OpError{Op: "tls handshake", Net: "tcp", Addr: stringAddr(addr), Err: err}
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

var _ http.RoundTripper = (*Transport)(nil)
var _ ClientProfile = fixedProfile{}
var _ ClientProfile = randomProfile{}
