package feed

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait          = 30 * time.Second
	pongWait           = 60 * time.Second
	pingPeriod         = (pongWait * 9) / 10
	maxMessageSize     = 1 << 20
	clientSendBuffer   = 64
	defaultHistorySize = 100
	viewerProtocol     = "olta.v1"
	viewerAuthPrefix   = "olta.auth."
)

// Config controls authentication, browser origins, and retained feed history.
// Empty tokens are accepted only for loopback listeners by Run.
type Config struct {
	AllowedOrigins []string
	PublisherToken string
	ViewerToken    string
	HistorySize    int
}

// Option configures the feed server.
type Option func(*Config)

// WithAllowedOrigins permits browser WebSocket requests from the listed origins.
// When no origins are configured, browser requests must be same-origin.
func WithAllowedOrigins(origins ...string) Option {
	return func(config *Config) {
		config.AllowedOrigins = append([]string(nil), origins...)
	}
}

// WithPublisherToken requires publishers to present a Bearer token.
func WithPublisherToken(token string) Option {
	return func(config *Config) { config.PublisherToken = token }
}

// WithViewerToken requires viewers to present a Bearer token or the browser
// WebSocket authentication subprotocol used by the bundled feed UI.
func WithViewerToken(token string) Option {
	return func(config *Config) { config.ViewerToken = token }
}

// WithHistorySize controls how many recent messages are replayed to new viewers.
func WithHistorySize(size int) Option {
	return func(config *Config) { config.HistorySize = size }
}

func newConfig(options ...Option) Config {
	config := Config{HistorySize: defaultHistorySize}
	for _, option := range options {
		option(&config)
	}
	if config.HistorySize < 0 {
		config.HistorySize = 0
	}
	return config
}

func sameToken(actual, expected string) bool {
	if expected == "" {
		return true
	}
	return len(actual) == len(expected) && subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if len(value) < len("Bearer ") || !strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(value[len("Bearer "):])
}

func viewerToken(r *http.Request) string {
	if token := bearerToken(r); token != "" {
		return token
	}
	for _, protocol := range websocket.Subprotocols(r) {
		if !strings.HasPrefix(protocol, viewerAuthPrefix) {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(protocol, viewerAuthPrefix))
		if err == nil {
			return string(decoded)
		}
	}
	return ""
}

func originAllowed(allowed []string, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	if len(allowed) == 0 {
		return strings.EqualFold(parsed.Host, r.Host)
	}
	normalized := strings.TrimSuffix(origin, "/")
	for _, candidate := range allowed {
		if strings.EqualFold(normalized, strings.TrimSuffix(strings.TrimSpace(candidate), "/")) {
			return true
		}
	}
	return false
}

func newUpgrader(config Config) websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		Subprotocols:    []string{viewerProtocol},
		CheckOrigin: func(r *http.Request) bool {
			return originAllowed(config.AllowedOrigins, r)
		},
	}
}

func serveSubscriber(hub *Hub, upgrader websocket.Upgrader, config Config, w http.ResponseWriter, r *http.Request) {
	if !sameToken(viewerToken(r), config.ViewerToken) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("feed subscriber upgrade: %v", err)
		return
	}
	bufferSize := clientSendBuffer
	if config.HistorySize > bufferSize {
		bufferSize = config.HistorySize
	}
	client := &Client{hub: hub, conn: conn, send: make(chan []byte, bufferSize)}
	client.hub.register <- client
	go client.writePump()
	go client.readPump(false)
}

func servePublisher(hub *Hub, upgrader websocket.Upgrader, config Config, w http.ResponseWriter, r *http.Request) {
	if !sameToken(bearerToken(r), config.PublisherToken) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("feed publisher upgrade: %v", err)
		return
	}
	client := &Client{hub: hub, conn: conn}
	go client.readPump(true)
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) readPump(publish bool) {
	defer func() {
		if c.send != nil {
			c.hub.unregister <- c
		}
		_ = c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	if err := c.conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		return
	}
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	for {
		messageType, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("feed websocket: %v", err)
			}
			return
		}
		if !publish || messageType != websocket.TextMessage {
			continue
		}
		message = []byte(strings.TrimSpace(string(message)))
		if len(message) == 0 || !json.Valid(message) {
			log.Print("feed publisher sent invalid JSON")
			continue
		}
		c.hub.broadcast <- message
	}
}

const DefaultListenAddress = "localhost:1337"

// Handler creates the Olta Feed static and WebSocket routes.
func Handler(assetDir string, options ...Option) http.Handler {
	config := newConfig(options...)
	hub := newHub(config.HistorySize)
	go hub.run()
	upgrader := newUpgrader(config)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveSubscriber(hub, upgrader, config, w, r)
	})
	mux.HandleFunc("/ws/publish", func(w http.ResponseWriter, r *http.Request) {
		servePublisher(hub, upgrader, config, w, r)
	})
	mux.Handle("/", http.FileServer(http.Dir(assetDir)))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func loopbackListener(listenAddress string) bool {
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Run starts the Olta Feed HTTP and WebSocket server.
func Run(listenAddress, assetDir string, options ...Option) error {
	config := newConfig(options...)
	if !loopbackListener(listenAddress) && (config.PublisherToken == "" || config.ViewerToken == "") {
		return errors.New("non-loopback feed listeners require publisher and viewer tokens")
	}
	if config.PublisherToken != "" && sameToken(config.PublisherToken, config.ViewerToken) {
		return errors.New("publisher and viewer tokens must be different")
	}
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           Handler(assetDir, options...),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("Olta Feed is available at http://%s/", listenAddress)
	if config.PublisherToken == "" || config.ViewerToken == "" {
		log.Print("Olta Feed authentication is disabled for this loopback-only listener")
	}
	return fmt.Errorf("feed server: %w", server.ListenAndServe())
}
