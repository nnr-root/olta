package config

import (
	"encoding/json"
	"os"

	log "github.com/s4l1hs/olta/pkg/campaign/logger"
)

const (
	DefaultDatabaseDriver = "sqlite3"
	DefaultDatabasePath   = "olta-campaign.db"
)

// AdminServer represents the Admin server configuration details
type AdminServer struct {
	ListenURL               string   `json:"listen_url"`
	UseTLS                  bool     `json:"use_tls"`
	CertPath                string   `json:"cert_path"`
	KeyPath                 string   `json:"key_path"`
	CSRFKey                 string   `json:"csrf_key"`
	AllowedInternalHosts    []string `json:"allowed_internal_hosts"`
	AllowedAPIOrigins       []string `json:"allowed_api_origins"`
	TrustedProxies          []string `json:"trusted_proxies"`
	AllowInsecureSiteImport bool     `json:"allow_insecure_site_import"`
}

// PhishServer represents the Phish server configuration details
type PhishServer struct {
	ListenURL      string   `json:"listen_url"`
	UseTLS         bool     `json:"use_tls"`
	CertPath       string   `json:"cert_path"`
	KeyPath        string   `json:"key_path"`
	TrustedProxies []string `json:"trusted_proxies"`
}

// TelemetryFeatures records which optional olta-proxy capabilities were
// enabled for this engagement, so the campaign resilience report knows
// which kill-chain stages actually had a watcher.
//
// These three booleans SHOULD match how olta-proxy was launched
// (-enable-cloaker, -enable-js-inspect, -enable-session-validator
// respectively), but they are a floor, not the final word: the resilience
// report (pkg/campaign/resilience) treats a false here as a claim that can
// be corrected by observed evidence, not a fact taken on faith. asncloak,
// jsinspect, and the session validation worker only ever emit an event for
// their stage when the corresponding proxy feature is actually running, so
// even one such event in the report's row set is hard proof the feature was
// on. If that happens while the matching field here is false, the stage is
// upgraded to measured automatically -- a stale false self-corrects.
//
// A stale true does NOT self-correct: absence of events proves nothing (an
// enabled feature can simply never match anything), so a field left true
// after olta-proxy was actually launched without that flag will make the
// report claim a stage was measured and clean when nothing was watching it.
// That direction remains the operator's responsibility -- keep these three
// booleans set to true only when the matching -enable-* flag is actually
// passed to olta-proxy.
type TelemetryFeatures struct {
	// Cloaker must match olta-proxy's -enable-cloaker flag.
	Cloaker bool `json:"cloaker"`
	// Verify must match olta-proxy's -enable-js-inspect flag.
	Verify bool `json:"verify"`
	// SessionValidator must match olta-proxy's -enable-session-validator flag.
	SessionValidator bool `json:"session_validator"`
}

// Config represents the configuration information.
type Config struct {
	AdminConf      AdminServer       `json:"admin_server"`
	PhishConf      PhishServer       `json:"phish_server"`
	DBName         string            `json:"db_name"`
	DBPath         string            `json:"db_path"`
	DBSSLCaPath    string            `json:"db_sslca_path"`
	TestFlag       bool              `json:"test_flag"`
	ContactAddress string            `json:"contact_address"`
	Logging        *log.Config       `json:"logging"`
	FeedEnabled    bool              `json:"feed_enabled"`
	FeedURL        string            `json:"feed_url"`
	Telemetry      TelemetryFeatures `json:"telemetry"`
}

// Version contains the current Olta Campaign version.
var Version = ""

// ServerName is the server type that is returned in the transparency response.
const ServerName = "IGNORE"

// LoadConfig loads the configuration from the specified filepath
func LoadConfig(filepath string) (*Config, error) {
	// Get the config file
	configFile, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	err = json.Unmarshal(configFile, config)
	if err != nil {
		return nil, err
	}
	if config.Logging == nil {
		config.Logging = &log.Config{}
	}
	config.ApplyDatabaseDefaults()
	// Explicitly set the TestFlag to false to prevent config.json overrides
	config.TestFlag = false
	return config, nil
}

// ApplyDatabaseDefaults keeps the campaign service zero-dependency by using
// its embedded SQLite database unless an external driver is explicitly set.
func (c *Config) ApplyDatabaseDefaults() {
	if c.DBName == "" {
		c.DBName = DefaultDatabaseDriver
	}
	if c.DBPath == "" && c.DBName == DefaultDatabaseDriver {
		c.DBPath = DefaultDatabasePath
	}
}
