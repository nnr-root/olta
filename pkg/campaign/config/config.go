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
	ListenURL            string   `json:"listen_url"`
	UseTLS               bool     `json:"use_tls"`
	CertPath             string   `json:"cert_path"`
	KeyPath              string   `json:"key_path"`
	CSRFKey              string   `json:"csrf_key"`
	AllowedInternalHosts []string `json:"allowed_internal_hosts"`
}

// PhishServer represents the Phish server configuration details
type PhishServer struct {
	ListenURL string `json:"listen_url"`
	UseTLS    bool   `json:"use_tls"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
}

// Config represents the configuration information.
type Config struct {
	AdminConf      AdminServer `json:"admin_server"`
	PhishConf      PhishServer `json:"phish_server"`
	DBName         string      `json:"db_name"`
	DBPath         string      `json:"db_path"`
	DBSSLCaPath    string      `json:"db_sslca_path"`
	TestFlag       bool        `json:"test_flag"`
	ContactAddress string      `json:"contact_address"`
	Logging        *log.Config `json:"logging"`
	FeedEnabled    bool        `json:"feed_enabled"`
	FeedURL        string      `json:"feed_url"`
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
