// Package database owns campaign relational database driver selection.
package database

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/s4l1hs/olta/pkg/campaign/config"
	sqlitedsn "github.com/s4l1hs/olta/pkg/storage/sqlite"
)

// Connector opens one supported relational database without exposing driver
// setup to campaign models.
type Connector interface {
	Driver() string
	Open(dsn, tlsCAPath string) (*gorm.DB, error)
}

// New returns the connector explicitly selected by configuration. An empty
// driver intentionally means SQLite, Olta Campaign's embedded default.
func New(driver string) (Connector, error) {
	switch driver {
	case "", config.DefaultDatabaseDriver:
		return sqliteConnector{}, nil
	case "mysql":
		return &mysqlConnector{}, nil
	default:
		return nil, fmt.Errorf("unsupported campaign database driver %q", driver)
	}
}

type sqliteConnector struct{}

func (sqliteConnector) Driver() string { return config.DefaultDatabaseDriver }

func (sqliteConnector) Open(path, tlsCAPath string) (*gorm.DB, error) {
	if tlsCAPath != "" {
		return nil, fmt.Errorf("SQLite does not support db_sslca_path")
	}
	if path == "" {
		path = config.DefaultDatabasePath
	}
	return gorm.Open(config.DefaultDatabaseDriver, sqlitedsn.ConcurrentDSN(path))
}

type mysqlConnector struct {
	tlsOnce sync.Once
	tlsErr  error
}

func (*mysqlConnector) Driver() string { return "mysql" }

func (c *mysqlConnector) Open(dsn, tlsCAPath string) (*gorm.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("MySQL requires db_path to contain a DSN")
	}
	if tlsCAPath != "" {
		c.tlsOnce.Do(func() { c.tlsErr = registerMySQLTLS(tlsCAPath) })
		if c.tlsErr != nil {
			return nil, c.tlsErr
		}
	}
	return gorm.Open("mysql", dsn)
}

func registerMySQLTLS(tlsCAPath string) error {
	pem, err := os.ReadFile(tlsCAPath)
	if err != nil {
		return fmt.Errorf("read MySQL CA certificate: %w", err)
	}
	rootCertPool := x509.NewCertPool()
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return fmt.Errorf("parse MySQL CA certificate %q", tlsCAPath)
	}
	if err := mysql.RegisterTLSConfig("ssl_ca", &tls.Config{RootCAs: rootCertPool, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("register MySQL TLS configuration: %w", err)
	}
	return nil
}
