// Package sqlite contains shared SQLite connection settings.
package sqlite

import "strings"

// ConcurrentDSN enables WAL and a busy timeout for campaign/proxy coexistence.
func ConcurrentDSN(path string) string {
	if path == "" || path == ":memory:" {
		return path
	}
	if !strings.HasPrefix(path, "file:") {
		path = "file:" + path
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + "_busy_timeout=10000&_journal_mode=WAL"
}
