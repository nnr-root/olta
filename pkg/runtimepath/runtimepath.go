// Package runtimepath resolves command asset directories independently of the
// caller's working directory.
package runtimepath

import (
	"fmt"
	"os"
	"path/filepath"
)

// Resolve finds the asset directory for a command. An explicit directory takes
// precedence; otherwise the working directory and executable directory are
// searched up to the filesystem root, both directly and below cmd/service.
func Resolve(explicit, service string, markers ...string) (string, error) {
	if explicit != "" {
		return validate(explicit, markers)
	}

	starts := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil {
		starts = append(starts, cwd)
	}
	if executable, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(executable))
	}

	seen := make(map[string]struct{})
	for _, start := range starts {
		for current := filepath.Clean(start); ; current = filepath.Dir(current) {
			for _, candidate := range []string{current, filepath.Join(current, "cmd", service)} {
				candidate, _ = filepath.Abs(candidate)
				if _, ok := seen[candidate]; ok {
					continue
				}
				seen[candidate] = struct{}{}
				if valid(candidate, markers) {
					return candidate, nil
				}
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
		}
	}

	return "", fmt.Errorf("could not locate assets for %s; use -asset-dir", service)
}

func validate(path string, markers []string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if !valid(abs, markers) {
		return "", fmt.Errorf("asset directory %q is missing required files", abs)
	}
	return abs, nil
}

func valid(root string, markers []string) bool {
	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(root, marker)); err != nil {
			return false
		}
	}
	return true
}
