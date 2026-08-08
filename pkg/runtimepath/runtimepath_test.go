package runtimepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveFromRepositoryRootAndCommandDirectory(t *testing.T) {
	repository := t.TempDir()
	commandDir := filepath.Join(repository, "cmd", "olta-feed")
	if err := os.MkdirAll(filepath.Join(commandDir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(commandDir, "app", "index.html"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	for _, workingDirectory := range []string{repository, commandDir} {
		if err := os.Chdir(workingDirectory); err != nil {
			t.Fatal(err)
		}
		resolved, err := Resolve("", "olta-feed", "app/index.html")
		if err != nil {
			t.Fatalf("Resolve() from %s: %v", workingDirectory, err)
		}
		resolvedInfo, err := os.Stat(resolved)
		if err != nil {
			t.Fatal(err)
		}
		commandInfo, err := os.Stat(commandDir)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(resolvedInfo, commandInfo) {
			t.Fatalf("Resolve() = %s, want %s", resolved, commandDir)
		}
	}
}
