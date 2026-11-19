package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRepositorySkeleton(t *testing.T) {
	root := repositoryRoot(t)

	requiredPaths := []string{
		"go.mod",
		"README.md",
		"Makefile",
		filepath.Join("cmd", "aml-api", "main.go"),
		filepath.Join("cmd", "aml-worker", "main.go"),
		filepath.Join("internal", "httpapi", "doc.go"),
		filepath.Join("internal", "authz", "doc.go"),
		filepath.Join("internal", "config", "doc.go"),
		filepath.Join("internal", "logging", "doc.go"),
		filepath.Join("tests", "repository_layout_test.go"),
	}

	for _, path := range requiredPaths {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("required skeleton path %q is missing or unreadable: %v", path, err)
		}
	}
}

func TestWave01DoesNotIntroduceOutOfScopeArtifacts(t *testing.T) {
	root := repositoryRoot(t)

	forbiddenPaths := []string{
		"db",
		filepath.Join("db", "migrations"),
		filepath.Join("internal", "debug"),
		filepath.Join("cmd", "checker"),
		filepath.Join("scripts", "exploits"),
		filepath.Join("checkers", "voltax"),
		filepath.Join("sploits", "voltax"),
	}

	for _, path := range forbiddenPaths {
		if _, err := os.Stat(filepath.Join(root, path)); err == nil {
			t.Fatalf("Wave 01 skeleton must not add out-of-scope path %q", path)
		} else if !os.IsNotExist(err) {
			t.Fatalf("could not inspect path %q: %v", path, err)
		}
	}
}

func TestWave01DoesNotIntroduceReservedFieldNames(t *testing.T) {
	root := repositoryRoot(t)
	reservedFieldNames := [][]byte{
		[]byte("flag" + "_value"),
		[]byte("secret" + "_for_checker"),
	}

	wave01Paths := []string{
		"README.md",
		filepath.Join("cmd", "aml-api", "main.go"),
		filepath.Join("cmd", "aml-worker", "main.go"),
		filepath.Join("internal", "httpapi", "doc.go"),
		filepath.Join("internal", "authz", "doc.go"),
		filepath.Join("internal", "config", "doc.go"),
		filepath.Join("internal", "logging", "doc.go"),
		filepath.Join("tests", "repository_layout_test.go"),
		filepath.Join("docs", "wave_reports", "wave_01_W01-T01_handoff.md"),
		filepath.Join("docs", "14_agent_execution_log.md"),
	}

	for _, path := range wave01Paths {
		content, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("could not read %q: %v", path, err)
		}
		for _, fieldName := range reservedFieldNames {
			if bytes.Contains(content, fieldName) {
				t.Fatalf("Wave 01 file %q contains reserved checker/flag field name %q", path, fieldName)
			}
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve repository layout test path")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(filename), ".."))
}
