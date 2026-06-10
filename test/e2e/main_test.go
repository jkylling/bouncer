//go:build e2e

// Package e2e exercises the bouncer binary as a black box: a TestMain
// `go build`s it once into a per-package temp dir, and each test
// drives the resulting binary via os/exec and HTTP. Nothing here
// imports internal/* — the surface under test is what an operator
// would actually run.
//
// Run with `make e2e` (or `go test -tags=e2e ./test/e2e/...`). The build
// tag keeps this suite out of the default `go test ./...` so the
// per-package go-build cost (~5s) is paid only when explicitly
// requested.
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// bouncerBin is the absolute path to the compiled bouncer binary,
// populated by TestMain. Helpers (runCmd, startServe) read it
// directly so per-test calls don't repeat the discovery dance.
var bouncerBin string

// TestMain compiles bouncer once and shares the resulting binary
// across every test in the package. The temp dir is deleted on
// teardown so a successful run leaves nothing on disk.
//
// The build cost (~5s on a cold cache, <1s warm) is amortised over
// every E2E test, which is the whole reason for going through
// TestMain rather than rebuilding per-test.
func TestMain(m *testing.M) {
	bin, cleanup, err := buildBinary("./cmd/bouncer", "bouncer")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: build bouncer: %v\n", err)
		os.Exit(1)
	}
	bouncerBin = bin
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// buildBinary compiles pkg into a per-suite temp dir and returns the
// path plus a cleanup that removes the dir. A stable name (rather
// than a random temp filename) keeps log output readable when a test
// shells out and the binary path appears in error messages.
func buildBinary(pkg, name string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "bouncer-e2e-")
	if err != nil {
		return "", nil, err
	}
	bin := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	// Build from the parent module so the relative pkg path resolves
	// against go.mod regardless of where `go test` is invoked from.
	cmd.Dir = repoRoot()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("go build %s: %w", pkg, err)
	}
	return bin, func() { _ = os.RemoveAll(dir) }, nil
}

// repoRoot returns the directory that holds go.mod. The e2e package
// lives at <root>/test/e2e/, so two parents up is the root. Computed
// off this file's runtime location so `go test` invoked from any cwd
// still finds the module root.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}
