package datadir

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
)

func TestIsInitializedRequiresBothFiles(t *testing.T) {
	dir := t.TempDir()
	if IsInitialized(dir) {
		t.Fatal("empty dir reported initialized")
	}
	mustTouch(t, filepath.Join(dir, SecretFile))
	if IsInitialized(dir) {
		t.Fatal("missing admin hash reported initialized")
	}
	mustTouch(t, filepath.Join(dir, AdminPasswordFile))
	if !IsInitialized(dir) {
		t.Fatal("complete layout reported uninitialized")
	}
}

// TestResolvePrecedence pins flag > env > cwd.
func TestResolvePrecedence(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	BindFlag(fs)
	_ = fs.Parse([]string{"--data-dir", "/from-flag"})
	t.Setenv(EnvDataDir, "/from-env")
	if got := Resolve(fs); got != "/from-flag" {
		t.Errorf("flag should win: got %q", got)
	}
}

func TestResolveFallsBackToEnv(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	BindFlag(fs)
	_ = fs.Parse(nil)
	t.Setenv(EnvDataDir, "/from-env")
	if got := Resolve(fs); got != "/from-env" {
		t.Errorf("env fallback: got %q", got)
	}
}

func TestResolveFallsBackToCwdWhenInitialized(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	mustTouch(t, SecretFile)
	mustTouch(t, AdminPasswordFile)

	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	BindFlag(fs)
	_ = fs.Parse(nil)
	if got := Resolve(fs); got != "." {
		t.Errorf("cwd fallback: got %q", got)
	}
}

func TestLayoutPaths(t *testing.T) {
	l := Layout{Dir: "/data"}
	cases := map[string]string{
		"APIs":     "/data/apis",
		"Policies": "/data/policies",
		"StoreDB":  "/data/store/store.db",
		"Secret":   "/data/secret.hex",
	}
	got := map[string]string{
		"APIs":     l.APIs(),
		"Policies": l.Policies(),
		"StoreDB":  l.StoreDB(),
		"Secret":   l.Secret(),
	}
	for k, want := range cases {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

func mustTouch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}
