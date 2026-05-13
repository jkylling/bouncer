package initcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunWritesLayout pins the on-disk shape that serve --data-dir
// later consumes: secret + admin hash. Mode bits are checked because
// 0o644 on either file would expose the credential on a shared host.
func TestRunWritesLayout(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Run(dir, Options{AdminPassword: "pw"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, name := range []string{SecretFile, AdminPasswordFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 0600", name, got)
		}
	}
}

// TestRunSkipIfInitialized pins the idempotency `serve --init`
// depends on: a second Run against an already-initialized dir is a
// no-op and does not rotate the secret out from under previously
// issued JWTs.
func TestRunSkipIfInitialized(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Run(dir, Options{AdminPassword: "pw"}); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	first, err := os.ReadFile(filepath.Join(dir, SecretFile))
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if err := Run(dir, Options{AdminPassword: "pw", SkipIfInitialized: true}); err != nil {
		t.Fatalf("second Run (skip): %v", err)
	}
	second, err := os.ReadFile(filepath.Join(dir, SecretFile))
	if err != nil {
		t.Fatalf("read secret after second Run: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("second Run rewrote secret.hex; SkipIfInitialized should short-circuit")
	}
}

// TestRunRefusesDoubleInitWithoutForce pins the guard the operator
// relies on: re-running init without --force errors loudly instead
// of silently invalidating every JWT issued against the previous
// secret.
func TestRunRefusesDoubleInitWithoutForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Run(dir, Options{AdminPassword: "pw"}); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	err := Run(dir, Options{AdminPassword: "pw"})
	if err == nil {
		t.Fatal("expected error on re-init without --force")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("err = %v, want one mentioning 'refusing to overwrite'", err)
	}
}

// TestRunForceRotatesSecret pins the escape hatch: --force re-writes
// the secret (and admin hash). Operators take this path knowingly;
// the test just confirms the rotation actually happens.
func TestRunForceRotatesSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Run(dir, Options{AdminPassword: "pw"}); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	first, err := os.ReadFile(filepath.Join(dir, SecretFile))
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if err := Run(dir, Options{AdminPassword: "pw", Force: true}); err != nil {
		t.Fatalf("force Run: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(dir, SecretFile))
	if err != nil {
		t.Fatalf("read secret after force: %v", err)
	}
	if string(first) == string(second) {
		t.Error("--force did not rotate secret.hex")
	}
}

// TestRunMITMWritesCA pins the optional MITM CA generation. The
// .crt + .key land at the canonical names so `serve --data-dir`
// auto-enables MITM mode when both files are present.
func TestRunMITMWritesCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Run(dir, Options{AdminPassword: "pw", MITM: true}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, name := range []string{MITMCertFile, MITMKeyFile} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
		if !strings.Contains(string(raw), "BEGIN") {
			t.Errorf("%s does not look PEM-encoded", name)
		}
	}
}

// TestResolvePasswordFromEnv pins the BOUNCER_ADMIN_PASSWORD env
// fallback. This is the path `bouncer serve --init` relies on after
// the --admin-password flag was removed from serve — operators set
// the env (or accept the stdin prompt).
func TestResolvePasswordFromEnv(t *testing.T) {
	t.Setenv("BOUNCER_ADMIN_PASSWORD", "from-env")
	got, err := resolvePassword("")
	if err != nil {
		t.Fatalf("resolvePassword: %v", err)
	}
	if got != "from-env" {
		t.Errorf("got %q, want %q", got, "from-env")
	}
}

// TestResolvePasswordFlagBeatsEnv pins the precedence: an explicit
// flag value wins over the env var. Without this, a CI script that
// passes the flag would silently see a stale env override.
func TestResolvePasswordFlagBeatsEnv(t *testing.T) {
	t.Setenv("BOUNCER_ADMIN_PASSWORD", "env-loses")
	got, err := resolvePassword("flag-wins")
	if err != nil {
		t.Fatalf("resolvePassword: %v", err)
	}
	if got != "flag-wins" {
		t.Errorf("got %q, want %q", got, "flag-wins")
	}
}

// TestRunWithApisSkipsAlreadyInstalled pins that Run delegates
// --with-apis to the shared bundles.InstallRefs helper and that an
// already-vendored ref is skipped rather than re-installed. The
// pre-seeded source.yaml stands in for a bundle the operator
// installed in a previous boot; a real install would touch the
// network, so we don't drive it from a unit test.
func TestRunWithApisSkipsAlreadyInstalled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	// First Run lays out the layout (including apis/).
	if err := Run(dir, Options{AdminPassword: "pw"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Pre-seed an already-installed bundle so the second Run's
	// InstallRefs sees it and skips.
	bundleDir := filepath.Join(dir, APIsDir, "widgets")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	src := "ref: github.com/acme/widgets@v1.0.0\nresolved_sha: " +
		strings.Repeat("a", 40) + "\n"
	if err := os.WriteFile(filepath.Join(bundleDir, "source.yaml"), []byte(src), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	err := Run(dir, Options{
		AdminPassword:     "pw",
		SkipIfInitialized: true,
		Quiet:             true,
		WithApis:          []string{"github.com/acme/widgets@v2.0.0"},
	})
	if err != nil {
		t.Fatalf("Run with-apis: %v", err)
	}
	// The skip-bootstrap + skip-install path leaves the seeded
	// bundle dir intact and doesn't create new sibling dirs.
	entries, err := os.ReadDir(filepath.Join(dir, APIsDir))
	if err != nil {
		t.Fatalf("read apis: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "widgets" {
		t.Errorf("apis/ entries = %v, want only widgets", entries)
	}
}
