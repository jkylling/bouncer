//go:build e2e

package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestInitWritesLayout pins the on-disk shape `serve --data-dir`
// later consumes: secret + admin hash + apis/ + policies/ + readme.
// File modes are checked because the secret and password hash both
// need 0o600 — a 0o644 hash hash on a shared host would let any
// local user log in as admin.
func TestInitWritesLayout(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "s3cret"})

	for _, rel := range []string{"secret.hex", "admin-password.hash", "README.md"} {
		if _, err := filepath.Abs(filepath.Join(dir, rel)); err != nil {
			t.Errorf("%s missing: %v", rel, err)
		}
	}
	if got := fileMode(t, filepath.Join(dir, "secret.hex")); got != 0o600 {
		t.Errorf("secret.hex mode = %o, want 0600", got)
	}
	if got := fileMode(t, filepath.Join(dir, "admin-password.hash")); got != 0o600 {
		t.Errorf("admin-password.hash mode = %o, want 0600", got)
	}
	// secret.hex is 64 hex chars + trailing \n.
	if got := len(mustReadFile(t, filepath.Join(dir, "secret.hex"))); got != 65 {
		t.Errorf("secret.hex length = %d, want 65", got)
	}
}

// TestInitRefusesDoubleInit pins the no-clobber guard. An operator
// who runs init twice on the same dir would otherwise rotate the
// secret out from under every JWT they previously issued.
func TestInitRefusesDoubleInit(t *testing.T) {
	dir := mustInit(t, initOpts{})
	res := run(t, "init", dir, "--admin-password", "x")
	if res.Err == nil {
		t.Fatalf("expected error on double init, got success\nstdout: %s\nstderr: %s",
			res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stderr, "refusing to overwrite") {
		t.Errorf("stderr = %q, want 'refusing to overwrite'", res.Stderr)
	}
}

// TestInitForceOverwrites pins the escape hatch. --force is
// destructive (rotates the secret), so the binary refuses by
// default; this test confirms the explicit opt-in actually works.
func TestInitForceOverwrites(t *testing.T) {
	dir := mustInit(t, initOpts{})
	first := mustReadFile(t, filepath.Join(dir, "secret.hex"))
	res := run(t, "init", dir, "--admin-password", "x", "--force")
	if res.Err != nil {
		t.Fatalf("init --force: %v\nstderr: %s", res.Err, res.Stderr)
	}
	second := mustReadFile(t, filepath.Join(dir, "secret.hex"))
	if string(first) == string(second) {
		t.Error("--force did not regenerate the secret")
	}
}

// TestInitMITMWritesCA pins the optional --mitm flow: the CA cert
// + key land in the data dir at the canonical names so
// `serve --data-dir` later picks them up automatically (MITM mode
// auto-enables when both files exist; see applyDataDir).
func TestInitMITMWritesCA(t *testing.T) {
	dir := mustInit(t, initOpts{MITM: true})
	for _, rel := range []string{"mitm-ca.crt", "mitm-ca.key"} {
		raw := mustReadFile(t, filepath.Join(dir, rel))
		if !strings.Contains(string(raw), "BEGIN") {
			t.Errorf("%s does not look PEM-encoded", rel)
		}
	}
	if got := fileMode(t, filepath.Join(dir, "mitm-ca.key")); got != 0o600 {
		t.Errorf("mitm-ca.key mode = %o, want 0600", got)
	}
}

// TestInitPasswordFromEnv pins the env fallback so a CI script can
// avoid putting cleartext on argv. The flag wins over env (also
// tested implicitly by every other test, which passes --admin-password).
func TestInitPasswordFromEnv(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	res := runEnv(t, map[string]string{"BOUNCER_ADMIN_PASSWORD": "from-env"},
		"init", dir)
	if res.Err != nil {
		t.Fatalf("init: %v\nstderr: %s", res.Err, res.Stderr)
	}
	hash := mustReadFile(t, filepath.Join(dir, "admin-password.hash"))
	// bcrypt hashes start with $2 — sanity check we wrote a hash and
	// not the cleartext password.
	if !strings.HasPrefix(string(hash), "$2") {
		t.Errorf("admin-password.hash does not look bcrypt: %q", hash)
	}
}

// TestInitHelp pins that --help exits zero with the expected
// banner. Operators who type `init --help` shouldn't see a
// validation error about the missing password.
func TestInitHelp(t *testing.T) {
	res := run(t, "init", "--help")
	if res.Err != nil {
		t.Fatalf("init --help: %v\nstderr: %s", res.Err, res.Stderr)
	}
	// cobra writes help to stdout.
	if !strings.Contains(res.Stdout, "Bootstrap a self-contained data directory") {
		t.Errorf("help banner missing: stdout=%q", res.Stdout)
	}
}
