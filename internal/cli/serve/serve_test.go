package serve

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/cli/initcmd"
)

// testConfig returns a config populated with the production timeout
// defaults — every test that drives newHTTPServer wants this shape.
func testConfig() *config {
	return &config{
		Addr:                     ":0",
		InboundReadHeaderTimeout: defaultInboundReadHeaderTimeout,
		InboundReadTimeout:       defaultInboundReadTimeout,
		InboundWriteTimeout:      defaultInboundWriteTimeout,
		InboundIdleTimeout:       defaultInboundIdleTimeout,
		UpstreamCallTimeout:      defaultUpstreamCallTimeout,
	}
}

// TestNewHTTPServerSetsAllTimeouts pins an `http.Server`
// with any of these four timeouts at the zero value is a slowloris
// invitation, so any future refactor that drops one fails the test.
// The values themselves can change with operational tuning; the
// invariant is "all four are set."
func TestNewHTTPServerSetsAllTimeouts(t *testing.T) {
	srv := newHTTPServer(testConfig(), http.NotFoundHandler())
	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout is zero — slowloris on the request line")
	}
	if srv.ReadTimeout == 0 {
		t.Error("ReadTimeout is zero — slowloris on the body")
	}
	if srv.WriteTimeout == 0 {
		t.Error("WriteTimeout is zero — a hung client write blocks forever")
	}
	if srv.IdleTimeout == 0 {
		t.Error("IdleTimeout is zero — keep-alive connections leak")
	}
}

// TestSlowlorisClientGetsClosedByReadHeaderTimeout validates that the
// mechanism we depend on (`http.Server.ReadHeaderTimeout`) actually
// closes a connection that opens a TCP socket and writes nothing.
// Production timeouts are seconds; this test uses a sub-second budget
// to keep the test fast. The assertion shape is what matters: open a
// socket, send nothing, observe the server hang up.
func TestSlowlorisClientGetsClosedByReadHeaderTimeout(t *testing.T) {
	const headerTimeout = 100 * time.Millisecond
	srv := &http.Server{
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: headerTimeout,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Write nothing. Wait for the server to give up. The deadline is
	// generous (5×) so a slow CI box doesn't false-fail.
	if err := conn.SetReadDeadline(time.Now().Add(5 * headerTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	// The server closes the connection with no response bytes, so the
	// client reads either io.EOF or a "connection reset" — either is
	// the correct shape. A timeout on Read means the server kept the
	// connection open past the budget — that is the regression.
	if err == nil {
		t.Fatal("read returned no error; server kept the connection open")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("read timed out (server held the connection): %v", err)
	}
}

// TestLoadConfigDefaults pins the baseline: every flag defaulted, plus
// --dev-stub-secret to clear the secret-required guard. Defaults are
// the production timeouts.
func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig([]string{"--dev-stub-secret"})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Addr != ":8080" {
		t.Errorf("Addr = %q, want :8080", cfg.Addr)
	}
	if cfg.ApisDir != "./apis" {
		t.Errorf("ApisDir = %q, want ./apis", cfg.ApisDir)
	}
	if cfg.PoliciesDir != "./policies" {
		t.Errorf("PoliciesDir = %q, want ./policies", cfg.PoliciesDir)
	}
	if !cfg.DevStubSecret {
		t.Error("DevStubSecret = false, want true")
	}
	if cfg.InboundReadHeaderTimeout != defaultInboundReadHeaderTimeout {
		t.Errorf("InboundReadHeaderTimeout = %v, want %v", cfg.InboundReadHeaderTimeout, defaultInboundReadHeaderTimeout)
	}
	if cfg.UpstreamCallTimeout != defaultUpstreamCallTimeout {
		t.Errorf("UpstreamCallTimeout = %v, want %v", cfg.UpstreamCallTimeout, defaultUpstreamCallTimeout)
	}
}

// TestLoadConfigRequiresSecret pins the "no implicit dev stub"
// invariant: the previous main silently booted with a deterministic
// well-known key when --secret-hex was empty, which is a footgun for
// prod. loadConfig now refuses unless the operator explicitly opts in.
func TestLoadConfigRequiresSecret(t *testing.T) {
	_, err := loadConfig(nil)
	if err == nil {
		t.Fatal("loadConfig with no secret flags should error")
	}
	if !strings.Contains(err.Error(), "secret-hex") || !strings.Contains(err.Error(), "dev-stub-secret") {
		t.Errorf("error = %v, want one mentioning both flags", err)
	}
}

// TestLoadConfigRejectsBothSecretFlags pins that --secret-hex and
// --dev-stub-secret can't both be set: silently preferring one over
// the other would make a misconfigured prod deployment look fine.
func TestLoadConfigRejectsBothSecretFlags(t *testing.T) {
	hex64 := strings.Repeat("aa", 32)
	_, err := loadConfig([]string{"--secret-hex", hex64, "--dev-stub-secret"})
	if err == nil {
		t.Fatal("loadConfig with both secret flags should error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %v, want one about mutual exclusion", err)
	}
}

// TestLoadConfigReadsEnv pins the BOUNCER_* env binding so an
// operator can inject the secret out-of-band (e.g. from a secret
// manager) without putting it on argv where ps would log it.
func TestLoadConfigReadsEnv(t *testing.T) {
	hex64 := strings.Repeat("bb", 32)
	t.Setenv("BOUNCER_SECRET_HEX", hex64)
	t.Setenv("BOUNCER_ADDR", ":9090")
	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.SecretHex != hex64 {
		t.Errorf("SecretHex from env = %q, want %q", cfg.SecretHex, hex64)
	}
	if cfg.Addr != ":9090" {
		t.Errorf("Addr from env = %q, want :9090", cfg.Addr)
	}
}

// TestLoadConfigMITMRequiresCAPair pins two MITM resolutions:
//
//   - Explicit --mitm without cert/key paths is a misconfig and must
//     refuse to boot.
//   - Default-on --mitm with no CA paths silently disables (so a
//     bare `bouncer serve --dev-stub-secret …` without a data-dir
//     just runs as a direct path-prefix proxy).
//   - --mitm-ca-cert/key paths without --mitm activate MITM (the
//     paths are the user's signal; we don't require the redundant
//     --mitm flag in default-on world).
func TestLoadConfigMITMRequiresCAPair(t *testing.T) {
	_, err := loadConfig([]string{"--dev-stub-secret", "--mitm"})
	if err == nil || !strings.Contains(err.Error(), "mitm-ca") {
		t.Fatalf("explicit --mitm without paths: err = %v, want one mentioning mitm-ca", err)
	}
	cfg, err := loadConfig([]string{"--dev-stub-secret"})
	if err != nil {
		t.Fatalf("default --mitm with no paths: err = %v, want nil", err)
	}
	if cfg.MITM {
		t.Fatalf("default --mitm with no paths: MITM = true, want false (silent fallback)")
	}
	cfg, err = loadConfig([]string{"--dev-stub-secret", "--mitm-ca-cert", "/x", "--mitm-ca-key", "/y"})
	if err != nil {
		t.Fatalf("paths set, --mitm default: err = %v, want nil", err)
	}
	if !cfg.MITM {
		t.Fatalf("paths set, --mitm default: MITM = false, want true")
	}
}

// TestLoadConfigTrafficStoreValidation pins the asymmetric pairing on
// --traffic-store=sqlite: it must be paired with --traffic-db, and
// --traffic-db without sqlite is a misconfig.
func TestLoadConfigTrafficStoreValidation(t *testing.T) {
	_, err := loadConfig([]string{"--dev-stub-secret", "--traffic-store", "sqlite"})
	if err == nil || !strings.Contains(err.Error(), "traffic-db") {
		t.Fatalf("err = %v, want one mentioning traffic-db", err)
	}
	_, err = loadConfig([]string{"--dev-stub-secret", "--traffic-db", "/tmp/x.db"})
	if err == nil || !strings.Contains(err.Error(), "without --traffic-store=sqlite") {
		t.Fatalf("err = %v, want one about traffic-db set without sqlite", err)
	}
	_, err = loadConfig([]string{"--dev-stub-secret", "--traffic-store", "weird"})
	if err == nil || !strings.Contains(err.Error(), "invalid traffic store") {
		t.Fatalf("err = %v, want one rejecting unknown store", err)
	}
}

// TestLoadConfigTrafficDefaults sanity-checks the default mode is
// `none` — no recorder, no /_api/traffic routes, zero overhead.
func TestLoadConfigTrafficDefaults(t *testing.T) {
	cfg, err := loadConfig([]string{"--dev-stub-secret"})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.TrafficStore != "none" {
		t.Errorf("TrafficStore = %q, want none", cfg.TrafficStore)
	}
	if cfg.TrafficBudget != defaultTrafficBudget {
		t.Errorf("TrafficBudget = %d, want %d", cfg.TrafficBudget, defaultTrafficBudget)
	}
	if cfg.TrafficMaxAge != defaultTrafficMaxAge {
		t.Errorf("TrafficMaxAge = %v, want %v", cfg.TrafficMaxAge, defaultTrafficMaxAge)
	}
	if cfg.TrafficMaxPinned != defaultTrafficMaxPinned {
		t.Errorf("TrafficMaxPinned = %d, want %d", cfg.TrafficMaxPinned, defaultTrafficMaxPinned)
	}
}

// TestLoadConfigStoreDefaults pins the default store kinds so a
// fresh deployment behaves the same as before the unified-store
// refactor: file-backed policies, in-memory proposals, no traffic
// capture.
func TestLoadConfigStoreDefaults(t *testing.T) {
	cfg, err := loadConfig([]string{"--dev-stub-secret"})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.PoliciesStore != "file" {
		t.Errorf("PoliciesStore = %q, want file", cfg.PoliciesStore)
	}
	if cfg.ProposalsStore != "memory" {
		t.Errorf("ProposalsStore = %q, want memory", cfg.ProposalsStore)
	}
}

// TestLoadConfigStoreDBFallback pins the unified-sqlite shortcut:
// --store-db is enough to satisfy a domain set to sqlite without
// its own --*-db, so the operator can put all three tables in one
// file with a single path.
func TestLoadConfigStoreDBFallback(t *testing.T) {
	cfg, err := loadConfig([]string{
		"--dev-stub-secret",
		"--traffic-store", "sqlite",
		"--policies-store", "sqlite",
		"--proposals-store", "sqlite",
		"--store-db", "/tmp/all.db",
	})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.StoreDB != "/tmp/all.db" {
		t.Errorf("StoreDB = %q, want /tmp/all.db", cfg.StoreDB)
	}
}

// TestLoadConfigPoliciesStoreSqliteRequiresPath pins the validation:
// asking for sqlite without a path (and without the shared --store-db
// fallback) is rejected at boot.
func TestLoadConfigPoliciesStoreSqliteRequiresPath(t *testing.T) {
	_, err := loadConfig([]string{
		"--dev-stub-secret",
		"--policies-store", "sqlite",
	})
	if err == nil {
		t.Fatal("expected validation error for sqlite without path")
	}
	if !strings.Contains(err.Error(), "policies-db") {
		t.Errorf("err = %v, want one mentioning policies-db", err)
	}
}

// TestLoadConfigTrafficMaxPinnedOverride pins that the flag plumbs
// through to config so the per-deployment cap actually reaches the
// store at boot.
func TestLoadConfigTrafficMaxPinnedOverride(t *testing.T) {
	cfg, err := loadConfig([]string{"--dev-stub-secret", "--traffic-max-pinned", "42"})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.TrafficMaxPinned != 42 {
		t.Errorf("TrafficMaxPinned = %d, want 42", cfg.TrafficMaxPinned)
	}
}

// TestLoadConfigFlagOverridesEnv pins the precedence rule: explicit
// flags win over env, mirroring viper's documented behaviour. Without
// this an operator setting both ends up confused about which wins.
func TestLoadConfigFlagOverridesEnv(t *testing.T) {
	t.Setenv("BOUNCER_ADDR", ":9090")
	cfg, err := loadConfig([]string{"--addr", ":7070", "--dev-stub-secret"})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Addr != ":7070" {
		t.Errorf("Addr = %q, want :7070 (flag should win over env)", cfg.Addr)
	}
}

// TestDeriveSecretDevStub pins the dev-stub byte pattern: the previous
// implementation set every byte to 0xAA, and any caller relying on a
// specific secret across local restarts would break if that flipped.
func TestDeriveSecretDevStub(t *testing.T) {
	got, err := deriveSecret(&config{DevStubSecret: true})
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	for i, b := range got {
		if b != 0xAA {
			t.Fatalf("byte[%d] = %#x, want 0xAA", i, b)
		}
	}
}

// TestDeriveSecretFromHex pins the hex path on a non-stub config.
func TestDeriveSecretFromHex(t *testing.T) {
	hex64 := strings.Repeat("cd", 32)
	got, err := deriveSecret(&config{SecretHex: hex64})
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	for i, b := range got {
		if b != 0xCD {
			t.Fatalf("byte[%d] = %#x, want 0xCD", i, b)
		}
	}
}

// TestDeriveSecretRejectsWrongLength: an operator pasting a 16-byte
// hex string should get a clear error, not a half-zeroed key.
func TestDeriveSecretRejectsWrongLength(t *testing.T) {
	_, err := deriveSecret(&config{SecretHex: strings.Repeat("aa", 16)})
	if err == nil {
		t.Fatal("expected error for 16-byte secret")
	}
}

// TestLoadConfigInitDefaultsDataDirToCwd pins the quickstart UX:
// `bouncer serve --init` with no --data-dir bootstraps cwd. The
// operator's intent ("init for me") is enough to commit to cwd as
// the target, even though it's not yet an initialized layout.
func TestLoadConfigInitDefaultsDataDirToCwd(t *testing.T) {
	dir := t.TempDir()
	chdirForTest(t, dir)

	cfg, err := loadConfig([]string{"--init", "--admin-password", "pw"})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.DataDir != "." {
		t.Errorf("DataDir = %q, want \".\" (cwd default under --init)", cfg.DataDir)
	}
	if !initcmd.IsInitialized(dir) {
		t.Error("--init did not bootstrap cwd")
	}
}

// TestLoadConfigInitBootstrapsAndIsIdempotent drives the
// `serve --init --data-dir <fresh>` flow against a temp dir, then
// re-runs loadConfig pointed at the same dir to verify the
// already-initialized branch short-circuits without rewriting the
// secret. The second invocation reading the same secret.hex is the
// proof — a non-idempotent --init would have written a fresh one.
func TestLoadConfigInitBootstrapsAndIsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	// No --dev-stub-secret: the freshly-written secret.hex is what
	// we want loadConfig to pick up via applyDataDir; mixing in the
	// stub would trip the mutually-exclusive check.
	args := []string{"--init", "--data-dir", dir, "--admin-password", "pw"}

	cfg, err := loadConfig(args)
	if err != nil {
		t.Fatalf("first init: %v", err)
	}
	if !initcmd.IsInitialized(dir) {
		t.Fatal("first init did not bootstrap dir")
	}
	first, err := os.ReadFile(filepath.Join(dir, initcmd.SecretFile))
	if err != nil {
		t.Fatalf("read secret after first init: %v", err)
	}
	if cfg.SecretHex == "" {
		t.Fatal("cfg.SecretHex empty after init: applyDataDir didn't pick up the freshly written file")
	}

	if _, err := loadConfig(args); err != nil {
		t.Fatalf("second init: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(dir, initcmd.SecretFile))
	if err != nil {
		t.Fatalf("read secret after second init: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("second --init rewrote secret.hex; --init must be idempotent on an initialized dir")
	}
}

// chdirForTest swaps cwd for the duration of t. Lets the cwd-default
// branch in loadConfig be exercised from a deterministic dir (the
// alternative — running tests *inside* a real data dir — would be
// inherited and brittle).
func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

// TestLoadConfigDefaultsDataDirToCwdWhenInitialized pins the
// "drop into your data dir and just run bouncer serve" UX. Cwd
// holds a complete `bouncer init` layout, no --data-dir flag, no
// $BOUNCER_DATA_DIR — DataDir resolves to "." and applyDataDir
// then pulls the per-file flags from there.
func TestLoadConfigDefaultsDataDirToCwdWhenInitialized(t *testing.T) {
	dir := t.TempDir()
	if err := initcmd.Bootstrap(dir, initcmd.Options{AdminPassword: "pw"}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	chdirForTest(t, dir)

	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.DataDir != "." {
		t.Errorf("DataDir = %q, want \".\" (cwd auto-detect)", cfg.DataDir)
	}
	if cfg.SecretHex == "" {
		t.Error("SecretHex empty: applyDataDir did not run after cwd auto-detect")
	}
}

// TestLoadConfigDoesNotDefaultDataDirWhenCwdEmpty pins the
// conservative branch: an empty cwd is not silently consumed.
// loadConfig must error on the missing-secret check (same behaviour
// as before the cwd-default change), not pick up some other dir.
func TestLoadConfigDoesNotDefaultDataDirWhenCwdEmpty(t *testing.T) {
	chdirForTest(t, t.TempDir())

	_, err := loadConfig(nil)
	if err == nil {
		t.Fatal("loadConfig: want missing-secret error, got nil")
	}
	if !strings.Contains(err.Error(), "secret-hex") && !strings.Contains(err.Error(), "secret") {
		t.Errorf("err = %v, want missing-secret message (cwd should NOT be auto-defaulted when not initialized)", err)
	}
}

// TestLoadConfigExplicitDataDirOverridesCwd pins the precedence: an
// explicit --data-dir flag beats the cwd auto-default even when cwd
// is itself an initialized dir. Without this, an operator who
// happens to be inside one data dir but pointed at another via the
// flag would silently pick up the wrong layout.
func TestLoadConfigExplicitDataDirOverridesCwd(t *testing.T) {
	cwd := t.TempDir()
	if err := initcmd.Bootstrap(cwd, initcmd.Options{AdminPassword: "pw"}); err != nil {
		t.Fatalf("bootstrap cwd: %v", err)
	}
	chdirForTest(t, cwd)

	other := t.TempDir()
	if err := initcmd.Bootstrap(other, initcmd.Options{AdminPassword: "pw"}); err != nil {
		t.Fatalf("bootstrap other: %v", err)
	}

	cfg, err := loadConfig([]string{"--data-dir", other})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.DataDir != other {
		t.Errorf("DataDir = %q, want %q (explicit flag must win over cwd default)", cfg.DataDir, other)
	}
}
