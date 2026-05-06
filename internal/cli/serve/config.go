package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/cli/initcmd"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/observability"
)

// defaultBundleBranch is the version `--with-apis github.com/x/y`
// (no @ref) installs from. GitHub's commits API resolves it to
// whatever main currently points at; an `apis upgrade` later picks
// up the new SHA without changing the recorded ref.
const defaultBundleBranch = "main"

// Default HTTP timeouts. Conservative defaults for a JSON
// control-plane proxy; non-zero so the slowloris / hung-upstream
// surface that MaxRequestBodyBytes alone does not cover stays
// closed. Operators tune via the matching flags.
const (
	defaultInboundReadHeaderTimeout = 5 * time.Second
	defaultInboundReadTimeout       = 30 * time.Second
	defaultInboundWriteTimeout      = 60 * time.Second
	defaultInboundIdleTimeout       = 120 * time.Second
	defaultUpstreamCallTimeout      = 30 * time.Second
	defaultTrafficBudget            = 16 * 1024 * 1024
	defaultTrafficMaxAge            = 24 * time.Hour
	defaultTrafficMaxPinned         = 1000
)

// config is the resolved set of knobs the binary needs at boot. It is
// populated from flags + env via viper.Unmarshal — the mapstructure
// tags pin each field to the matching flag/env key. Tests construct a
// config literal to drive `newHTTPServer` without parsing flags.
type config struct {
	Addr        string `mapstructure:"addr"`
	ApisDir     string `mapstructure:"apis-dir"`
	PoliciesDir string `mapstructure:"policies-dir"`

	// SecretHex is the 64-char hex form of the 32-byte server secret.
	// Mutually exclusive with DevStubSecret.
	SecretHex string `mapstructure:"secret-hex"`

	// DevStubSecret picks the deterministic `0xAA × 32` secret. Local
	// dev only; explicit flag so an empty --secret-hex doesn't
	// silently boot with the stub.
	DevStubSecret bool `mapstructure:"dev-stub-secret"`

	InboundReadHeaderTimeout time.Duration `mapstructure:"inbound-read-header-timeout"`
	InboundReadTimeout       time.Duration `mapstructure:"inbound-read-timeout"`
	InboundWriteTimeout      time.Duration `mapstructure:"inbound-write-timeout"`
	InboundIdleTimeout       time.Duration `mapstructure:"inbound-idle-timeout"`
	UpstreamCallTimeout      time.Duration `mapstructure:"upstream-call-timeout"`
	RefreshTTL               time.Duration `mapstructure:"refresh-ttl"`

	// Observability knobs. LogLevel/LogFormat shape the slog output;
	// OTelExporter selects how spans leave the process (default
	// `none` keeps the tracer no-op so the binary pays nothing for
	// otel unless an operator opts in). Typed fields parse themselves
	// at config-load time via TextUnmarshaler so validate() doesn't
	// reparse and setupObservability becomes a pass-through.
	LogLevel     slog.Level              `mapstructure:"log-level"`
	LogFormat    observability.LogFormat `mapstructure:"log-format"`
	OTelExporter observability.Exporter  `mapstructure:"otel-exporter"`
	OTelService  string                  `mapstructure:"otel-service-name"`
	OTelVersion  string                  `mapstructure:"otel-service-version"`

	// MITM mode adds CONNECT-and-TLS-terminate to the listener so an
	// unmodified HTTPS_PROXY-aware client can be pointed at the proxy.
	// MITMCAPath / MITMCAKey are required iff MITM is true; the
	// validate step enforces that pairing.
	MITM       bool   `mapstructure:"mitm"`
	MITMCAPath string `mapstructure:"mitm-ca-cert"`
	MITMCAKey  string `mapstructure:"mitm-ca-key"`

	// Traffic-viewer storage. `none` (default) leaves the recorder
	// unwired and the /_api/traffic routes unmounted — no overhead.
	// `memory` is in-process (lost on restart). `sqlite` writes to
	// TrafficDB. The byte and age budgets cap retention.
	TrafficStore     TrafficStoreKind `mapstructure:"traffic-store"`
	TrafficDB        string           `mapstructure:"traffic-db"`
	TrafficBudget    int              `mapstructure:"traffic-budget"`
	TrafficMaxAge    time.Duration    `mapstructure:"traffic-max-age"`
	TrafficMaxPinned int              `mapstructure:"traffic-max-pinned"`

	// Policies storage. PoliciesStore picks the backend kind:
	//   - "file": YAML files under --policies-dir (current default).
	//   - "memory": in-process map, lost on restart.
	//   - "sqlite": one row per (api, name) under --policies-db.
	// Defaults to "file" so existing deployments don't change shape.
	PoliciesStore PoliciesStoreKind `mapstructure:"policies-store"`
	PoliciesDB    string            `mapstructure:"policies-db"`

	// PoliciesReadOnly disables every mutating control-plane endpoint
	// (POST/PUT/DELETE on /_api/policies and the proposal-approve flow
	// that ultimately calls Service.Replace). The list / get / dryRun
	// endpoints and the read-only UI keep working. Useful for
	// production deployments that want the policies viewer without
	// risking accidental edits from a shared admin host.
	PoliciesReadOnly bool `mapstructure:"policies-readonly"`

	// Proposals storage. ProposalsStore picks the backend kind:
	//   - "memory": in-process map, lost on restart (current default).
	//   - "sqlite": one row per proposal under --proposals-db.
	ProposalsStore ProposalsStoreKind `mapstructure:"proposals-store"`
	ProposalsDB    string             `mapstructure:"proposals-db"`

	// StoreDB is the convenience shortcut: any domain whose own
	// --*-db flag is empty falls back to this when its backend is
	// sqlite. Setting --traffic-store=sqlite and --policies-store=
	// sqlite alongside --store-db=PATH gives the "one sqlite file
	// for everything" deployment with three tables in one DB.
	StoreDB string `mapstructure:"store-db"`

	// AdminPasswordHash is the bcrypt hash POST /_api/admin/login
	// compares against. Mutually exclusive with AdminPassword (which
	// hashes its cleartext at boot for dev convenience). Empty leaves
	// the login endpoint wired but serving 503; bootstrap then runs
	// through `cmd/issue-token --admin`.
	AdminPasswordHash string `mapstructure:"admin-password-hash"`

	// AdminPassword is the cleartext form, hashed at boot. Dev-only:
	// printed-cmdline secrets are unsafe in production, so the flag
	// log-warns when it's set. Production deployments should pass
	// AdminPasswordHash via env (or the env-mounted hash file).
	AdminPassword string `mapstructure:"admin-password"`

	// DataDir, when non-empty, is a directory laid out by
	// `bouncer init` — secret.hex, admin-password.hash, store.db,
	// apis/, policies/, optional mitm-ca.{crt,key}. After flag
	// parsing we read each unset field from the corresponding file
	// so a clean serve invocation is just `--data-dir <dir>`.
	DataDir string `mapstructure:"data-dir"`

	// Init, when true, bootstraps DataDir using the same logic as
	// `bouncer init <dir>` if it isn't already initialized. Idempotent
	// when DataDir already holds a secret + admin-password hash —
	// otherwise the boot fails so an operator can't accidentally
	// rewrite a populated dir. Combined with --with-apis this turns
	// the production quickstart into a single command.
	Init bool `mapstructure:"init"`

	// WithApis is a list of bundle refs to install before serve
	// starts. Each ref runs through the same install path as
	// `bouncer apis add <ref>`, including allowlist enforcement; an
	// already-installed ref (regardless of SHA) is skipped with a log
	// line so re-running `serve --init --with-apis ...` is safe.
	WithApis []string `mapstructure:"with-apis"`
}

// serveLong is the prose description cobra prints under `serve --help`.
const serveLong = `Run the policy-enforcing HTTP proxy.

Loads API YAML from --apis-dir and policy YAML from --policies-dir,
derives a server keypair from --secret-hex (or --dev-stub-secret for
local dev), and listens on --addr. The two directories are split
because the API set is roughly stable per upstream vendor while
policies are user-owned and may live elsewhere (e.g. mounted in from
a control-plane volume). Inbound requests must present a proxy JWT
in the Authorization header; issue one via the bundled UI at
/_admin/, the HTTP API at POST /_api/issue/tokens, or cmd/issue-token.

Examples:

  # Production shape: bouncer init creates the data dir, then serve
  # picks up the secret, admin password, installed APIs, and policies
  # from inside it.
  bouncer init /var/lib/bouncer
  bouncer serve --addr :443 --data-dir /var/lib/bouncer

  # Local dev: dev stub secret, test-fixture APIs/policies, default port.
  bouncer serve --dev-stub-secret \
      --apis-dir ./testdata/apis --policies-dir ./testdata/policies

  # Generate a fresh secret once, persist for the lifetime of issued tokens.
  openssl rand -hex 32 > /etc/bouncer/secret.hex

  # Local debug: pretty-print every span to stdout.
  bouncer serve --dev-stub-secret --otel-exporter stdout --log-format json

  # Ship spans to an OTLP/HTTP collector. The exporter honours the
  # standard OTEL_EXPORTER_OTLP_ENDPOINT/HEADERS/COMPRESSION env vars.
  OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 \
      bouncer serve --dev-stub-secret --otel-exporter otlphttp

  # MITM mode: the listener accepts plaintext HTTP CONNECTs and TLS-
  # terminates with on-the-fly certs signed by the supplied CA. An
  # unmodified Google API client points at the proxy via HTTPS_PROXY
  # and the CA cert installed in its trust store.
  bouncer serve --data-dir /var/lib/bouncer \
      --mitm --mitm-ca-cert /var/lib/bouncer/mitm-ca.crt \
      --mitm-ca-key /var/lib/bouncer/mitm-ca.key

  # Traffic viewer enabled with on-disk persistence. Recorded events
  # show up at GET /_api/traffic on the same listener.
  bouncer serve --data-dir /var/lib/bouncer \
      --traffic-store sqlite --traffic-db /var/lib/bouncer/traffic.db

After it is up, point clients at the upstream paths declared in
your config (e.g. /gmail/v1/users/me/profile) with a JWT in the
Authorization: Bearer header. In --mitm mode, point the client at
the real upstream URL (https://gmail.googleapis.com/...) with
HTTPS_PROXY set to the proxy's address.

Environment:
  Every flag has a BOUNCER_<UPPER_SNAKE> env equivalent —
  e.g. --secret-hex pairs with BOUNCER_SECRET_HEX. The OTLP
  exporter additionally honours the standard OTEL_EXPORTER_OTLP_*
  env vars for endpoint/headers/compression configuration.`

// bindServeFlags installs every serve flag onto fs. Shared between
// loadConfig (test entry) and Command's RunE so the schema lives in
// one place.
func bindServeFlags(fs *pflag.FlagSet) {
	fs.String("addr", ":8080", "listen address")
	fs.String("apis-dir", "./apis", "directory of API YAML specs and installed bundles. Top-level *.yaml are loose specs; immediate subdirectories with a bouncer.yaml are bundles installed via `bouncer apis add`. Overridden by <data-dir>/apis when --data-dir is set and this flag was not.")
	fs.String("policies-dir", "./policies", "directory of policy YAML specs (operator-managed; the bundled config/ ships API specs only)")
	fs.String("secret-hex", "", "32-byte server secret as 64 hex chars (or BOUNCER_SECRET_HEX)")
	fs.Bool("dev-stub-secret", false, "use deterministic dev stub secret (NEVER use in prod)")
	fs.Duration("inbound-read-header-timeout", defaultInboundReadHeaderTimeout, "max time to read inbound request line + headers")
	fs.Duration("inbound-read-timeout", defaultInboundReadTimeout, "max time from accept to inbound body fully read")
	fs.Duration("inbound-write-timeout", defaultInboundWriteTimeout, "max time spent writing the inbound response")
	fs.Duration("inbound-idle-timeout", defaultInboundIdleTimeout, "keep-alive idle window between inbound requests")
	fs.Duration("upstream-call-timeout", defaultUpstreamCallTimeout, "per-call timeout for every upstream HTTP request")
	fs.Duration("refresh-ttl", 0, "exp claim on refresh JWTs issued by /token rotation; 0 = no expiry")
	fs.String("log-level", "info", "log level (debug|info|warn|error)")
	fs.String("log-format", "text", "log format (text|json)")
	fs.String("otel-exporter", "none", "otel trace exporter (none|stdout|otlphttp); otlphttp honours OTEL_EXPORTER_OTLP_* env")
	fs.String("otel-service-name", "bouncer", "service.name attribute attached to spans")
	fs.String("otel-service-version", "", "service.version attribute attached to spans")
	fs.Bool("mitm", true, "run the listener as a TLS-terminating forward proxy (HTTPS_PROXY mode); on by default. Falls back to off when no MITM CA is available; --mitm=false disables explicitly.")
	fs.String("mitm-ca-cert", "", "path to the PEM-encoded MITM CA certificate (must be IsCA + KeyUsageCertSign)")
	fs.String("mitm-ca-key", "", "path to the PEM-encoded MITM CA private key")
	fs.String("traffic-store", "none", "traffic-viewer storage backend (none|memory|sqlite); none disables capture and the query API")
	fs.String("traffic-db", "", "path to the sqlite DB file when --traffic-store=sqlite (falls back to --store-db)")
	fs.Int("traffic-budget", defaultTrafficBudget, "byte budget for non-pinned traffic events; older rows evict past this")
	fs.Duration("traffic-max-age", defaultTrafficMaxAge, "max age of non-pinned traffic events; older rows evict regardless of byte pressure")
	fs.Int("traffic-max-pinned", defaultTrafficMaxPinned, "hard cap on pinned traffic events; pin requests past this return 409")
	fs.String("policies-store", "file", "policies storage backend (file|memory|sqlite); file uses --policies-dir")
	fs.String("policies-db", "", "path to the sqlite DB file when --policies-store=sqlite (falls back to --store-db)")
	fs.Bool("policies-readonly", false, "reject every mutating policy endpoint (and proposal approval); the policies viewer stays available")
	fs.String("proposals-store", "memory", "proposals storage backend (memory|sqlite); memory loses drafts on restart")
	fs.String("proposals-db", "", "path to the sqlite DB file when --proposals-store=sqlite (falls back to --store-db)")
	fs.String("store-db", "", "shared sqlite DB path; any domain set to sqlite without its own --*-db falls back to this so all three can live in one file")
	fs.String("admin-password-hash", "", "bcrypt hash for the /_api/admin/login flow; generate via `htpasswd -bnBC 12 \"\" <pw> | tr -d ':\\n'`")
	fs.String("admin-password", "", "cleartext admin password; hashed at boot. DEV ONLY — production deployments must use --admin-password-hash via env so the cleartext is not visible in `ps`.")
	fs.String("data-dir", "", "directory created by `bouncer init`. Defaults to the current working directory when it looks like an initialized data dir (secret.hex + admin-password.hash present). When set, defaults --secret-hex, --apis-dir, --policies-dir, --admin-password-hash, --store-db, and --mitm-ca-cert/key from the layout files (any explicit flag overrides).")
	fs.Bool("init", false, "bootstrap --data-dir if it isn't already initialized (equivalent to running `bouncer init <data-dir>` first). No-op when the dir already has a secret + admin-password hash.")
	fs.StringSlice("with-apis", nil, "install one or more bundle refs before serving (e.g. github.com/jkylling/bouncer-gws@v0.1.0, or just github.com/jkylling/bouncer-gws to track main). Already-installed refs are skipped; repeat the flag for several bundles.")
}

// buildConfig reads viper + post-parse setup against an already-bound
// fs. Used by both loadConfig (tests, parses argv first) and
// Command's RunE (cobra has already parsed). Side effects include
// bootstrap and bundle install when --init / --with-apis are set, so
// callers should treat this as the single boot-time entry rather
// than a pure parser.
func buildConfig(fs *pflag.FlagSet) (*config, error) {
	v := viper.New()
	if err := v.BindPFlags(fs); err != nil {
		return nil, fmt.Errorf("bind flags: %w", err)
	}
	v.SetEnvPrefix("BOUNCER")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	cfg := &config{}
	if err := v.Unmarshal(cfg, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		// Default viper hooks we'd otherwise lose by overriding.
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		// Lets typed fields (slog.Level, observability.LogFormat,
		// observability.Exporter) parse via their UnmarshalText.
		mapstructure.TextUnmarshallerHookFunc(),
	))); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	defaultDataDirFromCwd(cfg)
	if err := bootstrapIfRequested(cfg); err != nil {
		return nil, err
	}
	if err := installRequestedBundles(cfg, fs); err != nil {
		return nil, err
	}
	if err := applyDataDir(cfg, fs); err != nil {
		return nil, err
	}
	resolveMITMDefault(cfg, fs)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadConfig is the test entry: parses argv against a fresh flag set
// and runs buildConfig. Production calls flow through Command's RunE
// (which has its flag set already parsed by cobra).
func loadConfig(args []string) (*config, error) {
	fs := pflag.NewFlagSet("bouncer", pflag.ContinueOnError)
	bindServeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return buildConfig(fs)
}

// bootstrapIfRequested runs `initcmd.Bootstrap` against --data-dir
// when --init is set and the dir is not already initialized. The
// idempotent-skip is what makes `serve --init --with-apis ...` safe
// to re-run on every restart; a blanket re-init would invalidate
// every JWT issued against the previous secret.
func bootstrapIfRequested(cfg *config) error {
	if !cfg.Init {
		return nil
	}
	if cfg.DataDir == "" {
		return errors.New("--init requires --data-dir")
	}
	// --admin-password under --init means "use this for the bootstrap";
	// after bootstrap admin-password.hash is on disk and applyDataDir
	// will pick it up. Clear the cleartext unconditionally so the
	// idempotent-skip path also avoids the "password + hash both set"
	// mutex downstream.
	pw := cfg.AdminPassword
	cfg.AdminPassword = ""
	if initcmd.IsInitialized(cfg.DataDir) {
		return nil
	}
	// MITM CA generation tracks the serve --mitm flag — when MITM is
	// enabled (default), init writes the cert + key so serve picks
	// them up via the data-dir auto-derive. AdminPassword falls back
	// to env / stdin via Bootstrap's resolvePassword.
	return initcmd.Bootstrap(cfg.DataDir, initcmd.Options{
		AdminPassword: pw,
		MITM:          cfg.MITM,
	})
}

// installRequestedBundles runs each --with-apis ref through the same
// install path as `bouncer apis add`. Refs already vendored at any
// SHA are skipped — re-running `serve --with-apis foo` after a
// successful first run is a no-op rather than an error.
func installRequestedBundles(cfg *config, fs *pflag.FlagSet) error {
	if len(cfg.WithApis) == 0 {
		return nil
	}
	root := installRoot(cfg)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("apis dir: %w", err)
	}
	fetcher := bundles.NewFetcher(bundles.FetcherOpts{Token: os.Getenv("GITHUB_TOKEN")})
	for _, raw := range cfg.WithApis {
		ref, err := bundles.ParseRef(raw)
		if err != nil {
			return fmt.Errorf("--with-apis %q: %w", raw, err)
		}
		if ref.Version == "" {
			// Refs without a version track the upstream default
			// branch. The recorded source.yaml#ref keeps "main" so a
			// later `apis upgrade` re-resolves it the same way.
			ref.Version = defaultBundleBranch
		}
		installed, err := refAlreadyInstalled(root, ref)
		if err != nil {
			return fmt.Errorf("--with-apis %q: %w", raw, err)
		}
		if installed {
			fmt.Fprintf(os.Stderr, "with-apis: %s already installed, skipping\n", ref)
			continue
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		dest, err := fetcher.Install(ctx, root, ref, nil)
		cancel()
		if err != nil {
			return fmt.Errorf("--with-apis %s: %w", raw, err)
		}
		fmt.Fprintf(os.Stderr, "with-apis: installed %s at %s\n", ref, dest)
	}
	return nil
}

// installRoot returns the directory --with-apis should install
// into. Just the apis dir under the new unified layout.
func installRoot(cfg *config) string {
	return cfg.ApisDir
}

// refAlreadyInstalled scans the apis dir for any installed bundle
// whose source.yaml#ref slug matches ref's slug. We don't compare
// SHAs because the goal of --with-apis is "make the bundle available
// before serve starts": if the operator wants a different SHA they
// should run `bouncer apis upgrade` explicitly.
func refAlreadyInstalled(root string, ref bundles.Ref) (bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		src, err := bundles.LoadSource(filepath.Join(root, e.Name(), bundles.SourceFile))
		if err != nil {
			continue // not a bundle, or malformed source.yaml — skip
		}
		installedRef, err := bundles.ParseRef(src.Ref)
		if err != nil {
			continue
		}
		if installedRef.Slug() == ref.Slug() {
			return true, nil
		}
	}
	return false, nil
}

// resolveMITMDefault is the "default-on" softening. When the
// operator didn't set --mitm explicitly and no MITM CA is wired up
// (no --mitm-ca-cert / no auto-derived files in --data-dir), we drop
// MITM rather than failing validation. An explicit --mitm=true with
// missing files still errors — that's a misconfiguration the
// operator asked for.
func resolveMITMDefault(cfg *config, fs *pflag.FlagSet) {
	if fs.Changed("mitm") {
		return
	}
	if cfg.MITMCAPath == "" || cfg.MITMCAKey == "" {
		cfg.MITM = false
	}
}

// defaultDataDirFromCwd points cfg.DataDir at the current working
// directory when nothing else (flag, env) has set it and the cwd
// looks like a `bouncer init` layout. Lets an operator drop into
// their data dir and run `bouncer serve` without restating
// `--data-dir .` every time.
//
// Idempotent and conservative: only triggers on a fully-empty
// DataDir (so $BOUNCER_DATA_DIR or --data-dir always wins) and only
// when both secret.hex and admin-password.hash are present (the
// IsInitialized check). Anything less is a half-baked dir we'd
// rather error on than silently consume.
func defaultDataDirFromCwd(cfg *config) {
	if cfg.DataDir != "" {
		return
	}
	if !initcmd.IsInitialized(".") {
		return
	}
	cfg.DataDir = "."
}

// applyDataDir resolves --data-dir into the per-file flags. Any flag
// the operator explicitly set (`fs.Changed`) wins; everything else
// pulls from the layout written by `bouncer init`. Missing files
// are tolerated — a half-populated dir still serves what it can.
func applyDataDir(cfg *config, fs *pflag.FlagSet) error {
	if cfg.DataDir == "" {
		return nil
	}
	dir := cfg.DataDir
	read := func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	if !fs.Changed("secret-hex") && cfg.SecretHex == "" {
		if v, err := read("secret.hex"); err == nil {
			cfg.SecretHex = v
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("data-dir secret.hex: %w", err)
		}
	}
	if !fs.Changed("apis-dir") && exists("apis") {
		cfg.ApisDir = filepath.Join(dir, "apis")
	}
	if !fs.Changed("policies-dir") && exists("policies") {
		cfg.PoliciesDir = filepath.Join(dir, "policies")
	}
	if !fs.Changed("admin-password-hash") && cfg.AdminPasswordHash == "" {
		if v, err := read("admin-password.hash"); err == nil {
			cfg.AdminPasswordHash = v
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("data-dir admin-password.hash: %w", err)
		}
	}
	// store/store.db: pull into --store-db so any domain left at its
	// default (memory/none) gets implicitly upgraded to sqlite. The
	// store/ subdir is created lazily — sqlite refuses to open a
	// file under a missing parent directory.
	if !fs.Changed("store-db") && cfg.StoreDB == "" {
		storeDir := filepath.Join(dir, "store")
		if err := os.MkdirAll(storeDir, 0o755); err != nil {
			return fmt.Errorf("data-dir store/: %w", err)
		}
		cfg.StoreDB = filepath.Join(storeDir, "store.db")
		if !fs.Changed("traffic-store") {
			cfg.TrafficStore = TrafficStoreSqlite
		}
		if !fs.Changed("policies-store") {
			cfg.PoliciesStore = PoliciesStoreSqlite
		}
		if !fs.Changed("proposals-store") {
			cfg.ProposalsStore = ProposalsStoreSqlite
		}
	}
	if !fs.Changed("mitm-ca-cert") && exists("mitm-ca.crt") {
		cfg.MITMCAPath = filepath.Join(dir, "mitm-ca.crt")
	}
	if !fs.Changed("mitm-ca-key") && exists("mitm-ca.key") {
		cfg.MITMCAKey = filepath.Join(dir, "mitm-ca.key")
	}
	return nil
}

// validate enforces cross-field invariants viper's per-key getters
// can't express — chiefly that exactly one of --secret-hex /
// --dev-stub-secret is set, so a config typo can't silently downgrade
// prod to the deterministic stub.
func (c *config) validate() error {
	switch {
	case c.SecretHex == "" && !c.DevStubSecret:
		return fmt.Errorf("must set --secret-hex (or BOUNCER_SECRET_HEX), or pass --dev-stub-secret for local dev")
	case c.SecretHex != "" && c.DevStubSecret:
		return fmt.Errorf("--secret-hex and --dev-stub-secret are mutually exclusive")
	}
	if c.MITM && (c.MITMCAPath == "" || c.MITMCAKey == "") {
		return fmt.Errorf("--mitm requires both --mitm-ca-cert and --mitm-ca-key")
	}
	if err := validateStoreDB("traffic", c.TrafficStore == TrafficStoreSqlite, c.TrafficDB, c.StoreDB); err != nil {
		return err
	}
	if err := validateStoreDB("policies", c.PoliciesStore == PoliciesStoreSqlite, c.PoliciesDB, c.StoreDB); err != nil {
		return err
	}
	if err := validateStoreDB("proposals", c.ProposalsStore == ProposalsStoreSqlite, c.ProposalsDB, c.StoreDB); err != nil {
		return err
	}
	if c.AdminPasswordHash != "" && c.AdminPassword != "" {
		return fmt.Errorf("--admin-password and --admin-password-hash are mutually exclusive")
	}
	return nil
}

// validateStoreDB checks the per-domain DB pairing rule: a sqlite
// store needs either its own --{name}-db or the shared --store-db,
// and a non-sqlite store must not set --{name}-db. The kind itself
// is already type-checked by the field's UnmarshalText.
func validateStoreDB(name string, isSqlite bool, perDB, fallback string) error {
	if isSqlite && perDB == "" && fallback == "" {
		return fmt.Errorf("--%s-store=sqlite requires --%s-db (or --store-db)", name, name)
	}
	if !isSqlite && perDB != "" {
		return fmt.Errorf("--%s-db set without --%s-store=sqlite", name, name)
	}
	return nil
}

// deriveSecret produces the 32-byte server secret from cfg. Either
// --dev-stub-secret picks the deterministic stub, or --secret-hex is
// parsed; loadConfig.validate has already rejected the "neither" and
// "both" cases so this function does not have to.
func deriveSecret(cfg *config) ([32]byte, error) {
	if cfg.DevStubSecret {
		return auth.DevStubSecret(), nil
	}
	return auth.SecretFromHex(cfg.SecretHex)
}

// resolveAdminPasswordHash returns the bcrypt hash to wire into the
// login flow. --admin-password-hash passes through verbatim;
// --admin-password is hashed at boot for dev convenience and
// log-warns so it cannot quietly become a production pattern.
// Neither flag set returns "" — the login endpoint then serves 503.
func resolveAdminPasswordHash(cfg *config) (string, error) {
	if cfg.AdminPasswordHash != "" {
		return cfg.AdminPasswordHash, nil
	}
	if cfg.AdminPassword == "" {
		return "", nil
	}
	slog.Warn("hashing --admin-password at boot — dev only; production should set BOUNCER_ADMIN_PASSWORD_HASH instead so the cleartext is not visible in `ps`")
	hashed, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash admin password: %w", err)
	}
	return string(hashed), nil
}
