package servecmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/cli/cliconfig"
	"github.com/jkylling/bouncer/internal/cli/datadir"
	"github.com/jkylling/bouncer/internal/cli/initcmd"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/observability"
	"github.com/jkylling/bouncer/internal/server/admin"
)

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
	TrafficStore  TrafficStoreKind `mapstructure:"traffic-store"`
	TrafficDB     string           `mapstructure:"traffic-db"`
	TrafficBudget int              `mapstructure:"traffic-budget"`
	TrafficMaxAge time.Duration    `mapstructure:"traffic-max-age"`

	// Policies storage. PoliciesStore picks the backend kind:
	//   - "file": YAML files under --policies-dir (current default).
	//   - "memory": in-process map, lost on restart.
	//   - "sqlite": one row per (api, name) under --policies-db.
	// Defaults to "file" so existing deployments don't change shape.
	PoliciesStore PoliciesStoreKind `mapstructure:"policies-store"`
	PoliciesDB    string            `mapstructure:"policies-db"`

	// PoliciesReadOnly disables every mutating control-plane endpoint
	// (POST/PUT/DELETE on /_api/policies). The list / get / dryRun
	// endpoints and the read-only UI keep working. Useful for
	// production deployments that want the policies viewer without
	// risking accidental edits from a shared admin host.
	PoliciesReadOnly bool `mapstructure:"policies-readonly"`

	// Proposals queue storage. Memory is the default — the queue is
	// short-lived state (approved drafts promote into the policies
	// store; rejected ones are dropped).
	ProposalsStore ProposalsStoreKind `mapstructure:"proposals-store"`
	ProposalsDB    string             `mapstructure:"proposals-db"`

	// StoreDB is the convenience shortcut: any domain whose own
	// --*-db flag is empty falls back to this when its backend is
	// sqlite. Setting --traffic-store=sqlite and --policies-store=
	// sqlite alongside --store-db=PATH gives the "one sqlite file
	// for everything" deployment with three tables in one DB.
	StoreDB string `mapstructure:"store-db"`

	// AdminPasswordHash is the bcrypt hash POST /_api/admin/login
	// compares against. Empty leaves the login endpoint wired but
	// serving 503; bootstrap then runs through `cmd/issue-token
	// --admin`. With --data-dir, auto-loaded from
	// `<data-dir>/admin-password.hash`.
	AdminPasswordHash string `mapstructure:"admin-password-hash"`

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

	// InternalPolicies picks the embedded policy set that gates the
	// /_admin and /_api control-plane surface. One of demo / simple /
	// production; default `simple` mirrors the pre-policy behaviour.
	// See bouncer/internal/server/admin/internal_apis/policies for
	// each set's contents.
	InternalPolicies string `mapstructure:"internal-policies"`
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
	fs.Duration("traffic-max-age", defaultTrafficMaxAge, "max age of traffic events; older rows evict regardless of byte pressure")
	fs.String("policies-store", "file", "policies storage backend (file|memory|sqlite); file uses --policies-dir")
	fs.String("policies-db", "", "path to the sqlite DB file when --policies-store=sqlite (falls back to --store-db)")
	fs.Bool("policies-readonly", false, "reject every mutating policy endpoint; the policies viewer stays available")
	fs.String("proposals-store", "memory", "proposals queue backend (memory|sqlite)")
	fs.String("proposals-db", "", "path to the sqlite DB file when --proposals-store=sqlite (falls back to --store-db)")
	fs.String("store-db", "", "shared sqlite DB path; any domain set to sqlite without its own --*-db falls back to this so all three can live in one file")
	fs.String("admin-password-hash", "", "bcrypt hash for the /_api/admin/login flow. Auto-loaded from `<data-dir>/admin-password.hash` when --data-dir is set; otherwise generate via `htpasswd -bnBC 12 \"\" <pw> | tr -d ':\\n'`.")
	fs.String("data-dir", "", "directory created by `bouncer init`. Defaults to the current working directory when it looks like an initialized data dir (secret.hex + admin-password.hash present), or when --init is set. When set, defaults --secret-hex, --apis-dir, --policies-dir, --admin-password-hash, --store-db, and --mitm-ca-cert/key from the layout files (any explicit flag overrides).")
	fs.Bool("init", false, "bootstrap --data-dir if it isn't already initialized (equivalent to running `bouncer init <data-dir>` first). Defaults --data-dir to the current working directory when unset. No-op when the dir already has a secret + admin-password hash.")
	fs.StringSlice("with-apis", nil, "install one or more bundle refs before serving (e.g. github.com/jkylling/bouncer-gws@v0.1.0, or just github.com/jkylling/bouncer-gws to track main). Already-installed refs are skipped; repeat the flag for several bundles.")
	fs.String("internal-policies", "simple", "embedded policy set gating the control-plane surface (/_admin + /_api): demo (open except admin), simple (mirrors current access control), production (admin-only)")
}

// buildConfig reads viper + post-parse setup against an already-bound
// fs. Used by both loadConfig (tests, parses argv first) and
// Command's RunE (cobra has already parsed). Side effects include
// bootstrap and bundle install when --init / --with-apis are set, so
// callers should treat this as the single boot-time entry rather
// than a pure parser.
func buildConfig(fs *pflag.FlagSet) (*config, error) {
	cfg := &config{}
	if err := cliconfig.Load(fs, cfg); err != nil {
		return nil, err
	}
	defaultDataDirFromCwd(cfg)
	if err := bootstrapIfRequested(cfg); err != nil {
		return nil, err
	}
	// applyDataDir before installRequestedBundles so cfg.ApisDir
	// reflects the data-dir layout when the operator passes
	// --data-dir without an explicit --apis-dir; otherwise
	// --with-apis would install into the default ./apis instead of
	// <data-dir>/apis.
	if err := applyDataDir(cfg, fs); err != nil {
		return nil, err
	}
	if err := installRequestedBundles(cfg); err != nil {
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

// bootstrapIfRequested dispatches `--init` to the shared initcmd.Run
// with daemon-friendly defaults (idempotent on re-init, quiet).
func bootstrapIfRequested(cfg *config) error {
	if !cfg.Init {
		return nil
	}
	return initcmd.Run(cfg.DataDir, initcmd.Options{
		MITM:              cfg.MITM,
		SkipIfInitialized: true,
		Quiet:             true,
		WithApis:          cfg.WithApis,
	})
}

// installRequestedBundles handles --with-apis for the non-init serve
// path; --init routes through initcmd.Run instead.
func installRequestedBundles(cfg *config) error {
	if cfg.Init || len(cfg.WithApis) == 0 {
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return bundles.InstallRefs(ctx, cfg.ApisDir, cfg.WithApis, os.Stderr)
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
// directory when nothing else (flag, env) has set it. Lets an
// operator drop into their data dir and run `bouncer serve`, or
// run `bouncer serve --init` from a fresh dir, without restating
// `--data-dir .` every time.
//
// Two trigger conditions, both keyed off an empty DataDir so
// $BOUNCER_DATA_DIR or --data-dir always wins:
//   - --init is set: the operator has explicitly asked us to
//     bootstrap, cwd is the natural target.
//   - cwd already looks initialized (secret.hex + admin-password.hash
//     present): drop-in serve.
//
// An empty / half-baked cwd without --init is never silently
// consumed — we'd rather error on the missing-secret check.
func defaultDataDirFromCwd(cfg *config) {
	if cfg.DataDir != "" {
		return
	}
	if cfg.Init || datadir.IsInitialized(".") {
		cfg.DataDir = "."
	}
}

// applyDataDir resolves --data-dir into the per-file flags. Any flag
// the operator explicitly set (`fs.Changed`) wins; everything else
// pulls from the layout written by `bouncer init`. Missing files
// are tolerated — a half-populated dir still serves what it can.
func applyDataDir(cfg *config, fs *pflag.FlagSet) error {
	if cfg.DataDir == "" {
		return nil
	}
	l := datadir.Layout{Dir: cfg.DataDir}
	if !fs.Changed("secret-hex") && cfg.SecretHex == "" {
		if v, err := l.ReadSecret(); err == nil {
			cfg.SecretHex = v
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("data-dir secret.hex: %w", err)
		}
	}
	if !fs.Changed("apis-dir") && datadir.Exists(l.APIs()) {
		cfg.ApisDir = l.APIs()
	}
	if !fs.Changed("policies-dir") && datadir.Exists(l.Policies()) {
		cfg.PoliciesDir = l.Policies()
	}
	if !fs.Changed("admin-password-hash") && cfg.AdminPasswordHash == "" {
		if v, err := l.ReadAdminHash(); err == nil {
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
		if err := os.MkdirAll(l.Store(), 0o755); err != nil {
			return fmt.Errorf("data-dir store/: %w", err)
		}
		cfg.StoreDB = l.StoreDB()
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
	if !fs.Changed("mitm-ca-cert") && datadir.Exists(l.MITMCert()) {
		cfg.MITMCAPath = l.MITMCert()
	}
	if !fs.Changed("mitm-ca-key") && datadir.Exists(l.MITMKey()) {
		cfg.MITMCAKey = l.MITMKey()
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
	if err := admin.PolicySet(c.InternalPolicies).Validate(); err != nil {
		return fmt.Errorf("--internal-policies: %w", err)
	}
	if err := admin.PolicySet(c.InternalPolicies).Validate(); err != nil {
		return fmt.Errorf("--internal-policies: %w", err)
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
