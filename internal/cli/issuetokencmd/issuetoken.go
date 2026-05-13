// Package issuetoken implements the `bouncer issue-token` subcommand.
//
// Two modes, chosen by which flags are present:
//
//  1. Access-only (no --out): print a single short-lived access JWT
//     to stdout. The CI / scripting workflow — feed the JWT into a
//     curl call, run a smoke test, drop the token. Required flags:
//     --subject, --access-token, the secret.
//
//  2. Credentials file (--out): write a `credentials.json` containing
//     the upstream's client_id / client_secret, a long-lived refresh
//     JWT, and a token_uri pointing at the proxy's POST /token.
//     OAuth2 clients (gws-cli, generic libraries) point their
//     `token_uri` at this file and get transparent refresh against
//     the proxy. Required flags: --subject, --credentials-file,
//     --proxy-url, --out.
//
// The secret used here MUST be configured on the proxy (--secret-hex
// or --dev-stub-secret on both sides).
package issuetokencmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/cli/cliconfig"
	"github.com/jkylling/bouncer/internal/control/tokens"
	"github.com/jkylling/bouncer/internal/datadir"
)

// defaultGoogleTokenURL is the upstream OAuth2 token endpoint for
// Google. Picked as the default because every bundled API today is a
// Google API; operators using other providers pass --token-url.
const defaultGoogleTokenURL = "https://oauth2.googleapis.com/token"

const issueTokenLong = `Issue proxy tokens for the bouncer.

Two modes:

  Access-only (no --out): print one access JWT to stdout. Useful
  for CI scripts and integration tests that need a single short-
  lived bearer.

  Credentials file (--out): write credentials.json containing the
  upstream's client_id / client_secret, a refresh JWT, and a
  token_uri pointing at the proxy. OAuth2 clients use this for
  transparent refresh against the proxy.

Examples:

  # Access-only — local dev token good for one curl call.
  bouncer issue-token --dev-stub-secret \
      --subject demo --access-token "$GOOGLE_ACCESS_TOKEN" --ttl 5m

  # Credentials file — feed the file to gws-cli (or any OAuth2 client).
  bouncer issue-token --dev-stub-secret \
      --subject me \
      --credentials-file ./google-creds.json \
      --proxy-url http://localhost:8080 \
      --out ./credentials.json

  # google-creds.json is any flat JSON containing client_id,
  # client_secret, and refresh_token — for example, the output of
  # bouncer-gws/scripts/get_credentials.py.

Environment:
  Every flag has a BOUNCER_<UPPER_SNAKE> env equivalent —
  e.g. --secret-hex pairs with BOUNCER_SECRET_HEX.`

type config struct {
	// Shared
	Subject       string `mapstructure:"subject"`
	SecretHex     string `mapstructure:"secret-hex"`
	DevStubSecret bool   `mapstructure:"dev-stub-secret"`

	// Access-only mode
	AccessToken string        `mapstructure:"access-token"`
	TTL         time.Duration `mapstructure:"ttl"`

	// Headers is the repeatable --header pair list the operator wires
	// onto the issued token. See parseHeaderPairs for the accepted
	// shape (`Name=Value`). Cookies belong here too, written as a
	// `Cookie=name=value; name2=value2` entry.
	//
	// Cross-mode: in access-only mode they ride directly on the
	// issued access JWT; in credentials-file mode they ride on the
	// refresh JWT and the /token rotation propagates them onto each
	// fresh access JWT.
	Headers []string `mapstructure:"header"`

	// Credentials-file mode
	OutPath         string        `mapstructure:"out"`
	CredentialsFile string        `mapstructure:"credentials-file"`
	ProxyURL        string        `mapstructure:"proxy-url"`
	TokenURL        string        `mapstructure:"token-url"`
	RefreshTTL      time.Duration `mapstructure:"refresh-ttl"`

	// Admin marks the issued JWT (access or refresh+access pair) as
	// authorised for admin/control-plane endpoints. Off by default.
	// The bootstrap path for the admin password-login flow: the
	// operator runs `issue-token --admin --access-token=...`
	// (or the credentials variant) and pastes the token into the UI.
	Admin bool `mapstructure:"admin"`
}

// mode is the invocation pattern the operator chose. The two modes
// have disjoint required-flag sets; mode() inspects --out to pick
// which one this invocation is.
type mode string

const (
	modeAccess      mode = "access"
	modeCredentials mode = "credentials"
)

func (c *config) mode() mode {
	if c.OutPath != "" {
		return modeCredentials
	}
	return modeAccess
}

// bindFlags registers every flag on fs. Shared between Command()
// (production) and loadConfig (tests) so the flag schema lives in
// one place.
func bindFlags(fs *pflag.FlagSet) {
	// Shared
	fs.String("subject", "", "JWT sub claim (typically the holder's identifier)")
	fs.String("secret-hex", "", "32-byte server secret as 64 hex chars (or BOUNCER_SECRET_HEX)")
	fs.Bool("dev-stub-secret", false, "use deterministic dev stub secret (NEVER use in prod)")
	datadir.BindFlag(fs)

	// Access-only
	fs.String("access-token", "", "(access-only) upstream access token to embed (optional if --header is provided)")
	fs.Duration("ttl", time.Hour, "(access-only) JWT lifetime")

	// Cross-mode
	fs.StringArray("header", nil, "extra header to stamp on every forwarded request, as Name=Value (repeatable). For cookies, use --header 'Cookie=name=value; name2=value2'. In credentials-file mode the headers ride on the refresh JWT and propagate to every issued access JWT.")

	// Credentials-file
	fs.String("out", "", "(credentials) path to write the credentials.json")
	fs.String("credentials-file", "", "(credentials) input JSON containing client_id, client_secret, and refresh_token (e.g. the output of bouncer-gws/scripts/get_credentials.py)")
	fs.String("proxy-url", "", "(credentials) proxy base URL; token_uri is built as <proxy-url>/token")
	fs.String("token-url", defaultGoogleTokenURL, "(credentials) upstream OAuth2 token endpoint")
	fs.Duration("refresh-ttl", 0, "(credentials) exp on refresh JWT; 0 = no expiry")

	// Cross-mode
	fs.Bool("admin", false, "issue an admin JWT (authorised for /_api/* admin endpoints)")
}

// configFromFlags reads the bound flag set + BOUNCER_* env into a
// *config. Validates before returning.
func configFromFlags(fs *pflag.FlagSet) (*config, error) {
	cfg := &config{}
	if err := cliconfig.Load(fs, cfg); err != nil {
		return nil, err
	}
	if err := defaultSecretFromDataDir(cfg, fs); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultSecretFromDataDir reads <data-dir>/secret.hex when neither
// --secret-hex nor BOUNCER_SECRET_HEX is set. The data dir resolves
// via the standard precedence (--data-dir flag → $BOUNCER_DATA_DIR →
// cwd-if-initialized) so an operator can drop into their data dir
// and run a bare `issue-token --subject ... --access-token ...`.
func defaultSecretFromDataDir(cfg *config, fs *pflag.FlagSet) error {
	if cfg.SecretHex != "" || cfg.DevStubSecret {
		return nil
	}
	if fs.Changed("secret-hex") {
		return nil
	}
	dir := datadir.Resolve(fs)
	if dir == "" {
		return nil
	}
	hex, err := datadir.Layout{Dir: dir}.ReadSecret()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s/%s: %w", dir, datadir.SecretFile, err)
	}
	cfg.SecretHex = hex
	return nil
}

// loadConfig parses argv as if invoked from the CLI and returns the
// resolved *config. Test entry point.
func loadConfig(args []string) (*config, error) {
	fs := pflag.NewFlagSet("issue-token", pflag.ContinueOnError)
	bindFlags(fs)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return configFromFlags(fs)
}

// Command returns the `bouncer issue-token` cobra subcommand.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issue-token",
		Short: "Issue a proxy access JWT (or write a credentials.json with a refresh JWT)",
		Long:  issueTokenLong,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := configFromFlags(c.Flags())
			if err != nil {
				return err
			}
			return runIssueToken(cfg)
		},
	}
	bindFlags(cmd.Flags())
	return cmd
}

// runIssueToken is the post-config entry point shared by Command's
// RunE and any test driver.
func runIssueToken(cfg *config) error {
	secret, err := deriveSecret(cfg)
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	keys, err := auth.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}
	switch cfg.mode() {
	case modeAccess:
		return runAccessMode(cfg, keys)
	case modeCredentials:
		return runCredentialsMode(cfg, keys)
	default:
		// validate() should have rejected this — panic so the
		// unreachable status is loud, not silently exit-0.
		panic(fmt.Sprintf("issuetoken: unknown mode %q", cfg.mode()))
	}
}

// validate enforces the per-mode flag requirements. Cross-mode
// flags are tolerated (e.g. passing --access-token alongside --out
// just means it is ignored by the credentials path) so the operator
// can mix-and-match shell aliases — but the *required* set per mode
// must be satisfied.
func (c *config) validate() error {
	if c.SecretHex == "" && !c.DevStubSecret {
		return errors.New("must set --secret-hex (or BOUNCER_SECRET_HEX), or pass --dev-stub-secret")
	}
	if c.SecretHex != "" && c.DevStubSecret {
		return errors.New("--secret-hex and --dev-stub-secret are mutually exclusive")
	}
	if c.Subject == "" {
		return errors.New("--subject is required")
	}
	if c.mode() == modeAccess {
		if c.AccessToken == "" && len(c.Headers) == 0 {
			return errors.New("at least one of --access-token or --header is required (or pass --out for credentials-file mode)")
		}
		if c.TTL <= 0 {
			return errors.New("--ttl must be positive")
		}
		return nil
	}
	if c.CredentialsFile == "" {
		return errors.New("--credentials-file is required for credentials-file mode")
	}
	if c.ProxyURL == "" {
		return errors.New("--proxy-url is required for credentials-file mode")
	}
	// Normalize and validate --proxy-url. Two failure modes have
	// bitten in practice and both produce broken refresh that only
	// surfaces at first call: a missing scheme (gws-cli's reqwest
	// rejects relative URLs) and a trailing /token segment (operator
	// pastes the token_uri instead of the origin, every appended
	// segment then double-suffixes). Validate strictly here so a
	// typo fails at issue time rather than later in the data plane.
	normalized, err := normalizeOrigin(c.ProxyURL)
	if err != nil {
		return fmt.Errorf("--proxy-url: %w", err)
	}
	c.ProxyURL = normalized
	if c.TokenURL == "" {
		return errors.New("--token-url is required for credentials-file mode")
	}
	return nil
}

// normalizeOrigin parses raw as an absolute origin URL — scheme +
// host, no path — and returns the canonical form (no trailing
// slash). Rejects relative URLs (no scheme), non-http(s) schemes,
// and URLs that carry a path / query / fragment, all of which
// produce wrong refresh URLs at first use rather than at issue
// time. Empty strings are rejected by the caller (validate).
func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("must be an absolute http(s) URL, got %q", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host in %q", raw)
	}
	if path := strings.Trim(u.Path, "/"); path != "" {
		return "", fmt.Errorf("must be the proxy origin (no path); got path %q in %q — drop the path", path, raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("must be the proxy origin (no query/fragment); got %q", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// credentialsFile is the shape issue-token reads from
// --credentials-file: a flat JSON containing client_id, client_secret,
// and refresh_token. The loader is lenient with unknown fields, so a
// gcloud `application_default_credentials.json` or the output of
// bouncer-gws/scripts/get_credentials.py drops in unmodified.
type credentialsFile struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

// credentialsDoc is the shape issue-token writes when --out is set.
// The field names match what an OAuth2 client (gws-cli's
// `yup-oauth2`, generic Go google.ConfigFromJSON, etc.) expects in a
// credentials.json. The `type` field is required by yup-oauth2's
// AuthorizedUserSecret loader — without it the client refuses the
// file and falls back to the next loader (or fails).
type credentialsDoc struct {
	Type         string `json:"type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	TokenURI     string `json:"token_uri"`
}

// credentialsType is the gcloud / yup-oauth2 discriminator for an
// installed-app refresh credential. Pinned as a constant so the
// value can't drift across rewrites.
const credentialsType = "authorized_user"

func runAccessMode(cfg *config, keys *auth.ServerKeys) error {
	headers, err := parseHeaderPairs(cfg.Headers)
	if err != nil {
		return fmt.Errorf("--header: %w", err)
	}
	res, err := tokens.Issue(context.Background(), keys, &tokens.Spec{
		Subject:     cfg.Subject,
		AccessToken: cfg.AccessToken,
		Headers:     headers,
		TTLSeconds:  int64(cfg.TTL / time.Second),
		Admin:       cfg.Admin,
	})
	if err != nil {
		return fmt.Errorf("issue: %w", err)
	}
	fmt.Println(res.Token)
	return nil
}

// parseHeaderPairs decodes `Name=Value` strings into auth.Header.
// strings.Cut splits on the first `=`, preserving any later `=` in
// the value (e.g. base64 padding, or a `Cookie=name=val` row).
// Empty name fails loud — an empty value is sometimes a legitimate
// upstream signal (delete-header semantics) but the CLI rejects
// here too because the resulting `Set("X-Foo", "")` rarely does
// what the operator wanted.
func parseHeaderPairs(raw []string) ([]auth.Header, error) {
	out := make([]auth.Header, 0, len(raw))
	for _, s := range raw {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("expected Name=Value, got %q", s)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" || v == "" {
			return nil, fmt.Errorf("name and value are required (got %q)", s)
		}
		out = append(out, auth.Header{Name: k, Value: v})
	}
	return out, nil
}

func runCredentialsMode(cfg *config, keys *auth.ServerKeys) error {
	creds, err := loadCredentialsFile(cfg.CredentialsFile)
	if err != nil {
		return fmt.Errorf("credentials-file: %w", err)
	}
	headers, err := parseHeaderPairs(cfg.Headers)
	if err != nil {
		return fmt.Errorf("--header: %w", err)
	}
	refreshJWT, err := auth.IssueRefreshToken(keys, cfg.Subject, auth.RefreshCreds{
		RefreshToken: creds.RefreshToken,
		TokenURL:     cfg.TokenURL,
		Headers:      headers,
	}, cfg.RefreshTTL, cfg.Admin)
	if err != nil {
		return fmt.Errorf("issue refresh: %w", err)
	}
	doc := credentialsDoc{
		Type:         credentialsType,
		ClientID:     creds.ClientID,
		ClientSecret: creds.ClientSecret,
		RefreshToken: refreshJWT,
		// validate() normalised cfg.ProxyURL to a bare origin (no
		// trailing slash, no path), so this concatenation is a fixed
		// shape — no surprise double-suffixes.
		TokenURI: cfg.ProxyURL + "/token",
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := writeOutput(cfg.OutPath, raw); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	abs, _ := filepath.Abs(cfg.OutPath)
	fmt.Fprintf(os.Stderr, "issue-token: wrote %s\n", abs)
	return nil
}

// writeOutput writes raw to path with 0o600 permissions. The mode is
// hardcoded — the file holds a refresh JWT (not as sensitive as the
// raw upstream refresh token, which the proxy holds, but still
// shouldn't be world-readable).
func writeOutput(path string, raw []byte) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	return os.WriteFile(abs, append(raw, '\n'), 0o600)
}

// loadCredentialsFile reads the input JSON, returning the
// client_id / client_secret / refresh_token triple needed to mint
// the proxy's refresh JWT and populate the output credentials.json.
// Unknown fields (access_token, expires_at, scope, token_type, kind,
// type, ...) are tolerated so OAuth-flow dumps drop in unmodified.
func loadCredentialsFile(path string) (*credentialsFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc credentialsFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	missing := make([]string, 0, 3)
	if doc.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if doc.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if doc.RefreshToken == "" {
		missing = append(missing, "refresh_token")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s: missing %s", path, strings.Join(missing, ", "))
	}
	return &doc, nil
}

func deriveSecret(cfg *config) ([32]byte, error) {
	if cfg.DevStubSecret {
		return auth.DevStubSecret(), nil
	}
	return auth.SecretFromHex(cfg.SecretHex)
}
