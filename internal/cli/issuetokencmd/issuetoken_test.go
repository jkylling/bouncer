package issuetokencmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/cli/initcmd"
	"github.com/jkylling/bouncer/internal/control/tokens"
)

// ----- access-only mode -----

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig([]string{
		"--subject", "agent-1",
		"--dev-stub-secret",
		"--access-token", "ya29-x",
	})
	require.NoError(t, err)
	require.Equal(t, modeAccess, cfg.mode())
	require.Equal(t, "agent-1", cfg.Subject)
	require.Equal(t, "ya29-x", cfg.AccessToken)
	require.Equal(t, time.Hour, cfg.TTL)
}

func TestLoadConfigRequiresSubject(t *testing.T) {
	_, err := loadConfig([]string{"--dev-stub-secret", "--access-token", "x"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "subject")
}

func TestLoadConfigRequiresAccessToken(t *testing.T) {
	_, err := loadConfig([]string{"--subject", "s", "--dev-stub-secret"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "access-token")
}

func TestLoadConfigRejectsBothSecretFlags(t *testing.T) {
	hex64 := strings.Repeat("aa", 32)
	_, err := loadConfig([]string{
		"--subject", "s", "--access-token", "x",
		"--secret-hex", hex64, "--dev-stub-secret",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

// TestAccessTokenVerifies pins the cross-binary invariant: a token
// issued under --dev-stub-secret verifies against keys derived from
// the same stub. Without this the access-only mode is silently
// broken.
func TestAccessTokenVerifies(t *testing.T) {
	cfg, err := loadConfig([]string{
		"--subject", "agent-1",
		"--dev-stub-secret",
		"--access-token", "upstream-bearer",
		"--ttl", "1m",
	})
	require.NoError(t, err)
	keys := mustKeys(t, cfg)
	res, err := tokens.Issue(context.Background(), keys, &tokens.Spec{
		Subject:     cfg.Subject,
		AccessToken: cfg.AccessToken,
		TTLSeconds:  int64(cfg.TTL / time.Second),
	})
	require.NoError(t, err)
	got, err := auth.VerifyAccessToken(keys, res.Token)
	require.NoError(t, err)
	require.Equal(t, "agent-1", got.Subject)
	require.Equal(t, "upstream-bearer", got.Creds.AccessToken)
}

// ----- credentials-file mode -----

// writeCredentialsFile drops a flat-shape JSON containing
// client_id, client_secret, and refresh_token into dir and returns
// the path. This is the shape bouncer-gws/scripts/get_credentials.py
// produces; gcloud's application_default_credentials.json is
// equivalent (modulo extra metadata fields the loader ignores).
func writeCredentialsFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "google-creds.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
  "client_id": "cid.apps.googleusercontent.com",
  "client_secret": "sec-x",
  "refresh_token": "1//rt"
}`), 0o600))
	return path
}

func TestLoadConfigCredentialsMode(t *testing.T) {
	dir := t.TempDir()
	creds := writeCredentialsFile(t, dir)
	out := filepath.Join(dir, "credentials.json")
	cfg, err := loadConfig([]string{
		"--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", creds,
		"--proxy-url", "http://localhost:8080",
		"--out", out,
	})
	require.NoError(t, err)
	require.Equal(t, modeCredentials, cfg.mode())
}

func TestLoadConfigCredentialsRequiresCredentialsFile(t *testing.T) {
	_, err := loadConfig([]string{
		"--dev-stub-secret",
		"--subject", "me",
		"--proxy-url", "http://x",
		"--out", "/tmp/x.json",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "--credentials-file")
}

// TestNormalizeOrigin pins --proxy-url validation. The three
// failure modes covered here all produced silently-broken refresh
// in practice (gws-cli either refused the relative URL or
// double-suffixed /token) until validation moved to issue time.
func TestNormalizeOrigin(t *testing.T) {
	cases := map[string]struct {
		want    string
		wantErr string
	}{
		"http://localhost:8080":                 {want: "http://localhost:8080"},
		"https://proxy.internal":                {want: "https://proxy.internal"},
		"http://host.lima.internal:8080/":       {want: "http://host.lima.internal:8080"},
		"host.lima.internal:8080":               {wantErr: "absolute http(s)"},
		"http://host.lima.internal:8080/token":  {wantErr: "drop the path"},
		"http://host.lima.internal:8080/token/": {wantErr: "drop the path"},
		"https://proxy/foo/bar":                 {wantErr: "drop the path"},
		"ftp://x":                               {wantErr: "absolute http(s)"},
		"https://proxy?x=1":                     {wantErr: "no query/fragment"},
	}
	for in, tc := range cases {
		t.Run(in, func(t *testing.T) {
			got, err := normalizeOrigin(in)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestLoadConfigRejectsProxyURLWithToken: a operator who pastes
// the token_uri value (with /token) instead of the origin used to
// produce a credentials.json whose token_uri was
// http://host:port/token/token. Catch it at parse time.
func TestLoadConfigRejectsProxyURLWithToken(t *testing.T) {
	dir := t.TempDir()
	creds := writeCredentialsFile(t, dir)
	_, err := loadConfig([]string{
		"--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", creds,
		"--proxy-url", "http://host.lima.internal:8080/token",
		"--out", filepath.Join(dir, "x.json"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "drop the path")
}

func TestLoadConfigRejectsProxyURLMissingScheme(t *testing.T) {
	dir := t.TempDir()
	creds := writeCredentialsFile(t, dir)
	_, err := loadConfig([]string{
		"--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", creds,
		"--proxy-url", "host.lima.internal:8080",
		"--out", filepath.Join(dir, "x.json"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "absolute http(s)")
}

func TestLoadConfigCredentialsRequiresProxyURL(t *testing.T) {
	dir := t.TempDir()
	_, err := loadConfig([]string{
		"--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", writeCredentialsFile(t, dir),
		"--out", filepath.Join(dir, "x.json"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "--proxy-url")
}

// TestCredentialsFileEndToEnd pins the full credentials-mode flow:
// loadConfig → issue → write file → re-read file → verify the
// embedded refresh JWT decrypts to the input refresh token + token
// URL, and the file's other fields (client_id, secret, token_uri)
// match the inputs from --credentials-file.
func TestCredentialsFileEndToEnd(t *testing.T) {
	dir := t.TempDir()
	creds := writeCredentialsFile(t, dir)
	out := filepath.Join(dir, "credentials.json")
	cfg, err := loadConfig([]string{
		"--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", creds,
		"--proxy-url", "http://localhost:8080",
		"--out", out,
	})
	require.NoError(t, err)
	keys := mustKeys(t, cfg)
	require.NoError(t, runCredentialsMode(cfg, keys))

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var doc credentialsDoc
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Equal(t, "authorized_user", doc.Type)
	require.Equal(t, "cid.apps.googleusercontent.com", doc.ClientID)
	require.Equal(t, "sec-x", doc.ClientSecret)
	require.Equal(t, "http://localhost:8080/token", doc.TokenURI)

	// Read the raw JSON too — yup-oauth2 keys on the literal "type"
	// field (auth.rs::AuthorizedUserSecret), so the on-disk byte
	// `"type":"authorized_user"` is what really matters, not the Go
	// struct round-trip.
	require.Contains(t, string(raw), `"type": "authorized_user"`)

	// The refresh JWT verifies and unwraps to the input refresh
	// token + the default Google token URL.
	got, err := auth.VerifyRefreshToken(keys, doc.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, "me", got.Subject)
	require.Equal(t, "1//rt", got.Creds.RefreshToken)
	require.Equal(t, defaultGoogleTokenURL, got.Creds.TokenURL)
}

// TestCredentialsFileToleratesExtraFields: a typical OAuth-flow JSON
// dump (refresh_token + access_token + expires_at + scope metadata)
// is consumable verbatim via --credentials-file; the loader takes
// the three fields it needs and ignores the rest.
func TestCredentialsFileToleratesExtraFields(t *testing.T) {
	dir := t.TempDir()
	credsPath := filepath.Join(dir, "google-creds.json")
	require.NoError(t, os.WriteFile(credsPath, []byte(`{
  "kind": "oauth2",
  "client_id": "cid",
  "client_secret": "sec",
  "access_token": "ya29.fresh",
  "refresh_token": "1//from-google",
  "expires_at": "2099-01-01T00:00:00Z",
  "scope": "https://www.googleapis.com/auth/gmail.readonly",
  "token_type": "Bearer"
}`), 0o600))
	out := filepath.Join(dir, "credentials.json")
	cfg, err := loadConfig([]string{
		"--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", credsPath,
		"--proxy-url", "http://localhost:8080",
		"--out", out,
	})
	require.NoError(t, err)
	keys := mustKeys(t, cfg)
	require.NoError(t, runCredentialsMode(cfg, keys))

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var doc credentialsDoc
	require.NoError(t, json.Unmarshal(raw, &doc))
	got, err := auth.VerifyRefreshToken(keys, doc.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, "1//from-google", got.Creds.RefreshToken)
}

// TestCredentialsFileCustomTokenURL pins that --token-url overrides
// the default — needed for non-Google providers (Microsoft, Okta,
// etc.) sharing the same proxy.
func TestCredentialsFileCustomTokenURL(t *testing.T) {
	dir := t.TempDir()
	creds := writeCredentialsFile(t, dir)
	out := filepath.Join(dir, "credentials.json")
	cfg, err := loadConfig([]string{
		"--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", creds,
		"--proxy-url", "http://localhost:8080",
		"--token-url", "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		"--out", out,
	})
	require.NoError(t, err)
	keys := mustKeys(t, cfg)
	require.NoError(t, runCredentialsMode(cfg, keys))
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var doc credentialsDoc
	require.NoError(t, json.Unmarshal(raw, &doc))
	got, err := auth.VerifyRefreshToken(keys, doc.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, "https://login.microsoftonline.com/common/oauth2/v2.0/token", got.Creds.TokenURL)
}

// TestLoadCredentialsFileRejectsMissingFields: each of client_id,
// client_secret, refresh_token is required; the loader names the
// missing fields rather than failing with a generic parse error.
func TestLoadCredentialsFileRejectsMissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"client_id":"cid"}`), 0o600))
	_, err := loadCredentialsFile(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_secret")
	require.Contains(t, err.Error(), "refresh_token")
}

func mustKeys(t *testing.T, cfg *config) *auth.ServerKeys {
	t.Helper()
	secret, err := deriveSecret(cfg)
	require.NoError(t, err)
	keys, err := auth.FromSecret(secret)
	require.NoError(t, err)
	return keys
}

// ----- secret.hex cwd auto-discovery -----

// chdirInitialized creates a tempdir holding the two files
// IsInitialized requires (secret.hex + admin-password.hash), chdirs
// the test process there, and registers a cleanup that restores cwd.
// secret.hex is written with `body` so the test can verify it
// actually flowed through.
func chdirInitialized(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, initcmd.SecretFile), []byte(body), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, initcmd.AdminPasswordFile), []byte("hash"), 0o600))
	prev, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prev) })
	return dir
}

// TestLoadConfigSecretHexAutoLoadFromCwd: when the cwd looks like a
// `bouncer init` data dir and neither --secret-hex nor
// BOUNCER_SECRET_HEX is set, the secret is read from
// ./secret.hex.
func TestLoadConfigSecretHexAutoLoadFromCwd(t *testing.T) {
	t.Setenv("BOUNCER_SECRET_HEX", "")
	hex64 := strings.Repeat("ab", 32)
	chdirInitialized(t, hex64+"\n")
	cfg, err := loadConfig([]string{"--subject", "me", "--access-token", "x"})
	require.NoError(t, err)
	require.Equal(t, hex64, cfg.SecretHex)
}

// TestLoadConfigSecretHexFlagBeatsCwd: an explicit --secret-hex flag
// always wins, even when ./secret.hex is present.
func TestLoadConfigSecretHexFlagBeatsCwd(t *testing.T) {
	t.Setenv("BOUNCER_SECRET_HEX", "")
	cwdHex := strings.Repeat("aa", 32)
	flagHex := strings.Repeat("bb", 32)
	chdirInitialized(t, cwdHex)
	cfg, err := loadConfig([]string{
		"--subject", "me", "--access-token", "x",
		"--secret-hex", flagHex,
	})
	require.NoError(t, err)
	require.Equal(t, flagHex, cfg.SecretHex)
}

// TestLoadConfigSecretHexEnvBeatsCwd: BOUNCER_SECRET_HEX wins
// over ./secret.hex — the auto-load is the lowest-priority source.
func TestLoadConfigSecretHexEnvBeatsCwd(t *testing.T) {
	cwdHex := strings.Repeat("aa", 32)
	envHex := strings.Repeat("bb", 32)
	t.Setenv("BOUNCER_SECRET_HEX", envHex)
	chdirInitialized(t, cwdHex)
	cfg, err := loadConfig([]string{"--subject", "me", "--access-token", "x"})
	require.NoError(t, err)
	require.Equal(t, envHex, cfg.SecretHex)
}

// TestLoadConfigSecretHexCwdNotInitialized: a cwd missing
// admin-password.hash is not silently consumed — the operator gets
// the same "must set --secret-hex" error as if the file weren't
// there at all.
func TestLoadConfigSecretHexCwdNotInitialized(t *testing.T) {
	t.Setenv("BOUNCER_SECRET_HEX", "")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, initcmd.SecretFile),
		[]byte(strings.Repeat("aa", 32)), 0o600))
	prev, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prev) })

	_, err := loadConfig([]string{"--subject", "me", "--access-token", "x"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "--secret-hex")
}

// TestLoadConfigSecretHexCwdSkipsWhenDevStub: --dev-stub-secret
// suppresses the cwd auto-load (otherwise the existing mutex check
// would reject the dev-stub combo when an unrelated init data dir
// happens to be cwd).
func TestLoadConfigSecretHexCwdSkipsWhenDevStub(t *testing.T) {
	t.Setenv("BOUNCER_SECRET_HEX", "")
	chdirInitialized(t, strings.Repeat("aa", 32))
	cfg, err := loadConfig([]string{
		"--subject", "me", "--access-token", "x",
		"--dev-stub-secret",
	})
	require.NoError(t, err)
	require.Empty(t, cfg.SecretHex)
	require.True(t, cfg.DevStubSecret)
}
