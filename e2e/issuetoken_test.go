//go:build e2e

package e2e

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestIssueTokenAccessOnlyDevStub pins the simplest happy path: a
// single short-lived JWT printed to stdout, derived from the dev
// stub secret. CI smoke tests use this shape.
func TestIssueTokenAccessOnlyDevStub(t *testing.T) {
	res := run(t,
		"issue-token", "--dev-stub-secret",
		"--subject", "ci",
		"--access-token", "stub",
		"--ttl", "5m",
	)
	if res.Err != nil {
		t.Fatalf("issue-token: %v\nstderr: %s", res.Err, res.Stderr)
	}
	tok := strings.TrimSpace(res.Stdout)
	// JWT shape is base64url.base64url.base64url — three dot-separated
	// non-empty parts. Anything else means we wrote the wrong thing
	// (banner text, error message, etc.).
	if parts := strings.Split(tok, "."); len(parts) != 3 {
		t.Fatalf("token = %q, want JWT with 3 parts", tok)
	}
}

// TestIssueTokenSecretFromEnv pins the env binding so a CI script
// can keep the secret out of `ps`. Any subject + access-token works
// — we're checking the secret-source plumbing, not the JWT contents.
func TestIssueTokenSecretFromEnv(t *testing.T) {
	hex64 := strings.Repeat("aa", 32)
	res := runEnv(t, map[string]string{"BOUNCER_SECRET_HEX": hex64},
		"issue-token", "--subject", "x", "--access-token", "y")
	if res.Err != nil {
		t.Fatalf("issue-token: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if strings.TrimSpace(res.Stdout) == "" {
		t.Error("expected JWT on stdout, got empty")
	}
}

// TestIssueTokenRejectsBothSecretFlags pins the mutual-exclusion
// check. A misconfigured CI step that sets both shouldn't silently
// pick one — the operator deserves a clear error.
func TestIssueTokenRejectsBothSecretFlags(t *testing.T) {
	hex64 := strings.Repeat("bb", 32)
	res := run(t,
		"issue-token", "--dev-stub-secret",
		"--secret-hex", hex64,
		"--subject", "x", "--access-token", "y",
	)
	if res.Err == nil {
		t.Fatalf("expected error, got success: %s", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "mutually exclusive") {
		t.Errorf("stderr = %q, want one about mutual exclusion", res.Stderr)
	}
}

// TestIssueTokenRequiresSubject pins the validation: without
// --subject the binary refuses, rather than issuing a token with
// an empty sub claim.
func TestIssueTokenRequiresSubject(t *testing.T) {
	res := run(t,
		"issue-token", "--dev-stub-secret", "--access-token", "x",
	)
	if res.Err == nil {
		t.Fatal("expected error for missing --subject")
	}
	if !strings.Contains(res.Stderr, "--subject is required") {
		t.Errorf("stderr = %q, want 'subject is required'", res.Stderr)
	}
}

// TestIssueTokenCredentialsFile pins the --out / credentials-file
// happy path: the binary writes a parseable credentials.json with
// the expected fields and a token_uri equal to <proxy>/token. This
// is what gws-cli (and any OAuth2 client) reads.
func TestIssueTokenCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	creds := writeCredentialsFile(t, dir)
	out := filepath.Join(dir, "credentials.json")
	res := run(t,
		"issue-token", "--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", creds,
		"--proxy-url", "http://127.0.0.1:8080",
		"--out", out,
	)
	if res.Err != nil {
		t.Fatalf("issue-token: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if got := fileMode(t, out); got != 0o600 {
		t.Errorf("credentials.json mode = %o, want 0600", got)
	}
	var doc struct {
		Type         string `json:"type"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal(mustReadFile(t, out), &doc); err != nil {
		t.Fatalf("parse credentials.json: %v", err)
	}
	if doc.Type != "authorized_user" {
		t.Errorf("type = %q, want authorized_user", doc.Type)
	}
	if doc.TokenURI != "http://127.0.0.1:8080/token" {
		t.Errorf("token_uri = %q, want http://127.0.0.1:8080/token", doc.TokenURI)
	}
	if doc.ClientID == "" || doc.ClientSecret == "" || doc.RefreshToken == "" {
		t.Error("credentials.json missing fields")
	}
}

// TestIssueTokenRejectsProxyURLWithPath pins the early-fail on a
// proxy-url that carries a path. The bug it prevents: an operator
// pastes the token_uri in instead of the origin, downstream every
// gws-cli call appends to the wrong base and fails on first call
// rather than at issue time.
func TestIssueTokenRejectsProxyURLWithPath(t *testing.T) {
	dir := t.TempDir()
	creds := writeCredentialsFile(t, dir)
	res := run(t,
		"issue-token", "--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", creds,
		"--proxy-url", "http://127.0.0.1:8080/token",
		"--out", filepath.Join(dir, "creds.json"),
	)
	if res.Err == nil {
		t.Fatal("expected error for path-bearing proxy-url")
	}
	if !strings.Contains(res.Stderr, "drop the path") {
		t.Errorf("stderr = %q, want one about dropping the path", res.Stderr)
	}
}

// TestIssueTokenRejectsRelativeProxyURL pins the scheme check. A
// relative URL ("localhost:8080") would later trip up gws-cli's
// reqwest, which rejects URLs without a scheme.
func TestIssueTokenRejectsRelativeProxyURL(t *testing.T) {
	dir := t.TempDir()
	creds := writeCredentialsFile(t, dir)
	res := run(t,
		"issue-token", "--dev-stub-secret",
		"--subject", "me",
		"--credentials-file", creds,
		"--proxy-url", "localhost:8080",
		"--out", filepath.Join(dir, "creds.json"),
	)
	if res.Err == nil {
		t.Fatal("expected error for relative proxy-url")
	}
	if !strings.Contains(res.Stderr, "absolute http(s)") {
		t.Errorf("stderr = %q, want one about absolute http(s) URL", res.Stderr)
	}
}

// TestIssueTokenSecretFromCwd pins the cwd ./secret.hex auto-load:
// invoking issue-token from inside an initialized data dir succeeds
// without --secret-hex / BOUNCER_SECRET_HEX. Lets an operator
// drop into their data dir and run a bare `bouncer issue-token
// --subject ... --access-token ...`.
func TestIssueTokenSecretFromCwd(t *testing.T) {
	dir := mustInit(t, initOpts{})
	res := runEnvDir(t,
		map[string]string{"BOUNCER_SECRET_HEX": ""},
		dir,
		"issue-token", "--subject", "me", "--access-token", "x", "--ttl", "5m",
	)
	if res.Err != nil {
		t.Fatalf("issue-token: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if parts := strings.Split(strings.TrimSpace(res.Stdout), "."); len(parts) != 3 {
		t.Fatalf("token = %q, want JWT with 3 parts", res.Stdout)
	}
}

// TestIssueTokenAdminFlagFlows pins the --admin pathway: the issued
// JWT must carry the admin claim, which serve later verifies. We
// don't decode the JWT here (no internal imports); the round-trip
// proof lives in admin_test.go where this same flag is used to issue
// a bootstrap admin token.
func TestIssueTokenAdminFlagFlows(t *testing.T) {
	res := run(t,
		"issue-token", "--dev-stub-secret",
		"--subject", "boot", "--access-token", "x", "--admin",
	)
	if res.Err != nil {
		t.Fatalf("issue-token --admin: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if strings.TrimSpace(res.Stdout) == "" {
		t.Error("expected JWT on stdout")
	}
}
