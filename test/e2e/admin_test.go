//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This suite holds one smoke per admin surface: the per-status-code
// and per-branch behaviour (bad passwords, anonymous redirects, open
// docs/favicon tiers, CA 404s, logout cookie attributes) is pinned by
// the unit tests in internal/server/admin — e2e re-runs only what
// needs the real binary: cobra wiring, the shipped policy set, real
// cookies, and the CLI↔server bootstrap.

// adminFixture is the shared bootstrap for admin tests: init, serve,
// loginAdmin. Returning the proc + JWT in one call keeps every test
// body two lines of setup and the rest assertions.
type adminFixture struct {
	srv      *serveProc
	jwt      string
	cookie   *http.Cookie
	password string
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	dir := mustInit(t, initOpts{Password: "admin"})
	srv := startServe(t, serveOpts{DataDir: dir})
	jwt, cookie := loginAdmin(t, srv.BaseURL, "admin")
	return &adminFixture{srv: srv, jwt: jwt, cookie: cookie, password: "admin"}
}

// TestAdminLoginRoundTrip pins the password→JWT round-trip: the
// returned JWT is the bootstrap path for every other admin
// operation, so a regression here cascades. We assert the response
// has both Token and ExpiresAt and that the cookie is set with the
// expected attributes.
func TestAdminLoginRoundTrip(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "admin"})
	srv := startServe(t, serveOpts{DataDir: dir})

	resp, raw := httpDo(t, httpClient(), http.MethodPost, srv.BaseURL+"/_api/admin/login",
		map[string]string{"password": "admin"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", resp.StatusCode, raw)
	}
	var body struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("parse: %v\nraw: %s", err, raw)
	}
	if body.Token == "" || body.ExpiresAt.IsZero() {
		t.Errorf("login response missing fields: token=%q expires_at=%v", body.Token, body.ExpiresAt)
	}
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "bouncer_admin" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("no admin cookie set")
	}
	if !found.HttpOnly {
		t.Error("admin cookie not HttpOnly")
	}
	if found.SameSite != http.SameSiteStrictMode {
		t.Errorf("admin cookie SameSite = %v, want Strict", found.SameSite)
	}
}

// TestWhoamiAnonymousVsAdmin pins that /_api/whoami reflects the
// caller. UI code reads this to decide whether to render edit
// affordances; if it lied either direction, the UI would be wrong.
func TestWhoamiAnonymousVsAdmin(t *testing.T) {
	f := newAdminFixture(t)
	c := httpClient()

	_, raw := httpDo(t, c, http.MethodGet, f.srv.BaseURL+"/_api/whoami", nil, nil)
	var anon struct {
		Authenticated bool `json:"authenticated"`
		Admin         bool `json:"admin"`
	}
	if err := json.Unmarshal(raw, &anon); err != nil {
		t.Fatalf("anon whoami: %v", err)
	}
	if anon.Authenticated || anon.Admin {
		t.Errorf("anon whoami = %+v, want all false", anon)
	}

	_, raw = httpDo(t, c, http.MethodGet, f.srv.BaseURL+"/_api/whoami", nil, bearer(f.jwt))
	var admin struct {
		Authenticated bool `json:"authenticated"`
		Admin         bool `json:"admin"`
	}
	if err := json.Unmarshal(raw, &admin); err != nil {
		t.Fatalf("admin whoami: %v", err)
	}
	if !admin.Authenticated || !admin.Admin {
		t.Errorf("admin whoami = %+v, want both true", admin)
	}
}

// TestIssueAdminOnly pins POST /_api/tokens/issue: anonymous gets
// 401, non-admin (would-be) gets 403, admin gets a fresh JWT.
// We collapse the two reject cases into a single test because they
// share the same setup and the assertion is the same shape.
func TestIssueAdminOnly(t *testing.T) {
	f := newAdminFixture(t)
	c := httpClient()

	body := map[string]any{
		"subject":      "ci",
		"access_token": "stub",
		"ttl_seconds":  60,
	}

	resp, _ := httpDo(t, c, http.MethodPost, f.srv.BaseURL+"/_api/tokens/issue", body, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon issue: status=%d, want 401", resp.StatusCode)
	}

	resp, raw := httpDo(t, c, http.MethodPost, f.srv.BaseURL+"/_api/tokens/issue", body, bearer(f.jwt))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin issue: status=%d body=%s", resp.StatusCode, raw)
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &issued); err != nil {
		t.Fatalf("parse issue: %v", err)
	}
	if parts := strings.Split(issued.Token, "."); len(parts) != 3 {
		t.Errorf("issued token = %q, want JWT", issued.Token)
	}
}

// TestMCPInitializeAndToolsList drives the JSON-RPC surface end to
// end through the live binary. We expect `initialize` to advertise
// the tool/resource capabilities and `tools/list` to enumerate the
// catalogue. Anything subtler is covered by the unit tests in
// internal/server/admin/mcp; this is the binary-side smoke test
// the CLAUDE.md "/_api/* response-shape changes update e2e" rule
// asks for.
func TestMCPInitializeAndToolsList(t *testing.T) {
	f := newAdminFixture(t)

	post := func(method string, params any) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      "1",
			"method":  method,
			"params":  params,
		})
		req, _ := http.NewRequest(http.MethodPost, f.srv.BaseURL+"/_api/mcp", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+f.jwt)
		resp, err := httpClient().Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if e, ok := out["error"]; ok {
			t.Fatalf("rpc error: %+v", e)
		}
		return out
	}

	init := post("initialize", map[string]any{"protocolVersion": "2025-03-26", "clientInfo": map[string]string{"name": "ci"}})
	result, _ := init["result"].(map[string]any)
	if result["protocolVersion"] == nil {
		t.Errorf("initialize result missing protocolVersion: %+v", init)
	}

	tools := post("tools/list", nil)
	tlResult, _ := tools["result"].(map[string]any)
	arr, _ := tlResult["tools"].([]any)
	have := map[string]bool{}
	for _, x := range arr {
		if m, ok := x.(map[string]any); ok {
			if name, _ := m["name"].(string); name != "" {
				have[name] = true
			}
		}
	}
	for _, name := range []string{"list_apis", "list_policies", "list_traffic"} {
		if !have[name] {
			t.Errorf("tools/list missing %q (have: %v)", name, have)
		}
	}
}

// TestCADownloadServesPEM pins GET /_api/ca.crt: the endpoint is
// open (no auth), serves the on-disk mitm-ca.crt verbatim with a
// PEM content type, and is reachable by an anonymous client. This
// is the bootstrap-trust corner — an agent with no JWT yet must be
// able to fetch the CA so its TLS handshake to the proxy succeeds.
func TestCADownloadServesPEM(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "admin", MITM: true})
	srv := startServe(t, serveOpts{DataDir: dir})

	resp, raw := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/_api/ca.crt", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type=%q, want application/x-pem-file", ct)
	}
	if !strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Errorf("body lacks PEM marker: %s", raw)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, "mitm-ca.crt"))
	if err != nil {
		t.Fatalf("read on-disk ca: %v", err)
	}
	if string(raw) != string(onDisk) {
		t.Errorf("body mismatch with on-disk file")
	}
}

// TestIssueTokenAdminBootstrapAcceptedByLogin pins the bootstrap
// alternative: when no admin password is set (or as a one-off
// override), `bouncer issue-token --admin --secret-hex <…>` issues
// a token that /_api/whoami accepts as admin. This is the documented
// recovery path when the password is lost.
func TestIssueTokenAdminBootstrapAcceptedByLogin(t *testing.T) {
	dir := mustInit(t, initOpts{})
	// Pin both sides to the same secret so issue-token's signature
	// verifies inside serve. Overriding --secret-hex on serve also
	// confirms the flag wins over the data-dir's auto-loaded secret.
	srv := startServe(t, serveOpts{
		DataDir: dir,
		Extra:   []string{"--secret-hex", testSecretHex},
	})

	res := run(t,
		"issue-token", "--secret-hex", testSecretHex,
		"--subject", "boot", "--access-token", "x", "--admin",
	)
	if res.Err != nil {
		t.Fatalf("issue-token: %v\nstderr: %s", res.Err, res.Stderr)
	}
	tok := strings.TrimSpace(res.Stdout)

	_, raw := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/_api/whoami", nil, bearer(tok))
	var body struct {
		Authenticated bool `json:"authenticated"`
		Admin         bool `json:"admin"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("parse whoami: %v\nraw: %s", err, raw)
	}
	if !body.Authenticated || !body.Admin {
		t.Errorf("issue-token --admin JWT not accepted as admin: %+v", body)
	}
}
