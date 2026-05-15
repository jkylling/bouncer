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

// TestAdminLoginRejectsBadPassword pins the 401 path: a wrong
// password returns 401 with a generic message and no cookie. The
// generic message + bcrypt-paced response is the authentication
// rate-limit story.
func TestAdminLoginRejectsBadPassword(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "admin"})
	srv := startServe(t, serveOpts{DataDir: dir})

	resp, raw := httpDo(t, httpClient(), http.MethodPost, srv.BaseURL+"/_api/admin/login",
		map[string]string{"password": "wrong"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login: status=%d body=%s, want 401", resp.StatusCode, raw)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "bouncer_admin" && c.Value != "" {
			t.Error("admin cookie set on failed login")
		}
	}
}

// TestAdminUIRedirectsAnonymous pins the browser redirect: an
// anonymous GET on /_admin lands at /_admin/login with the
// `?next=` round-trip parameter. Same redirect is tested for the
// trailing-slash variant, which chi treats as a distinct route.
func TestAdminUIRedirectsAnonymous(t *testing.T) {
	dir := mustInit(t, initOpts{})
	srv := startServe(t, serveOpts{DataDir: dir})

	for _, path := range []string{"/_admin", "/_admin/"} {
		resp, _ := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+path, nil, nil)
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET %s: status=%d, want 303", path, resp.StatusCode)
			continue
		}
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "/_admin/login") {
			t.Errorf("GET %s: Location=%q, want /_admin/login...", path, loc)
		}
	}
}

// TestAdminUIServesShellAuthed pins the authed branch: with a valid
// admin cookie, /_admin 303s to /_admin/agents (the default
// dashboard entry point) and that target serves the embedded HTML
// shell.
func TestAdminUIServesShellAuthed(t *testing.T) {
	f := newAdminFixture(t)
	c := httpClient()

	req, _ := http.NewRequest(http.MethodGet, f.srv.BaseURL+"/_admin", nil)
	req.AddCookie(f.cookie)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET /_admin: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET /_admin: status=%d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/_admin/agents" {
		t.Fatalf("GET /_admin: Location=%q, want /_admin/agents", loc)
	}

	req2, _ := http.NewRequest(http.MethodGet, f.srv.BaseURL+loc, nil)
	req2.AddCookie(f.cookie)
	resp2, err := c.Do(req2)
	if err != nil {
		t.Fatalf("GET %s: %v", loc, err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status=%d, want 200", loc, resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET %s: Content-Type=%q, want text/html", loc, ct)
	}
}

// TestAdminLoginUIServesHTML pins the password page itself. Unlike
// /_admin, /_admin/login is open (the JS would otherwise have
// nowhere to render) so an anonymous GET gets the HTML directly.
func TestAdminLoginUIServesHTML(t *testing.T) {
	dir := mustInit(t, initOpts{})
	srv := startServe(t, serveOpts{DataDir: dir})
	resp, raw := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/_admin/login", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_admin/login: status=%d", resp.StatusCode)
	}
	if !strings.Contains(string(raw), "<html") && !strings.Contains(string(raw), "<!doctype") && !strings.Contains(string(raw), "<!DOCTYPE") {
		t.Errorf("login page does not look like HTML")
	}
}

// TestDocsPathsServeAnonymously pins the open-tier doc surface: the
// orientation page plus the two authoring guides answer 200 with a
// markdown content-type and a non-empty body, no JWT required. An
// agent's denial-recovery flow follows the `next_steps.docs_policies`
// link into this surface — if it ever required auth, the recovery
// loop would deadlock.
func TestDocsPathsServeAnonymously(t *testing.T) {
	dir := mustInit(t, initOpts{})
	srv := startServe(t, serveOpts{DataDir: dir})

	for _, path := range []string{
		"/_api/docs",
		"/_api/docs/policies",
		"/_api/docs/apis",
	} {
		resp, raw := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+path, nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status=%d, want 200", path, resp.StatusCode)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
			t.Errorf("GET %s: Content-Type=%q, want text/markdown", path, ct)
		}
		if len(raw) == 0 {
			t.Errorf("GET %s: empty body", path)
		}
	}
}

// TestFaviconUnauth pins that the favicon route serves anonymously.
// A redirect-to-login on this path would mean every browser visit
// triggers an extra hop and the traffic recorder logs spurious
// no_match denials.
func TestFaviconUnauth(t *testing.T) {
	dir := mustInit(t, initOpts{})
	srv := startServe(t, serveOpts{DataDir: dir})
	resp, _ := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/favicon.ico", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("favicon: status=%d, want 200", resp.StatusCode)
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

// TestIssueAdminOnly pins POST /_api/issue/tokens: anonymous gets
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

	resp, _ := httpDo(t, c, http.MethodPost, f.srv.BaseURL+"/_api/issue/tokens", body, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon issue: status=%d, want 401", resp.StatusCode)
	}

	resp, raw := httpDo(t, c, http.MethodPost, f.srv.BaseURL+"/_api/issue/tokens", body, bearer(f.jwt))
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

// TestIssueRefreshAdminOnly mirrors TestIssueAdminOnly for the refresh
// endpoint: anonymous gets 401, admin gets a JWT, and a non-expiring
// refresh (ttl_seconds=0) omits expires_at from the response.
func TestIssueRefreshAdminOnly(t *testing.T) {
	f := newAdminFixture(t)
	c := httpClient()

	body := map[string]any{
		"subject":       "ci",
		"refresh_token": "1//rt",
		"token_url":     "https://oauth2.googleapis.com/token",
		// ttl_seconds omitted → non-expiring
	}

	resp, _ := httpDo(t, c, http.MethodPost, f.srv.BaseURL+"/_api/issue/refresh", body, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon issue-refresh: status=%d, want 401", resp.StatusCode)
	}

	resp, raw := httpDo(t, c, http.MethodPost, f.srv.BaseURL+"/_api/issue/refresh", body, bearer(f.jwt))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin issue-refresh: status=%d body=%s", resp.StatusCode, raw)
	}
	var issued struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at,omitempty"`
	}
	if err := json.Unmarshal(raw, &issued); err != nil {
		t.Fatalf("parse issue-refresh: %v", err)
	}
	if parts := strings.Split(issued.Token, "."); len(parts) != 3 {
		t.Errorf("issued refresh token = %q, want JWT", issued.Token)
	}
	if issued.ExpiresAt != "" {
		t.Errorf("expires_at = %q, want empty (non-expiring refresh)", issued.ExpiresAt)
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
	for _, name := range []string{"list_apis", "list_policies", "connections", "credentials_staged"} {
		if !have[name] {
			t.Errorf("tools/list missing %q (have: %v)", name, have)
		}
	}

	// Prompts surface (the setup body the agent walks
	// through). One smoke check; per-bundle token prompts depend on
	// installed bundles which this admin fixture doesn't load.
	prompts := post("prompts/list", nil)
	pResult, _ := prompts["result"].(map[string]any)
	pArr, _ := pResult["prompts"].([]any)
	havePrompt := map[string]bool{}
	for _, x := range pArr {
		if m, ok := x.(map[string]any); ok {
			if name, _ := m["name"].(string); name != "" {
				havePrompt[name] = true
			}
		}
	}
	if !havePrompt["setup"] {
		t.Errorf("prompts/list missing setup (have: %v)", havePrompt)
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

// TestCADownload404sWithoutMITM pins the no-MITM deployment shape:
// the route is mounted but returns 404 so a client checking for it
// sees an unambiguous "no MITM CA on this deployment".
func TestCADownload404sWithoutMITM(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "admin"})
	srv := startServe(t, serveOpts{DataDir: dir, Extra: []string{"--mitm=false"}})

	resp, _ := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/_api/ca.crt", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d, want 404 (mitm disabled)", resp.StatusCode)
	}
}

// TestInstallWrapperBakesProxyURL pins GET /install/bouncer-wrap:
// admin-authenticated request returns a POSIX shell script with the
// caller's reachable URL baked in. The /bouncer:setup MCP prompt
// instructs the agent to curl this endpoint and write the body to
// ~/.local/bin/bouncer-wrap; a regression that changes the rendered
// shape (env vars set, sha256 header) would break the bootstrap.
func TestInstallWrapperBakesProxyURL(t *testing.T) {
	f := newAdminFixture(t)
	resp, raw := httpDo(t, httpClient(), http.MethodGet,
		f.srv.BaseURL+"/install/bouncer-wrap", nil,
		http.Header{"Authorization": []string{"Bearer " + f.jwt}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	body := string(raw)
	if !strings.HasPrefix(body, "#!/bin/sh") {
		t.Errorf("body lacks shebang:\n%s", body)
	}
	if !strings.Contains(body, `BOUNCER_PROXY="`+f.srv.BaseURL+`"`) {
		t.Errorf("body does not bake proxy URL %q:\n%s", f.srv.BaseURL, body)
	}
	if !strings.Contains(body, "HTTPS_PROXY=") || !strings.Contains(body, "SSL_CERT_FILE=") {
		t.Errorf("body missing required env exports:\n%s", body)
	}
	if resp.Header.Get("X-Bouncer-Sha256") == "" {
		t.Error("X-Bouncer-Sha256 header missing")
	}
}

// TestInstallWrapperRequiresAuth pins the gating contract: an
// anonymous caller is rejected so the per-tenant render isn't leaked
// to unauthenticated requests. The error body shape mirrors other
// admin denials.
func TestInstallWrapperRequiresAuth(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "admin"})
	srv := startServe(t, serveOpts{DataDir: dir})

	resp, _ := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/install/bouncer-wrap", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("status=%d, want 401 or 403 for anonymous", resp.StatusCode)
	}
}

// TestInstallCAServesPEM pins GET /install/ca.pem: same bytes as
// /_api/ca.crt but auth-gated and served as ca.pem rather than
// bouncer-mitm-ca.crt so the /bouncer:setup prompt's
// `~/.config/bouncer/ca.pem` filename lands without renaming.
func TestInstallCAServesPEM(t *testing.T) {
	f := newAdminFixture(t)
	resp, raw := httpDo(t, httpClient(), http.MethodGet,
		f.srv.BaseURL+"/install/ca.pem", nil,
		http.Header{"Authorization": []string{"Bearer " + f.jwt}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type=%q, want application/x-pem-file", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, `filename="ca.pem"`) {
		t.Errorf("Content-Disposition=%q, want filename=\"ca.pem\"", cd)
	}
	if !strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Errorf("body lacks PEM marker: %s", raw)
	}
}

// TestLogoutClearsCookie pins POST /_api/admin/logout: the response
// sets the cookie with MaxAge=-1, which tells the browser to drop
// it. We don't try to assert the JWT itself is invalidated — the
// admin docstring is explicit that there's no revocation list, so
// the flow is "drop the cookie, JWT expires on its own ttl."
func TestLogoutClearsCookie(t *testing.T) {
	f := newAdminFixture(t)
	resp, _ := httpDo(t, httpClient(), http.MethodPost, f.srv.BaseURL+"/_api/admin/logout", nil, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status=%d, want 204", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "bouncer_admin" && c.MaxAge >= 0 {
			t.Errorf("logout cookie MaxAge=%d, want negative", c.MaxAge)
		}
	}
}

// TestIssueTokenAdminBootstrapAcceptedByLogin pins the bootstrap
// alternative: when no admin password is set (or as a one-off
// override), `bouncer issue-token --admin --dev-stub-secret` issues
// a token that /_api/whoami accepts as admin. This is the documented
// recovery path when the password is lost.
func TestIssueTokenAdminBootstrapAcceptedByLogin(t *testing.T) {
	dir := mustInit(t, initOpts{})
	// Override the secret with the dev stub so issue-token's stub
	// matches what serve will use to verify. Pass --secret-hex
	// pointing at the all-AA stub on serve, then issue via stub.
	stubHex := strings.Repeat("aa", 32)
	srv := startServe(t, serveOpts{
		DataDir: dir,
		Extra:   []string{"--secret-hex", stubHex},
	})

	res := run(t,
		"issue-token", "--dev-stub-secret",
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
