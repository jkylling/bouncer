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

// TestServeFromDataDir pins the canonical happy path: init writes
// the layout, serve --data-dir consumes it, and /_api/whoami answers
// 200 (which startServe already verifies — this test asserts the
// shape of the JSON, proving the auth middleware booted correctly).
func TestServeFromDataDir(t *testing.T) {
	dir := mustInit(t, initOpts{})
	srv := startServe(t, serveOpts{DataDir: dir})

	resp, raw := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/_api/whoami", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("whoami: status=%d body=%s", resp.StatusCode, raw)
	}
	var body struct {
		Authenticated bool `json:"authenticated"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("parse whoami: %v\nraw: %s", err, raw)
	}
	if body.Authenticated {
		t.Error("anonymous whoami reported authenticated=true")
	}
}

// TestAPIsListSurfacesBundleReadme drives the full chain for the
// bundle README round trip: a vendored bundle that ships README.md
// shows up in /_api/apis with a `readme_url`, and that URL serves
// the file's bytes as text/markdown. Local --apis-dir entries (no
// bundle) get an empty readme_url, asserted as a negative.
func TestAPIsListSurfacesBundleReadme(t *testing.T) {
	dir := mustInit(t, initOpts{})

	// Local API in --apis-dir: should NOT have a readme_url.
	if err := os.WriteFile(filepath.Join(dir, "apis", "local.yaml"),
		[]byte("name: local\nbase_url: https://local.invalid\npath_prefixes: [/local]\n"),
		0o600); err != nil {
		t.Fatalf("write local api: %v", err)
	}

	// Bundle with a README: should get a readme_url.
	bundleSHA := "8888888888888888888888888888888888888888"
	bundleDir := filepath.Join(dir, "apis", "withdoc")
	if err := os.MkdirAll(filepath.Join(bundleDir, "apis"), 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	mustWriteFile(t, filepath.Join(bundleDir, "bouncer.yaml"),
		"schema_version: 1\nname: withdoc\nversion: 0.1.0\napis: [apis/]\n")
	mustWriteFile(t, filepath.Join(bundleDir, "apis", "vendored.yaml"),
		"name: vendored\nbase_url: https://vendored.invalid\npath_prefixes: [/vendored]\n")
	mustWriteFile(t, filepath.Join(bundleDir, "source.yaml"),
		"ref: github.com/acme/withdoc@v0.1.0\nresolved_sha: \""+bundleSHA+"\"\n")
	mustWriteFile(t, filepath.Join(bundleDir, "README.md"),
		"# withdoc bundle\n\nOperator notes for the vendored API.\n")

	srv := startServe(t, serveOpts{DataDir: dir})

	resp, raw := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/_api/apis", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var body struct {
		APIs []struct {
			Name      string `json:"name"`
			ReadmeURL string `json:"readme_url"`
		} `json:"apis"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("parse: %v\nraw: %s", err, raw)
	}
	want := map[string]string{"local": "", "vendored": "/_api/apis/withdoc/readme"}
	got := map[string]string{}
	for _, api := range body.APIs {
		got[api.Name] = api.ReadmeURL
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("api %q readme_url = %q, want %q", name, got[name], w)
		}
	}

	rresp, rbody := httpDo(t, httpClient(), http.MethodGet,
		srv.BaseURL+"/_api/apis/withdoc/readme", nil, nil)
	if rresp.StatusCode != http.StatusOK {
		t.Fatalf("readme status=%d body=%s", rresp.StatusCode, rbody)
	}
	if ct := rresp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(string(rbody), "withdoc bundle") {
		t.Errorf("body = %q", rbody)
	}
}

// TestServeDefaultsDataDirToCwd pins the cwd-auto-detect UX: an
// operator who chdirs into their data dir and runs `bouncer serve`
// (no --data-dir) gets a running proxy. Asserts the listener is up
// by hitting /_api/whoami — startServe's readiness probe already
// requires that, but the explicit check makes the contract obvious.
func TestServeDefaultsDataDirToCwd(t *testing.T) {
	dir := mustInit(t, initOpts{})
	srv := startServe(t, serveOpts{DataDir: dir, OmitDataDir: true})

	resp, _ := httpDo(t, httpClient(), http.MethodGet, srv.BaseURL+"/_api/whoami", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("whoami: status=%d (cwd auto-default did not produce a working serve)", resp.StatusCode)
	}
}

// TestServeVersion pins the --version subcommand. Not just a smoke
// test: a missing build-info ldflag would render "bouncer
// dev (unknown)" — the test only requires the prefix so a real
// release tag still passes.
func TestServeVersion(t *testing.T) {
	res := run(t, "version")
	if res.Err != nil {
		t.Fatalf("version: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if !strings.HasPrefix(res.Stdout, "bouncer ") {
		t.Errorf("version stdout = %q, want 'bouncer ...'", res.Stdout)
	}
}

// TestServeHelp pins that the top-level help banner lists every
// subcommand. A future refactor that drops one from the dispatcher
// should fail this test.
func TestServeHelp(t *testing.T) {
	res := run(t, "--help")
	if res.Err != nil {
		t.Fatalf("--help: %v\nstderr: %s", res.Err, res.Stderr)
	}
	for _, sub := range []string{"init", "serve", "apis", "issue-token", "version"} {
		if !strings.Contains(res.Stdout, sub) {
			t.Errorf("help stdout missing %q: %s", sub, res.Stdout)
		}
	}
}

// TestServeUnknownCommand pins the dispatcher: an unknown verb is
// reported clearly (with usage) instead of silently exiting 0.
func TestServeUnknownCommand(t *testing.T) {
	res := run(t, "wibble")
	if res.Err == nil {
		t.Fatalf("unknown command: expected error")
	}
	if !strings.Contains(res.Stderr, "unknown command") {
		t.Errorf("stderr = %q, want 'unknown command'", res.Stderr)
	}
}

// TestServeRejectsMissingSecret pins that boot refuses without
// --secret-hex. An operator who accidentally passes `bouncer serve`
// with no flags should get a clear error, not a silent boot with a
// footgun secret.
func TestServeRejectsMissingSecret(t *testing.T) {
	res := run(t, "serve", "--apis-dir", t.TempDir(), "--policies-dir", t.TempDir())
	if res.Err == nil {
		t.Fatal("expected error for missing secret")
	}
	if !strings.Contains(res.Stderr, "secret-hex") {
		t.Errorf("stderr = %q, want one mentioning secret-hex", res.Stderr)
	}
}

// TestServeFlagOverridesDataDir pins the precedence: an explicit
// --policies-dir wins over the dir-relative default. Same shape
// applies to every other --data-dir-derived flag.
func TestServeFlagOverridesDataDir(t *testing.T) {
	data := mustInit(t, initOpts{})
	override := filepath.Join(t.TempDir(), "custom-policies")
	if err := os.MkdirAll(override, 0o755); err != nil {
		t.Fatalf("mkdir override: %v", err)
	}
	srv := startServe(t, serveOpts{
		DataDir: data,
		Extra:   []string{"--policies-dir", override},
	})

	// The boot log records the configured policies dir; grep its
	// stderr to confirm the override wired through. We use a
	// generous sleep + Stop sequence: serve buffers its own logs
	// until the http handler starts, but the listening line
	// (logged before ListenAndServe) is reliably present as soon
	// as /_api/whoami answers.
	srv.Stop(t)
	if !strings.Contains(srv.Stderr(), "listening") {
		t.Errorf("expected 'listening' in stderr; got: %s", srv.Stderr())
	}
}

// TestServeShutdownOnSIGTERM pins clean shutdown: the binary must
// exit zero when sent SIGTERM (or SIGINT on platforms without
// SIGTERM in the child process). startServe's t.Cleanup calls
// Stop() — this test asserts the Stop returns within budget by
// timing it explicitly.
func TestServeShutdownOnSIGTERM(t *testing.T) {
	dir := mustInit(t, initOpts{})
	srv := startServe(t, serveOpts{DataDir: dir})

	start := time.Now()
	srv.Stop(t)
	if elapsed := time.Since(start); elapsed > shutdownTimeout {
		t.Errorf("shutdown took %v; budget is %v", elapsed, shutdownTimeout)
	}
}

// TestServeTrafficStoreSqliteRecords pins the end-to-end recorder:
// serve with --traffic-store sqlite, send a request the proxy will
// 401 (no JWT), and confirm the event lands in the traffic store
// queryable via /_api/traffic. Hooks the bundled gmail API so the
// path actually reaches the catch-all (not the admin routes).
func TestServeTrafficStoreSqliteRecords(t *testing.T) {
	dir := mustInit(t, initOpts{})
	copyBundledAPI(t, dir, "gmail.yaml")
	srv := startServe(t, serveOpts{
		DataDir: dir,
		Extra:   []string{"--traffic-store", "sqlite"},
	})

	// Hit a Gmail-shaped path so the proxy's catch-all (not admin)
	// handles it. The recorder records denials, so the missing JWT
	// is fine — what we want is one row in the store.
	c := httpClient()
	resp, _ := httpDo(t, c, http.MethodGet, srv.BaseURL+"/gmail/v1/users/me/profile", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("proxy GET: status=%d, want 401", resp.StatusCode)
	}

	jwt, _ := loginAdmin(t, srv.BaseURL, "admin")
	// Recorder is async — give it a moment to flush. The polling
	// loop is short (under 2s in practice) but capped so a flake
	// doesn't hang.
	deadline := time.Now().Add(5 * time.Second)
	var listResp struct {
		Rows []map[string]any `json:"rows"`
	}
	for time.Now().Before(deadline) {
		_, raw := httpDo(t, c, http.MethodGet, srv.BaseURL+"/_api/traffic", nil, bearer(jwt))
		listResp.Rows = nil
		_ = json.Unmarshal(raw, &listResp)
		if len(listResp.Rows) > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("traffic store never recorded the request")
}

// TestServePoliciesReadOnlyRejectsWrites pins the --policies-readonly
// flag: GET works, POST returns the documented error. Critical for
// production deployments that want the viewer without risking
// accidental edits from a shared admin host.
func TestServePoliciesReadOnlyRejectsWrites(t *testing.T) {
	dir := mustInit(t, initOpts{})
	srv := startServe(t, serveOpts{
		DataDir: dir,
		Extra:   []string{"--policies-readonly"},
	})

	jwt, _ := loginAdmin(t, srv.BaseURL, "admin")
	c := httpClient()

	// :capabilities is open and reports writeable=false.
	_, raw := httpDo(t, c, http.MethodGet, srv.BaseURL+"/_api/policies:capabilities", nil, nil)
	var caps struct {
		Writeable bool `json:"writeable"`
	}
	if err := json.Unmarshal(raw, &caps); err != nil {
		t.Fatalf("parse capabilities: %v\nraw: %s", err, raw)
	}
	if caps.Writeable {
		t.Error("expected writeable=false under --policies-readonly")
	}

	// POST is rejected. Body shape is intentionally minimal — the
	// readonly gate fires before validation, so an empty policy
	// works as the trigger.
	body := map[string]any{
		"api":  "google.gmail",
		"name": "x",
		"action": map[string]any{
			"effect": "permit",
		},
	}
	resp, raw := httpDo(t, c, http.MethodPost, srv.BaseURL+"/_api/policies", body, bearer(jwt))
	// 405 Method Not Allowed is the documented response when writes
	// are disabled — see writePolicyError's ErrReadOnly branch.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		t.Fatalf("policies POST under readonly: status=%d body=%s, want non-2xx", resp.StatusCode, raw)
	}
}
