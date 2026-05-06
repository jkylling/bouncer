//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// readyTimeout caps how long startServe waits for the proxy to start
// answering /_api/whoami. 10s is generous; a healthy boot is well
// under a second on a developer laptop.
const readyTimeout = 10 * time.Second

// shutdownTimeout caps how long Stop() waits for the binary to exit
// after SIGTERM. The serve loop's own shutdownTimeout is 10s; we add
// a small margin so a clean shutdown finishes inside our budget
// before we fall back to SIGKILL.
const shutdownTimeout = 12 * time.Second

// runResult carries everything a one-shot subcommand invocation
// produced. Stdout and Stderr are kept separate (rather than merged)
// because half the validation-error tests assert on stderr and we
// want stdout-clean for ones that pipe a JWT.
type runResult struct {
	Stdout string
	Stderr string
	Err    error
}

// run executes the bouncer binary with the given args and returns
// its captured streams. Non-zero exit produces a non-nil Err but the
// output is still returned — many tests want to assert on the error
// banner the binary printed before exiting.
func run(t *testing.T, args ...string) runResult {
	t.Helper()
	return runEnv(t, nil, args...)
}

// runEnv is run() with a per-call env overlay. Empty values delete
// the variable. Inherited env passes through unchanged.
func runEnv(t *testing.T, env map[string]string, args ...string) runResult {
	t.Helper()
	return runEnvDir(t, env, "", args...)
}

// runEnvDir is runEnv() with a per-call working directory. Empty dir
// inherits the test's cwd. Used by tests that exercise cwd-derived
// defaults (e.g. issue-token's ./secret.hex auto-load).
func runEnvDir(t *testing.T, env map[string]string, dir string, args ...string) runResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bouncerBin, args...)
	cmd.Env = mergeEnv(os.Environ(), env)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return runResult{Stdout: stdout.String(), Stderr: stderr.String(), Err: err}
}

// mergeEnv overlays add onto base, deleting keys whose value is "".
// A missing key in `add` means "leave the base value alone".
func mergeEnv(base []string, add map[string]string) []string {
	if len(add) == 0 {
		return base
	}
	out := make([]string, 0, len(base)+len(add))
	for _, kv := range base {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if _, override := add[k]; override {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range add {
		if v == "" {
			continue
		}
		out = append(out, k+"="+v)
	}
	return out
}

// initOpts configures mustInit. Zero values are sensible — the
// resulting data dir is a fresh tempdir with admin password "admin"
// and no MITM CA.
type initOpts struct {
	// Dir, when non-empty, is the data dir to bootstrap into. Empty
	// means "create a fresh t.TempDir()".
	Dir string
	// Password sets --admin-password. Empty defaults to "admin".
	Password string
	// MITM, when true, also generates the MITM CA.
	MITM bool
	// Extra flags appended after the standard ones (e.g. --force).
	Extra []string
}

// mustInit runs `bouncer init` and returns the data dir. Tests
// use this when they need a serve-ready dir; per-flag init tests
// call run() directly so they can assert on stderr.
func mustInit(t *testing.T, opts initOpts) string {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = filepath.Join(t.TempDir(), "data")
	}
	if opts.Password == "" {
		opts.Password = "admin"
	}
	args := []string{"init", opts.Dir, "--admin-password", opts.Password}
	if opts.MITM {
		args = append(args, "--mitm")
	}
	args = append(args, opts.Extra...)
	res := run(t, args...)
	if res.Err != nil {
		t.Fatalf("bouncer init: err=%v\nstdout: %s\nstderr: %s", res.Err, res.Stdout, res.Stderr)
	}
	return opts.Dir
}

// freePort binds a 127.0.0.1 ephemeral port, closes the listener,
// and returns the port. There is a tiny TOCTOU window between the
// close and the binary re-binding, but kernel ephemeral-port
// rotation makes a collision rare enough that retrying is overkill
// for a developer-box test suite.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// serveProc is the handle returned by startServe. BaseURL is the
// http://127.0.0.1:PORT origin a test points its client at. Stop()
// is idempotent — t.Cleanup hooks call it at end-of-test, but a
// test that wants to grep stdout/stderr after shutdown can call it
// early.
type serveProc struct {
	BaseURL string
	cmd     *exec.Cmd

	mu       sync.Mutex
	stopped  bool
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	doneCh   chan error
	cancelFn context.CancelFunc
}

// Stop sends SIGTERM and waits for the binary to exit, falling back
// to SIGKILL after shutdownTimeout. Safe to call multiple times.
func (s *serveProc) Stop(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.mu.Unlock()

	if s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(os.Interrupt)
	}
	select {
	case <-s.doneCh:
	case <-time.After(shutdownTimeout):
		t.Logf("serve: hard-killing after %s", shutdownTimeout)
		s.cancelFn()
		<-s.doneCh
	}
}

// Stdout / Stderr return whatever the process has emitted so far. A
// test that grep's the boot log calls these after a brief sleep or
// after Stop() flushes the writer.
func (s *serveProc) Stdout() string { return s.stdout.String() }
func (s *serveProc) Stderr() string { return s.stderr.String() }

// serveOpts configures startServe. Empty values default to:
// in-memory stores (no sqlite), bind 127.0.0.1:<freePort>, the
// caller-supplied data dir.
type serveOpts struct {
	// DataDir is the dir bootstrapped by mustInit. Required unless
	// OmitDataDir is set.
	DataDir string
	// OmitDataDir, when true, runs `bouncer serve` without the
	// --data-dir flag and chdirs into DataDir instead. Used to
	// exercise the cwd-default branch of loadConfig.
	OmitDataDir bool
	// Extra flags appended after --data-dir / --addr. Tests use
	// this to flip --policies-readonly, --traffic-store sqlite, etc.
	Extra []string
	// Env overlay (e.g. setting BOUNCER_LOG_LEVEL=debug).
	Env map[string]string
}

// startServe launches `bouncer serve --data-dir <opts.DataDir>`
// on a fresh ephemeral port and waits for /_api/whoami to answer
// 200. Test cleanup is registered automatically — the caller never
// needs to remember to Stop() unless it wants early shutdown.
func startServe(t *testing.T, opts serveOpts) *serveProc {
	t.Helper()
	if opts.DataDir == "" {
		t.Fatal("startServe: DataDir is required")
	}
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	args := []string{"serve", "--addr", addr}
	if !opts.OmitDataDir {
		args = append(args, "--data-dir", opts.DataDir)
	}
	args = append(args, opts.Extra...)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bouncerBin, args...)
	cmd.Env = mergeEnv(os.Environ(), opts.Env)
	if opts.OmitDataDir {
		// Subprocess cwd = the data dir, so loadConfig's
		// IsInitialized(".") check picks it up.
		cmd.Dir = opts.DataDir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("serve start: %v", err)
	}

	s := &serveProc{
		BaseURL:  "http://" + addr,
		cmd:      cmd,
		stdout:   &stdout,
		stderr:   &stderr,
		doneCh:   make(chan error, 1),
		cancelFn: cancel,
	}
	go func() { s.doneCh <- cmd.Wait() }()
	t.Cleanup(func() { s.Stop(t) })

	if err := waitReady(s.BaseURL, readyTimeout); err != nil {
		s.Stop(t)
		t.Fatalf("serve never became ready: %v\nstdout: %s\nstderr: %s",
			err, s.stdout.String(), s.stderr.String())
	}
	return s
}

// waitReady polls /_api/whoami until it returns 200 or timeout
// elapses. /_api/whoami is the cheapest open endpoint — no auth, no
// store reads — so a successful poll proves the listener is up
// without measuring anything else.
func waitReady(baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/_api/whoami")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("readiness probe timed out")
}

// httpClient returns a one-off client that does not follow
// redirects (so tests can assert on 303 → /_admin/login) and shares
// no cookie jar across calls (each test that needs a session builds
// its own jar via loginAdmin).
func httpClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// httpDo is the everyday HTTP helper. body is JSON-marshalled when
// non-nil; the response body is fully consumed and returned so the
// caller can re-decode without worrying about the underlying stream.
func httpDo(t *testing.T, c *http.Client, method, target string, body any, hdr http.Header) (*http.Response, []byte) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		buf = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, target, buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, raw
}

// loginAdmin POSTs to /_api/admin/login and returns the JWT plus
// the Set-Cookie session value. Tests use the JWT as a Bearer token
// and the cookie as an alternative session for browser-style flows.
func loginAdmin(t *testing.T, baseURL, password string) (jwt string, cookie *http.Cookie) {
	t.Helper()
	resp, raw := httpDo(t, httpClient(), http.MethodPost, baseURL+"/_api/admin/login",
		map[string]string{"password": password}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", resp.StatusCode, raw)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("login: parse: %v\nraw: %s", err, raw)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "bouncer_admin" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatalf("login: no admin cookie in response")
	}
	return body.Token, cookie
}

// bearer returns http.Header with the Authorization: Bearer ... set.
// Tiny convenience for the many tests that just need a single
// admin-bearing request.
func bearer(jwt string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+jwt)
	return h
}

// fileMode returns the mode bits of path (or fails the test). Used
// by init tests to assert the secret/key files are 0o600.
func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

// mustReadFile is os.ReadFile + t.Fatalf on error. Saves a guarded
// read at every test site that just wants the bytes.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

// writeCredentialsFile drops a flat-shape Google credentials JSON
// (client_id + client_secret + refresh_token) into dir and returns
// the path. Issue-token's credentials-file mode validates the
// JSON shape, so the bytes have to be plausible — but no network
// is touched, so the values are arbitrary placeholders.
func writeCredentialsFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "google-creds.json")
	body := `{
  "client_id": "test-client.apps.googleusercontent.com",
  "client_secret": "test-secret",
  "refresh_token": "1//0g.refresh"
}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write google-creds.json: %v", err)
	}
	return path
}

// copyBundledAPI copies one of the bundled API specs from
// testdata/apis/ into the data dir's apis/ subfolder, so tests that
// need a routable upstream path don't reinvent a YAML stub. Production
// users get the same specs via `bouncer apis add
// github.com/jkylling/bouncer-gws@<ref>`; testdata/ is the test-only
// copy, by Go convention.
// Returns the basename copied (e.g. "gmail.yaml").
func copyBundledAPI(t *testing.T, dataDir, name string) string {
	t.Helper()
	src := filepath.Join(repoRoot(), "testdata", "apis", name)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read bundled api %s: %v", src, err)
	}
	dst := filepath.Join(dataDir, "apis", name)
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	return name
}
