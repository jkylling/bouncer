//go:build ui

package uitest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

// adminPassword is the password every uitest provisions the test
// bouncer with via $BOUNCER_ADMIN_PASSWORD. The same value gets
// typed into the login form.
const adminPassword = "uitest-password"

// pwInstance holds the playwright + browser handles, lazily started
// on the first test and torn down by TestMain. One browser is shared
// across tests; each test gets its own BrowserContext (a clean
// cookie jar / storage).
type pwInstance struct {
	pw      *playwright.Playwright
	browser playwright.Browser
}

// global is the per-package handles. Initialised in TestMain so
// every Test* sees the same playwright + bouncer binary.
var (
	global     pwInstance
	bouncerBin string
)

// TestMain compiles the bouncer binary once and starts playwright;
// teardown happens in reverse on return.
func TestMain(m *testing.M) {
	// Build the bouncer binary into a per-package temp dir. Reusing
	// `go test`'s working dir as the build CWD so go.mod is picked up.
	tmp, err := os.MkdirTemp("", "uitest-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdtemp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)
	bouncerBin = filepath.Join(tmp, "bouncer")
	if runtime.GOOS == "windows" {
		bouncerBin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bouncerBin, "./cmd/bouncer")
	cmd.Dir = repoRoot()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "go build:", err)
		os.Exit(1)
	}

	// Launch playwright + a single Chromium that every test shares.
	pw, err := playwright.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "playwright.Run (did you forget `go run ./uitest/cmd/install-playwright`?):", err)
		os.Exit(1)
	}
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "chromium launch:", err)
		_ = pw.Stop()
		os.Exit(1)
	}
	global = pwInstance{pw: pw, browser: browser}

	code := m.Run()

	_ = browser.Close()
	_ = pw.Stop()
	os.Exit(code)
}

// repoRoot returns the bouncer module root by walking up from this
// source file. The uitest package always lives at <root>/uitest/.
func repoRoot() string {
	_, here, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(here))
}

// bouncerProc is a running `bouncer serve` subprocess and the URL it
// listens on. Tests get one from startBouncer; the registered cleanup
// SIGTERMs the process at test end.
type bouncerProc struct {
	BaseURL string
	cmd     *exec.Cmd
	dataDir string
}

// startBouncer boots `bouncer serve --init --mitm=false` against a
// fresh data dir on a random local port. Returns once `/_admin/login`
// responds. The whole thing is registered for cleanup so a test that
// fails mid-flight still tears down.
func startBouncer(t *testing.T) *bouncerProc {
	return startBouncerWithAPIs(t, nil)
}

// startBouncerWithAPIs is startBouncer plus a slice of API-yaml
// filenames (resolved against <repo-root>/testdata/apis) copied into
// the data dir's apis subdir before serve starts. Tests that need a
// registered API to attach policies / traffic to use this.
func startBouncerWithAPIs(t *testing.T, apiYAMLs []string) *bouncerProc {
	t.Helper()
	dataDir := t.TempDir()
	if len(apiYAMLs) > 0 {
		apisDir := filepath.Join(dataDir, "apis")
		if err := os.MkdirAll(apisDir, 0o755); err != nil {
			t.Fatalf("mkdir apis: %v", err)
		}
		for _, name := range apiYAMLs {
			src := filepath.Join(repoRoot(), "testdata", "apis", name)
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read %s: %v", src, err)
			}
			if err := os.WriteFile(filepath.Join(apisDir, name), data, 0o644); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	port := pickPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cmd := exec.Command(bouncerBin,
		"serve",
		"--init",
		"--data-dir", dataDir,
		"--mitm=false",
		"--addr", addr,
	)
	cmd.Env = append(os.Environ(),
		"BOUNCER_ADMIN_PASSWORD="+adminPassword,
	)
	// Pipe to a buffer so a failing test can dump the bouncer's
	// stdout/stderr alongside the playwright trace.
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bouncer: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("bouncer log:\n%s", buf.String())
		}
	})
	base := "http://" + addr
	if err := waitReady(base, 5*time.Second); err != nil {
		t.Fatalf("bouncer ready: %v\nlog:\n%s", err, buf.String())
	}
	return &bouncerProc{BaseURL: base, cmd: cmd, dataDir: dataDir}
}

// pickPort returns an ephemeral local port. The OS may re-issue it
// between the Listener.Close() and the bouncer process binding, but
// the window is tiny and `bouncer serve` would fail loudly enough
// that a flake here surfaces clearly.
func pickPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// waitReady polls /_admin/login until it returns 200 or the budget
// expires. Login is the cheapest endpoint to probe since it bypasses
// the policy middleware via the embedded login policy.
func waitReady(base string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/_admin/login")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(80 * time.Millisecond)
	}
	return fmt.Errorf("not ready after %s", budget)
}

// session bundles a BrowserContext + Page + base URL for one test.
// Use newSession(t, proc) to spin one up; teardown is automatic.
//
// console / pageErrors accumulate JS-side failures fired during the
// session. The Cleanup hook on the owning *testing.T reports them as
// test errors at teardown so any test that drives the UI catches a
// regression where a page silently throws or logs console.error.
type session struct {
	t       *testing.T
	proc    *bouncerProc
	ctx     playwright.BrowserContext
	page    playwright.Page
	shotDir string
	step    int

	jsMu          sync.Mutex
	console       []string
	pageErrors    []string
	allowedErrors []string
}

func matchesAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// allowConsoleError opts the session out of the console.error
// tripwire for any message containing substr. Use sparingly: a
// browser logs failed fetches as console.error, so a test that
// drives a deliberate-failure path (e.g. POST → 401) needs to
// declare the expected message here, otherwise the cleanup hook
// fails the test on the very behaviour it's exercising.
func (s *session) allowConsoleError(substr string) {
	s.jsMu.Lock()
	defer s.jsMu.Unlock()
	s.allowedErrors = append(s.allowedErrors, substr)
}

// newSession creates a fresh BrowserContext on the shared browser and
// arranges teardown. Each test should call this once.
func newSession(t *testing.T, proc *bouncerProc) *session {
	t.Helper()
	ctx, err := global.browser.NewContext(playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: 1280, Height: 800},
	})
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	page, err := ctx.NewPage()
	if err != nil {
		_ = ctx.Close()
		t.Fatalf("new page: %v", err)
	}
	shotDir := filepath.Join(repoRoot(), "uitest", "screenshots", t.Name())
	_ = os.MkdirAll(shotDir, 0o755)
	s := &session{t: t, proc: proc, ctx: ctx, page: page, shotDir: shotDir}

	// console.error and uncaught exceptions both indicate the JS
	// shipped on a page is broken — fail the test that drove the
	// session if either fires.
	page.OnConsole(func(msg playwright.ConsoleMessage) {
		if msg.Type() != "error" {
			return
		}
		s.jsMu.Lock()
		s.console = append(s.console, msg.Text())
		s.jsMu.Unlock()
	})
	page.OnPageError(func(err error) {
		s.jsMu.Lock()
		s.pageErrors = append(s.pageErrors, err.Error())
		s.jsMu.Unlock()
	})

	t.Cleanup(func() {
		_ = ctx.Close()
		s.jsMu.Lock()
		defer s.jsMu.Unlock()
		for _, e := range s.pageErrors {
			t.Errorf("uncaught JS exception during %s: %s", t.Name(), e)
		}
		for _, e := range s.console {
			if matchesAny(e, s.allowedErrors) {
				continue
			}
			t.Errorf("console.error during %s: %s", t.Name(), e)
		}
	})
	return s
}

// login fills in the admin password form and waits for the
// post-login redirect to land. The login form posts via fetch and
// then location.replace(...), so we wait for the response *and* the
// next navigation — the URL glob "**/_admin/**" alone would match
// the still-pending /_admin/login page.
func (s *session) login() {
	s.t.Helper()
	if _, err := s.page.Goto(s.proc.BaseURL + "/_admin/login"); err != nil {
		s.t.Fatalf("goto login: %v", err)
	}
	if err := s.page.Locator(`input[name="password"]`).Fill(adminPassword); err != nil {
		s.t.Fatalf("fill password: %v", err)
	}
	// Wait for the POST to land *and* the resulting nav. Pair via
	// ExpectResponse so the fetch must finish before we proceed.
	_, err := s.page.ExpectResponse("**/_api/admin/login", func() error {
		return s.page.Locator(`form button[type="submit"]`).Click()
	})
	if err != nil {
		s.t.Fatalf("submit login: %v", err)
	}
	// Wait until the URL is no longer the login page.
	if err := s.page.WaitForURL(func(url string) bool {
		return !strings.Contains(url, "/_admin/login")
	}); err != nil {
		s.t.Fatalf("wait login redirect: %v", err)
	}
}

// shot takes a full-page screenshot under <repo>/uitest/screenshots/<test>/<step>-<name>.png.
// step counter increments so the filename sort matches the call order.
func (s *session) shot(name string) {
	s.t.Helper()
	s.step++
	path := filepath.Join(s.shotDir, fmt.Sprintf("%02d-%s.png", s.step, sanitize(name)))
	if _, err := s.page.Screenshot(playwright.PageScreenshotOptions{
		Path:     playwright.String(path),
		FullPage: playwright.Bool(true),
	}); err != nil {
		s.t.Logf("screenshot %s: %v", name, err)
	}
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '/' || r == '\\' {
			return '-'
		}
		return r
	}, s)
}

// adminHTTP returns an http.Client with a cookie jar that carries
// the admin session, plus the base URL. Test bodies use it for
// out-of-band assertions ("did the wizard's POST land on disk?")
// without rebuilding the request shape every time.
func adminHTTP(t *testing.T, proc *bouncerProc) (*http.Client, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	cli := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	body := bytes.NewBufferString(`{"password":"` + adminPassword + `"}`)
	resp, err := cli.Post(proc.BaseURL+"/_api/admin/login", "application/json", body)
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin login: HTTP %d", resp.StatusCode)
	}
	return cli, proc.BaseURL
}

// getJSON GETs url, decodes into dst, fails the test on any non-2xx.
func getJSON(t *testing.T, cli *http.Client, url string, dst any) {
	t.Helper()
	resp, err := cli.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("get %s: HTTP %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

// postJSON POSTs body to url, decodes into dst, fails on non-2xx.
func postJSON(t *testing.T, cli *http.Client, url string, body, dst any) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := cli.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := readAll(resp.Body)
		t.Fatalf("post %s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	if dst == nil {
		return
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

func readAll(r interface{ Read([]byte) (int, error) }) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			if err.Error() == "EOF" {
				return sb.String(), nil
			}
			return sb.String(), err
		}
	}
}

// suppress unused warnings on helpers some tests don't touch — the
// compiler complains if a test file doesn't use a helper that's not
// exported. sync.Once is harmless and self-documenting.
var _ = sync.Once{}
var _ = context.Background
