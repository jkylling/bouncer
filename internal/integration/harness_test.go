//go:build integration

// Package integration is the Go counterpart of `rust-impl/tests/common`:
// helpers for end-to-end tests that run the proxy against real Google
// APIs.
//
// All files in this package are `_test.go` files gated by the
// `integration` build tag, so they are excluded from `go test ./...`.
// Opt in with
//
//	go test -tags=integration ./internal/integration/...
//
// Reads credentials from `<repo>/.secrets/`:
//
//	google-token.json              — refresh_token + initial access_token
//	oauth-desktop-credentials.json — client_id / client_secret for refresh
//
// The bound account holds the seed fixtures (Gmail labels + messages,
// Drive folder + files, Calendar events) planted by the Rust impl's
// `real_*` seeders. Sheets / Docs fixtures are seeded on demand by the
// `EnsureSpreadsheet` / `EnsureDocument` helpers.
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/apiclient"
	"github.com/jkylling/bouncer/internal/auth"
	rt "github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	"github.com/jkylling/bouncer/internal/server"
)

// User identifier embedded in the issued proxy JWT.
const proxyUser = "integration-test"

// 32-byte fixed server secret used by the proxy's auth keys. Tests do
// not interop with the production server, so this can stay constant.
var proxySecret = func() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = 0x2a
	}
	return s
}()

// WorkspaceRoot returns the absolute path to the workspace dir that
// hosts both this repo and the sibling `.secrets/` directory.
// Anchored from this source file's location so tests work regardless
// of cwd.
func WorkspaceRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("integration: runtime.Caller failed")
	}
	// .../<repo>/internal/integration/harness_test.go → .../<repo>/..
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// RepoRoot returns the absolute path to the bouncer repo root (the
// directory holding go.mod). Used by tests that need to load
// in-tree assets like testdata/apis.
func RepoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("integration: runtime.Caller failed")
	}
	// .../<repo>/internal/integration/harness_test.go → .../<repo>
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// ---------------------------------------------------------------------------
// OAuth refresh — cached for the test process lifetime.
// ---------------------------------------------------------------------------

var (
	upstreamOnce  sync.Once
	upstreamToken string
	upstreamErr   error
)

// UpstreamAccessToken returns a fresh OAuth2 access token by refreshing
// the long-lived refresh token in `.secrets/google-token.json`. Cached
// per-process so the dozens of fixture lookups in a test run don't burn
// rate limit on the token endpoint.
func UpstreamAccessToken(t *testing.T) string {
	t.Helper()
	upstreamOnce.Do(func() {
		upstreamToken, upstreamErr = refreshGoogleAccessToken()
	})
	if upstreamErr != nil {
		t.Fatalf("refresh google access token: %v", upstreamErr)
	}
	return upstreamToken
}

func refreshGoogleAccessToken() (string, error) {
	root := WorkspaceRoot()
	tokFile := filepath.Join(root, ".secrets", "google-token.json")
	credFile := filepath.Join(root, ".secrets", "oauth-desktop-credentials.json")

	var tok struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := readJSON(tokFile, &tok); err != nil {
		return "", fmt.Errorf("%s: %w", tokFile, err)
	}
	if tok.RefreshToken == "" {
		return "", fmt.Errorf("%s: refresh_token missing", tokFile)
	}

	var creds struct {
		Installed struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		} `json:"installed"`
	}
	if err := readJSON(credFile, &creds); err != nil {
		return "", fmt.Errorf("%s: %w", credFile, err)
	}
	if creds.Installed.ClientID == "" || creds.Installed.ClientSecret == "" {
		return "", fmt.Errorf("%s: client_id/client_secret missing", credFile)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tok.RefreshToken)
	form.Set("client_id", creds.Installed.ClientID)
	form.Set("client_secret", creds.Installed.ClientSecret)

	req, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("refresh failed (%s) — regenerate .secrets/google-token.json: %s",
			resp.Status, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token: %s", body)
	}
	return out.AccessToken, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// ---------------------------------------------------------------------------
// Proxy construction.
// ---------------------------------------------------------------------------

// Proxy is the harness's view of a running test proxy: the httptest
// server, the JWT to send as the bearer, and a shutdown hook.
type Proxy struct {
	URL string
	JWT string

	server *httptest.Server
}

// Close shuts down the underlying httptest server.
func (p *Proxy) Close() { p.server.Close() }

// BuildProxy compiles every bundled API from `testdata/apis` into
// a shared Runtime, attaches the supplied policies, fronts the runtime
// with a real HTTP server, and returns a ready-to-use Proxy bound to
// the upstream Google credentials. The server routes each request to
// the API whose actions claim it; apiName is retained as a sanity
// check that the named API actually loaded.
func BuildProxy(t *testing.T, apiName string, policies []models.Policy) *Proxy {
	t.Helper()
	apis := loadAllAPIs(t)
	builder := rt.NewBuilder()
	for i := range apis {
		if err := builder.AddAPI(&apis[i]); err != nil {
			t.Fatalf("AddAPI %q: %v", apis[i].Name, err)
		}
	}
	runtime, err := builder.Build()
	if err != nil {
		t.Fatalf("compile apis: %v", err)
	}
	for i := range policies {
		if err := runtime.AddPolicy(&policies[i]); err != nil {
			t.Fatalf("AddPolicy %q: %v", policies[i].Name, err)
		}
	}
	if runtime.API(apiName) == nil {
		t.Fatalf("api %q not found in shared runtime", apiName)
	}

	keys, err := auth.FromSecret(proxySecret)
	if err != nil {
		t.Fatalf("server keys: %v", err)
	}

	access := UpstreamAccessToken(t)
	httpClient := &http.Client{Timeout: 30 * time.Second}

	factory := func(name string, creds auth.AccessCreds) (compiled.PhysicalAPI, error) {
		api := runtime.API(name)
		if api == nil {
			return nil, fmt.Errorf("api %q not registered", name)
		}
		extra := make([]apiclient.Header, 0, len(creds.Headers))
		for _, h := range creds.Headers {
			extra = append(extra, apiclient.Header{Name: h.Name, Value: h.Value})
		}
		return apiclient.New(httpClient, api.BaseURL(), creds.AccessToken, extra)
	}

	srv := server.NewServer(server.Dependencies{
		Runtime:    runtime,
		Keys:       keys,
		HTTPClient: httpClient,
		APIFactory: factory,
	})
	hs := httptest.NewServer(srv.Router())

	jwt, err := auth.IssueAccessToken(keys, proxyUser, auth.AccessCreds{AccessToken: access}, time.Hour, false)
	if err != nil {
		hs.Close()
		t.Fatalf("issue proxy token: %v", err)
	}

	t.Cleanup(hs.Close)
	return &Proxy{URL: hs.URL, JWT: jwt, server: hs}
}

func loadAllAPIs(t *testing.T) []models.API {
	t.Helper()
	apisDir := filepath.Join(RepoRoot(), "testdata", "apis")
	apis, err := models.FromYAMLDir[models.API](apisDir)
	if err != nil {
		t.Fatalf("load apis from %s: %v", apisDir, err)
	}
	return apis
}

// ---------------------------------------------------------------------------
// Request helpers + outcome assertion.
// ---------------------------------------------------------------------------

// Get issues an authenticated GET against the proxy.
func (p *Proxy) Get(t *testing.T, path string) (status int, body []byte) {
	t.Helper()
	return p.Do(t, "GET", path, nil)
}

// Do issues an authenticated request with the given method, path, and
// optional JSON-marshallable body. The bearer is the proxy JWT.
func (p *Proxy) Do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, p.URL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.JWT)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// Outcome pairs a path with the HTTP status the proxy is expected to
// return for it.
type Outcome struct {
	Path   string
	Status int
}

// ExpectOutcomes asserts each (path, status) pair against the proxy
// using a GET. Reports every mismatch in one go to make policy-tuning
// loops faster.
func (p *Proxy) ExpectOutcomes(t *testing.T, outcomes []Outcome) {
	t.Helper()
	for _, o := range outcomes {
		got, body := p.Get(t, o.Path)
		if got != o.Status {
			t.Errorf("%s: got %d, want %d\n  body: %s", o.Path, got, o.Status, body)
		}
	}
}
