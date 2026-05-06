package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// caTestServer mounts MountCA on a fresh router (no auth middleware
// — the endpoint is open by design) and returns the test server.
func caTestServer(t *testing.T, caPath string) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	MountCA(r, caPath)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func TestCAServesPEM(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "mitm-ca.crt")
	want := []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(caPath, want, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	ts := caTestServer(t, caPath)
	resp, err := http.Get(ts.URL + CAPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type = %q, want application/x-pem-file", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "bouncer-mitm-ca.crt") {
		t.Errorf("Content-Disposition = %q, want filename hint", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(want) {
		t.Errorf("body = %q, want %q", body, want)
	}
}

// TestCA404sWhenPathEmpty pins the MITM-disabled deployment shape:
// the endpoint is mounted (the parent server doesn't conditionally
// wire it) but returns 404 with a JSON-shaped error body.
func TestCA404sWhenPathEmpty(t *testing.T) {
	ts := caTestServer(t, "")
	resp, err := http.Get(ts.URL + CAPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestCA404sWhenFileMissing pins the operator-error case: path is
// configured but the file isn't there (e.g. operator regenerated the
// CA elsewhere). Same 404 shape as the disabled case.
func TestCA404sWhenFileMissing(t *testing.T) {
	ts := caTestServer(t, "/no/such/path/mitm-ca.crt")
	resp, err := http.Get(ts.URL + CAPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestCAOpenToAnonymous pins the no-auth contract: the endpoint must
// not redirect-to-login or 401. The agent's whole point is fetching
// this *before* it has a credential.
func TestCAOpenToAnonymous(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "mitm-ca.crt")
	if err := os.WriteFile(caPath, []byte("stub\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Mount on a router with the AuthMiddleware to mirror the prod
	// wiring — confirm the handler still serves anonymous.
	r := chi.NewRouter()
	r.Use(AuthMiddleware(mustKeys(t)))
	MountCA(r, caPath)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + CAPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (open to anonymous)", resp.StatusCode)
	}
}
