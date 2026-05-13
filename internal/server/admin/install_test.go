package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func installTestServer(t *testing.T, caPath string) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	MountInstall(r, caPath)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func TestInstallWrapperBakesProxyURL(t *testing.T) {
	ts := installTestServer(t, "")
	resp, err := http.Get(ts.URL + InstallWrapperPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Errorf("Content-Type = %q, want text/x-shellscript", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "bouncer-wrap") {
		t.Errorf("Content-Disposition = %q, want bouncer-wrap filename", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "#!/bin/sh") {
		t.Errorf("body does not start with shebang:\n%s", body)
	}
	if !strings.Contains(string(body), `BOUNCER_PROXY="`+ts.URL+`"`) {
		t.Errorf("body does not bake proxy URL %q:\n%s", ts.URL, body)
	}
}

func TestInstallWrapperSha256HeaderMatchesBody(t *testing.T) {
	ts := installTestServer(t, "")
	resp, err := http.Get(ts.URL + InstallWrapperPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	want := sha256.Sum256(body)
	got := resp.Header.Get("X-Bouncer-Sha256")
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("X-Bouncer-Sha256 = %q, want %q", got, hex.EncodeToString(want[:]))
	}
}

func TestInstallWrapperHonorsForwardedHeaders(t *testing.T) {
	ts := installTestServer(t, "")
	req, _ := http.NewRequest(http.MethodGet, ts.URL+InstallWrapperPath, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "api.bouncer.cloud")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `BOUNCER_PROXY="https://api.bouncer.cloud"`) {
		t.Errorf("body does not respect forwarded headers:\n%s", body)
	}
}

func TestInstallCAServesPEM(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "mitm-ca.crt")
	want := []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(caPath, want, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	ts := installTestServer(t, caPath)

	resp, err := http.Get(ts.URL + InstallCAPath)
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
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, `filename="ca.pem"`) {
		t.Errorf("Content-Disposition = %q, want filename=\"ca.pem\"", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(want) {
		t.Errorf("body = %q, want %q", body, want)
	}
	// X-Bouncer-Sha256 must match the body bytes exactly.
	sum := sha256.Sum256(want)
	if got := resp.Header.Get("X-Bouncer-Sha256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("X-Bouncer-Sha256 = %q, want %q", got, hex.EncodeToString(sum[:]))
	}
}

func TestInstallCA404sWhenPathEmpty(t *testing.T) {
	ts := installTestServer(t, "")
	resp, err := http.Get(ts.URL + InstallCAPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
