package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// TestAPIsListReturnsRegisteredAPIs pins the canonical schema
// shape: every registered API appears with name, base_url,
// path_prefixes, actions, and meta. Sorted alphabetically by name
// so a diff-based agent doesn't see false changes.
func TestAPIsListReturnsRegisteredAPIs(t *testing.T) {
	b := runtime.NewBuilder()
	if err := b.AddAPI(&models.API{
		Name:         "zeta",
		BaseURL:      "https://zeta.example.com",
		PathPrefixes: []string{"/zeta"},
		Actions: []models.Action{{
			Name: "ping", Method: "GET", Path: "/ping", Filter: "true",
		}},
	}); err != nil {
		t.Fatalf("add zeta: %v", err)
	}
	if err := b.AddAPI(&models.API{
		Name:         "alpha",
		BaseURL:      "https://alpha.example.com",
		PathPrefixes: []string{"/alpha"},
	}); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	r := chi.NewRouter()
	MountAPIs(r, rt, BundleData{})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + APIsPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got APIsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.APIs) != 2 {
		t.Fatalf("got %d APIs, want 2", len(got.APIs))
	}
	if got.APIs[0].Name != "alpha" || got.APIs[1].Name != "zeta" {
		t.Errorf("order = %v, want [alpha zeta]", []string{got.APIs[0].Name, got.APIs[1].Name})
	}
	zeta := got.APIs[1]
	if zeta.BaseURL != "https://zeta.example.com" {
		t.Errorf("base_url = %q", zeta.BaseURL)
	}
	if len(zeta.Actions) != 1 || zeta.Actions[0].Name != "ping" || zeta.Actions[0].Method != "GET" {
		t.Errorf("actions = %+v", zeta.Actions)
	}
}

// TestAPIsListIncludesReadmeURL pins the bundle wiring: when an API
// is sourced from a vendored bundle that ships a README, the JSON
// descriptor carries a `readme_url` pointing at the per-bundle
// route. Without this every agent would have to guess the URL shape.
func TestAPIsListIncludesReadmeURL(t *testing.T) {
	b := runtime.NewBuilder()
	if err := b.AddAPI(&models.API{
		Name:         "gmail",
		BaseURL:      "https://gmail.example.com",
		PathPrefixes: []string{"/gmail"},
	}); err != nil {
		t.Fatalf("add gmail: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	r := chi.NewRouter()
	MountAPIs(r, rt, BundleData{
		Readmes:   map[string][]byte{"gws": []byte("# Google Workspace bundle\n")},
		APIBundle: map[string]string{"gmail": "gws"},
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + APIsPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var got APIsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.APIs) != 1 || got.APIs[0].ReadmeURL != "/_api/apis/gws/readme" {
		t.Fatalf("readme_url = %q", got.APIs[0].ReadmeURL)
	}

	rresp, err := http.Get(ts.URL + got.APIs[0].ReadmeURL)
	if err != nil {
		t.Fatalf("get readme: %v", err)
	}
	defer rresp.Body.Close()
	if rresp.StatusCode != http.StatusOK {
		t.Fatalf("readme status = %d", rresp.StatusCode)
	}
	if ct := rresp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("Content-Type = %q", ct)
	}
	body, _ := io.ReadAll(rresp.Body)
	if !strings.Contains(string(body), "Google Workspace") {
		t.Errorf("body = %q", body)
	}
}

// TestAPIsReadmeMissingBundle404s pins the loud-failure path: a
// bundle that wasn't registered (or has no README) returns 404
// rather than an empty 200, so a typo in the URL surfaces.
func TestAPIsReadmeMissingBundle404s(t *testing.T) {
	rt, err := runtime.NewBuilder().Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	r := chi.NewRouter()
	MountAPIs(r, rt, BundleData{})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/_api/apis/nope/readme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
