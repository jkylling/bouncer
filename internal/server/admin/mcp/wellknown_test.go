package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestWellKnownProbesReturnNotOAuthSignal pins the contract that
// MCP-aware harnesses probing the OAuth discovery + DCR paths see
// a clean 404 with a JSON body that signals "this isn't an OAuth
// resource server, configure a static Bearer". Without this the
// probes fall through to the proxy data-plane catchall, which 401s
// with a message about issuing JWTs — confusing and noisy.
func TestWellKnownProbesReturnNotOAuthSignal(t *testing.T) {
	r := chi.NewRouter()
	MountWellKnown(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{"GET", "/.well-known/oauth-authorization-server"},
		{"GET", "/.well-known/openid-configuration"},
		{"GET", "/.well-known/oauth-protected-resource"},
		{"GET", "/.well-known/oauth-protected-resource/_api/mcp"},
		{"POST", "/register"},
		{"GET", "/register"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, ts.URL+tc.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			body, _ := io.ReadAll(resp.Body)
			var got notOAuthBody
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("decode: %v\nraw: %s", err, body)
			}
			if got.AuthMethod != "pre_issued_bearer" {
				t.Errorf("auth_method = %q, want pre_issued_bearer", got.AuthMethod)
			}
			if got.BearerConfig == "" || got.IssueTokenHint == "" || got.Docs == "" {
				t.Errorf("missing hint fields: %+v", got)
			}
		})
	}
}
