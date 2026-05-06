package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/server/oauth"
)

// TestRefreshThenProxyCall pins the full /token → proxy round-trip
// via the public router: a refresh JWT POSTed to /token returns a
// fresh access JWT that authenticates the next data-plane call
// without any out-of-band step. Catches a regression where /token
// is wired but produces JWTs the proxy's authenticate() rejects.
func TestRefreshThenProxyCall(t *testing.T) {
	// Stub upstream serves both /token (the refresh exchange) and
	// the data-plane URL the proxy forwards to. One server keeps
	// the test small; the path discriminator decides which leg.
	var seenAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("client_id") != "client-id" {
				t.Errorf("upstream client_id = %q", r.PostForm.Get("client_id"))
			}
			_, _ = io.WriteString(w, `{"access_token":"upstream-fresh","expires_in":3600}`)
		default:
			seenAuth = r.Header.Get("Authorization")
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(rt, keys, upstream.Client(), gmailFactory, 0)
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	refresh, err := auth.IssueRefreshToken(keys, "agent-e2e", auth.RefreshCreds{
		RefreshToken: "rt-original",
		TokenURL:     upstream.URL + "/token",
	}, 0, false)
	if err != nil {
		t.Fatalf("issue refresh: %v", err)
	}

	// Step 1: POST /token with the refresh JWT.
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	form.Set("client_id", "client-id")
	form.Set("client_secret", "client-secret")
	resp, err := http.Post(proxy.URL+oauth.Path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status = %d, body = %s", resp.StatusCode, body)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Step 2: use the new access JWT against the data plane.
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	used, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy call: %v", err)
	}
	defer used.Body.Close()
	if used.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(used.Body)
		t.Fatalf("proxy status = %d, body = %s", used.StatusCode, body)
	}
	if !strings.Contains(seenAuth, "upstream-fresh") {
		t.Errorf("upstream auth = %q, want bearer upstream-fresh", seenAuth)
	}
}
