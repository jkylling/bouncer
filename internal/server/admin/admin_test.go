package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/auth/authtest"
	"github.com/jkylling/bouncer/internal/control/tokens"
)

// testServer wires only admin routes onto a chi router and serves
// them via httptest. No proxy / runtime / factory dependencies — the
// admin package's job is the routes and the issue primitive, and the
// tests stay focused on those. End-to-end coverage lives in the
// parent package's issue_test.go.
func testServer(t *testing.T) (*httptest.Server, *auth.ServerKeys) {
	t.Helper()
	keys := mustKeys(t)
	r := testRouter(keys)
	MountOn(r, keys)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, keys
}

func mustKeys(t *testing.T) *auth.ServerKeys {
	t.Helper()
	keys, err := auth.FromSecret(authtest.Secret())
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}
	return keys
}

// postIssue posts body (a struct or raw bytes) to IssuePath and
// returns the response. Attaches an admin Bearer because IssuePath
// is admin-tier; tests that exercise the non-admin denial use
// postIssueRaw.
func postIssue(t *testing.T, base string, keys *auth.ServerKeys, body any) *http.Response {
	t.Helper()
	return postIssueRaw(t, base, body, adminBearer(t, keys))
}

// postIssueRaw is the bearer-explicit variant. Pass an empty bearer
// to test the unauthenticated denial path.
func postIssueRaw(t *testing.T, base string, body any, bearer string) *http.Response {
	t.Helper()
	var raw []byte
	switch b := body.(type) {
	case []byte:
		raw = b
	case string:
		raw = []byte(b)
	default:
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, base+IssuePath, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestIssueTokenRoundTrips(t *testing.T) {
	ts, keys := testServer(t)
	resp := postIssue(t, ts.URL, keys, tokens.Spec{
		Subject:     "agent-1",
		AccessToken: "ya29-fake",
		TTLSeconds:  60,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var out IssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Token == "" {
		t.Fatal("token empty")
	}
	if d := time.Until(out.ExpiresAt); d < 30*time.Second || d > 2*time.Minute {
		t.Errorf("expires_at = %v, want roughly 1 minute out", out.ExpiresAt)
	}
	tok, err := auth.VerifyAccessToken(keys, out.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok.Subject != "agent-1" {
		t.Errorf("Subject = %q, want agent-1", tok.Subject)
	}
	if tok.Creds.AccessToken != "ya29-fake" {
		t.Errorf("AccessToken = %q, want ya29-fake", tok.Creds.AccessToken)
	}
}

func TestIssueTokenValidation(t *testing.T) {
	ts, keys := testServer(t)
	cases := []struct {
		name string
		req  tokens.Spec
		want string
	}{
		{
			name: "empty_subject",
			req:  tokens.Spec{TTLSeconds: 60, AccessToken: "x"},
			want: "subject required",
		},
		{
			name: "zero_ttl",
			req:  tokens.Spec{Subject: "s", AccessToken: "x"},
			want: "ttl_seconds must be positive",
		},
		// Zero-credential JWTs are explicitly allowed — they're the
		// shape an MCP-only client uses (no upstream forward).
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postIssue(t, ts.URL, keys, tc.req)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tc.want) {
				t.Errorf("body = %q, want substring %q", body, tc.want)
			}
		})
	}
}

func TestIssueTokenRejectsMalformedJSON(t *testing.T) {
	ts, keys := testServer(t)
	resp := postIssue(t, ts.URL, keys, `{"subject":`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestIssueTokenEmptyBodyHitsValidator pins that a no-body POST falls
// through to tokens.Spec.Validate, which rejects the empty Subject
// with a clear error. Earlier the decoder caught io.EOF and surfaced
// the opaque "invalid JSON" message instead.
func TestIssueTokenEmptyBodyHitsValidator(t *testing.T) {
	ts, keys := testServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+IssuePath, http.NoBody)
	req.Header.Set("Authorization", adminBearer(t, keys))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "subject required") {
		t.Errorf("body = %q, want validator message", body)
	}
}

func TestIssueTokenRejectsUnknownField(t *testing.T) {
	ts, keys := testServer(t)
	resp := postIssue(t, ts.URL, keys, `{"subject":"s","ttl_seconds":1,"access_token":"x","audience":["gmail"]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400 (audience is not yet supported), body = %s", resp.StatusCode, body)
	}
}

// postIssueRefresh is the refresh-issue counterpart to postIssue. Same
// admin-Bearer treatment, posts to IssueRefreshPath with the JSON
// body marshalled from `body`.
func postIssueRefresh(t *testing.T, base string, keys *auth.ServerKeys, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, base+IssueRefreshPath, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", adminBearer(t, keys))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestIssueRefreshRoundTrips(t *testing.T) {
	ts, keys := testServer(t)
	resp := postIssueRefresh(t, ts.URL, keys, tokens.RefreshSpec{
		Subject:      "agent-1",
		RefreshToken: "1//rt-fake",
		TokenURL:     "https://oauth2.googleapis.com/token",
		TTLSeconds:   3600,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var out IssueRefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Token == "" {
		t.Fatal("token empty")
	}
	if out.ExpiresAt == nil {
		t.Fatal("expires_at missing for finite-TTL refresh")
	}
	tok, err := auth.VerifyRefreshToken(keys, out.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok.Subject != "agent-1" {
		t.Errorf("Subject = %q", tok.Subject)
	}
	if tok.Creds.RefreshToken != "1//rt-fake" {
		t.Errorf("RefreshToken = %q", tok.Creds.RefreshToken)
	}
}

// TestIssueRefreshOmitsExpiresAtForNonExpiring pins the wire shape
// for the no-TTL case: the JSON body must omit `expires_at`
// entirely, not emit a misleading 0001-01-01 timestamp.
func TestIssueRefreshOmitsExpiresAtForNonExpiring(t *testing.T) {
	ts, keys := testServer(t)
	resp := postIssueRefresh(t, ts.URL, keys, tokens.RefreshSpec{
		Subject:      "agent-1",
		RefreshToken: "rt",
		TokenURL:     "https://x",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "expires_at") {
		t.Errorf("body contains expires_at for non-expiring token: %s", body)
	}
}

func TestIssueRefreshValidation(t *testing.T) {
	ts, keys := testServer(t)
	cases := []struct {
		name string
		req  tokens.RefreshSpec
		want string
	}{
		{
			name: "missing_subject",
			req:  tokens.RefreshSpec{RefreshToken: "rt", TokenURL: "https://x"},
			want: "subject required",
		},
		{
			name: "missing_refresh_token",
			req:  tokens.RefreshSpec{Subject: "s", TokenURL: "https://x"},
			want: "refresh_token required",
		},
		{
			name: "missing_token_url",
			req:  tokens.RefreshSpec{Subject: "s", RefreshToken: "rt"},
			want: "token_url required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postIssueRefresh(t, ts.URL, keys, tc.req)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tc.want) {
				t.Errorf("body = %q, want substring %q", body, tc.want)
			}
		})
	}
}

// TestIssueRefreshRequiresAdmin pins the same RequireAdmin gate the
// access-issue endpoint has — issuing an admin refresh JWT is the
// privilege-escalation primitive.
func TestIssueRefreshRequiresAdmin(t *testing.T) {
	ts, _ := testServer(t)
	raw, _ := json.Marshal(tokens.RefreshSpec{
		Subject: "s", RefreshToken: "rt", TokenURL: "https://x",
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+IssueRefreshPath, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestIndexRedirectsToServices pins that GET /_admin and /_admin/
// both redirect to /_admin/services (the default dashboard). The
// auth-bearing client will follow the redirect.
func TestIndexRedirectsToServices(t *testing.T) {
	ts, keys := testServer(t)
	bearer := adminBearer(t, keys)
	for _, path := range []string{UIPath, UIPath + "/"} {
		t.Run(path, func(t *testing.T) {
			// Disable auto-follow so we can see the redirect
			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
			req.Header.Set("Authorization", bearer)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("get %s: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303 redirect", resp.StatusCode)
			}
			loc := resp.Header.Get("Location")
			if !strings.Contains(loc, "/_admin/services") {
				t.Errorf("Location = %q, want redirect to /_admin/services", loc)
			}
		})
	}
}

// TestIndexAnonymousRedirectsToLogin pins that an unauthenticated GET
// on /_admin redirects to login (the auth middleware catches the
// unauthenticated request before the page handler can redirect).
func TestIndexAnonymousRedirectsToLogin(t *testing.T) {
	ts, _ := testServer(t)
	// Disable redirect-following to see the first redirect
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(ts.URL + UIPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, LoginUIPath) {
		t.Errorf("Location = %q, want prefix %q", loc, LoginUIPath)
	}
}
