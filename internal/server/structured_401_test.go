package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/server/admin"
)

// TestUpstream401RewrittenForTokenBundle pins the structured-401
// rewrite: when the matched API came from a bundle with a `token:`
// block, an upstream 401 is rewritten into the
// credentials_not_staged shape so the agent's auto-on-401 flow can
// react. The upstream's original body is preserved verbatim under
// `upstream_body` so operators tracing through bouncer still see
// what the upstream said.
func TestUpstream401RewrittenForTokenBundle(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{
		Runtime:    rt,
		Keys:       keys,
		HTTPClient: upstream.Client(),
		APIFactory: gmailFactory,
		BundleData: admin.BundleData{
			APIBundle: map[string]string{"google.gmail": "bouncer-gws"},
			TokenBundles: []*bundles.BundleToken{{
				BundleName: "bouncer-gws",
				Spec:       &bundles.Service{Slug: "google", Title: "Google"},
			}},
		},
	})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got admin.StructuredCredentialsNotStaged
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, body)
	}
	if got.Error != admin.StructuredErrorCredentialsNotStaged {
		t.Errorf("error = %q, want %q", got.Error, admin.StructuredErrorCredentialsNotStaged)
	}
	if got.Service != "google" {
		t.Errorf("service = %q, want google", got.Service)
	}
	if got.StagePrompt != "/google-token" {
		t.Errorf("stage_prompt = %q, want /google-token", got.StagePrompt)
	}
	if !strings.Contains(got.UpstreamBody, "invalid_grant") {
		t.Errorf("upstream_body should preserve upstream error: %s", got.UpstreamBody)
	}
}

// TestUpstream401UnchangedWithoutTokenBundle pins the negative case:
// an API not owned by a bundle with a token block streams the
// upstream's 401 verbatim, matching pre-token-bundle behavior.
func TestUpstream401UnchangedWithoutTokenBundle(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `original upstream body`)
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	// No bundle data set — apiToService is empty.
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "original upstream body" {
		t.Errorf("body = %q, want verbatim upstream", body)
	}
}
