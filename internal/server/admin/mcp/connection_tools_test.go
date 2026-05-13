package mcp

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/connections"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// tokenTestServer is a variant of testServer that wires a real
// connection store + token bundle list so we can exercise the
// per-service tool registration end-to-end.
func tokenTestServer(t *testing.T, tokenBundleList []*bundles.BundleToken, populate map[string]connections.Credentials) (*httptest.Server, *auth.ServerKeys, *connections.Store) {
	t.Helper()
	keys, err := auth.FromSecret(auth.DevStubSecret())
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	b := runtime.NewBuilder()
	if err := b.AddAPI(&models.API{
		Name:         "stub",
		BaseURL:      "https://example.invalid",
		PathPrefixes: []string{"/stub"},
	}); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build runtime: %v", err)
	}
	policySvc := policies.New(rt, policies.NewMemoryStore())

	store := connections.NewStore(filepath.Join(t.TempDir(), "connections"))
	for provider, creds := range populate {
		if _, err := store.Put(provider, creds); err != nil {
			t.Fatalf("seed connection %s: %v", provider, err)
		}
	}

	r := chi.NewRouter()
	r.Use(adminAuthMiddleware(keys))
	New(Deps{
		Runtime:       rt,
		PolicyService: policySvc,
		Docs: Docs{
			AgentGuide:      []byte("# agent\n"),
			PolicyAuthoring: []byte("# policies\n"),
			APIAuthoring:    []byte("# apis\n"),
		},
		TokenBundles:    tokenBundleList,
		ConnectionStore: store,
		Keys:            keys,
	}).Mount(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, keys, store
}

// googleBundleToken is the shared fixture for tests exercising the
// per-service tool. The PromptBody and Spec.Service match what
// bouncer-gws would ship.
func googleBundleToken() *bundles.BundleToken {
	return &bundles.BundleToken{
		BundleName: "bouncer-gws",
		PromptBody: []byte("stage google credentials\n"),
		Spec: &bundles.Service{
			Slug:   "google",
			Title:  "Google Workspace",
			Prompt: "prompts/google-token.md",
			Credential: bundles.CredentialSpec{
				Path:     "~/.config/bouncer/google-creds.json",
				Mode:     "0600",
				Template: `{"access_token": "{{ .AccessToken }}"}`,
			},
			Env: map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "{{ .Path }}"},
		},
	}
}

// googleCreds is the test triple used when staging a connection.
// TokenURL matches Google's real endpoint so tokens.IssueRefresh
// validates without us pointing at a mock server.
func googleCreds() connections.Credentials {
	return connections.Credentials{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RefreshToken: "1//refresh",
		TokenURL:     "https://oauth2.googleapis.com/token",
	}
}

func TestToolsListIncludesPerBundleAndConnectionTools(t *testing.T) {
	ts, keys, _ := tokenTestServer(t, []*bundles.BundleToken{googleBundleToken()}, nil)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/list", nil)
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	for _, want := range []string{
		`"name":"connections"`,
		`"name":"credentials_staged"`,
		`"name":"get_google_token"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("tools/list missing %s:\n%s", want, raw)
		}
	}
}

func TestGetServiceTokenReturnsServiceNotConnected(t *testing.T) {
	ts, keys, _ := tokenTestServer(t, []*bundles.BundleToken{googleBundleToken()}, nil)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name": "get_google_token",
	})
	if resp.Error != nil {
		t.Fatalf("transport error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(raw), `"isError":true`) {
		t.Errorf("expected isError:true:\n%s", raw)
	}
	if !strings.Contains(string(raw), "service_not_connected") {
		t.Errorf("expected service_not_connected:\n%s", raw)
	}
}

func TestGetServiceTokenIssuesBouncerJWTWhenConnected(t *testing.T) {
	ts, keys, _ := tokenTestServer(t,
		[]*bundles.BundleToken{googleBundleToken()},
		map[string]connections.Credentials{"google": googleCreds()},
	)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name": "get_google_token",
	})
	if resp.Error != nil {
		t.Fatalf("transport error: %+v", resp.Error)
	}
	text := callText(t, resp)
	var got GetServiceTokenResult
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, text)
	}
	if got.Service != "google" {
		t.Errorf("Service = %q", got.Service)
	}
	if got.AccessToken == "" || got.AccessToken == "1//refresh" {
		t.Errorf("AccessToken should be a bouncer-issued JWT, got %q", got.AccessToken)
	}
	if got.CredentialPath != "~/.config/bouncer/google-creds.json" {
		t.Errorf("CredentialPath = %q", got.CredentialPath)
	}
	if got.Env["GOOGLE_APPLICATION_CREDENTIALS"] != "{{ .Path }}" {
		t.Errorf("Env missing GOOGLE_APPLICATION_CREDENTIALS: %v", got.Env)
	}
}

// TestGetServiceTokenIssuesAccessJWTForByoVariant covers the BYO-
// access-token connection shape (variant != "", Fields.access_token
// set, empty Credentials triple). Regression: runGetServiceToken used
// to always call IssueRefresh, which 400'd with
// `invalid spec: refresh_token required` for these connections.
func TestGetServiceTokenIssuesAccessJWTForByoVariant(t *testing.T) {
	ts, keys, store := tokenTestServer(t,
		[]*bundles.BundleToken{googleBundleToken()},
		nil,
	)
	if _, err := store.PutVariant("google", "access_token", map[string]string{
		"access_token": "ya29-upstream-bearer",
	}); err != nil {
		t.Fatalf("seed variant: %v", err)
	}
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name": "get_google_token",
	})
	if resp.Error != nil {
		t.Fatalf("transport error: %+v", resp.Error)
	}
	text := callText(t, resp)
	if strings.Contains(text, `"isError":true`) || strings.Contains(text, "refresh_token required") {
		t.Fatalf("byo access-token connection should not require refresh_token:\n%s", text)
	}
	var got GetServiceTokenResult
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, text)
	}
	if got.AccessToken == "" || got.AccessToken == "ya29-upstream-bearer" {
		t.Errorf("AccessToken should be a bouncer-issued JWT, got %q", got.AccessToken)
	}

	// And the verify-time creds should carry the pasted upstream
	// bearer — that's what the proxy will forward upstream.
	access, err := auth.VerifyAccessToken(keys, got.AccessToken)
	if err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
	if access.Creds.AccessToken != "ya29-upstream-bearer" {
		t.Errorf("wrapped access token = %q, want %q", access.Creds.AccessToken, "ya29-upstream-bearer")
	}
}

// TestGetServiceTokenReportsNotConnectedWhenNoCredentials covers an
// edge case: a variant connection persisted with no recognizable
// credential field (neither refresh_token nor access_token). The tool
// should treat it as not-connected rather than 500.
func TestGetServiceTokenReportsNotConnectedWhenNoCredentials(t *testing.T) {
	ts, keys, store := tokenTestServer(t,
		[]*bundles.BundleToken{googleBundleToken()},
		nil,
	)
	if _, err := store.PutVariant("google", "custom", map[string]string{
		"unrelated_field": "x",
	}); err != nil {
		t.Fatalf("seed variant: %v", err)
	}
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name": "get_google_token",
	})
	if resp.Error != nil {
		t.Fatalf("transport error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(raw), "service_not_connected") {
		t.Errorf("expected service_not_connected:\n%s", raw)
	}
}

func TestCredentialsStagedReflectsStore(t *testing.T) {
	ts, keys, _ := tokenTestServer(t,
		[]*bundles.BundleToken{googleBundleToken()},
		map[string]connections.Credentials{"google": googleCreds()},
	)
	bearer := issueAccess(t, keys, false)

	// staged for connected service
	resp := rpc(t, ts.URL, bearer, "tools/call", map[string]any{
		"name":      "credentials_staged",
		"arguments": map[string]any{"service": "google"},
	})
	if !strings.Contains(callText(t, resp), `"staged": true`) {
		t.Errorf("expected staged:true for connected service:\n%s", callText(t, resp))
	}

	// not staged for unknown service — provider validation in the
	// store maps unknown slugs onto ErrUnknown, which the tool
	// reports as staged=false.
	resp = rpc(t, ts.URL, bearer, "tools/call", map[string]any{
		"name":      "credentials_staged",
		"arguments": map[string]any{"service": "slack.api"},
	})
	if !strings.Contains(callText(t, resp), `"staged": false`) {
		t.Errorf("expected staged:false for unconnected service:\n%s", callText(t, resp))
	}
}

func TestConnectionsListsStored(t *testing.T) {
	ts, keys, _ := tokenTestServer(t,
		[]*bundles.BundleToken{googleBundleToken()},
		map[string]connections.Credentials{
			"google":    googleCreds(),
			"slack.api": {ClientID: "slack-id", ClientSecret: "s", RefreshToken: "r", TokenURL: "https://slack.com/api/oauth.v2.access"},
		},
	)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name": "connections",
	})
	text := callText(t, resp)
	if !strings.Contains(text, `"provider": "google"`) {
		t.Errorf("missing google: %s", text)
	}
	if !strings.Contains(text, `"provider": "slack.api"`) {
		t.Errorf("missing slack: %s", text)
	}
}

// callText unwraps the tools/call envelope to its single text body.
func callText(t *testing.T, resp Response) string {
	t.Helper()
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got callToolResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, raw)
	}
	if len(got.Content) == 0 {
		t.Fatal("empty content")
	}
	return got.Content[0].Text
}
