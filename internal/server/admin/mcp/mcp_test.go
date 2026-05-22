package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// testServer wires the MCP dispatcher onto a chi router with the
// auth middleware so admin-tier checks exercise the same path as
// production. Returns a pre-built ServerKeys so callers can issue
// admin/anonymous bearers as needed.
func testServer(t *testing.T) (*httptest.Server, *auth.ServerKeys, *runtime.Runtime, *policies.Service) {
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
	}).Mount(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, keys, rt, policySvc
}

// adminAuthMiddleware is a minimal stand-in for the parent admin
// package's middleware: parses Authorization: Bearer <jwt> and
// stamps a Caller on ctx. We reach for the auth package directly
// rather than importing the parent admin package and creating a
// dependency cycle in the test.
func adminAuthMiddleware(keys *auth.ServerKeys) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := auth.Caller{Role: auth.RoleAnonymous}
			h := r.Header.Get("Authorization")
			if strings.HasPrefix(h, "Bearer ") {
				if tok, err := auth.VerifyAccessToken(keys, strings.TrimPrefix(h, "Bearer ")); err == nil {
					c = auth.Caller{Subject: tok.Subject, Role: auth.RoleUser}
					if tok.Admin {
						c.Role = auth.RoleAdmin
					}
				}
			}
			ctx := auth.WithCaller(r.Context(), c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func issueAccess(t *testing.T, keys *auth.ServerKeys, admin bool) string {
	t.Helper()
	tok, err := auth.IssueAccessToken(keys, "ci", auth.AccessCreds{AccessToken: "stub"}, 60_000_000_000, admin) // 60s
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

// rpc wraps a JSON-RPC POST to Path. Returns the parsed response.
func rpc(t *testing.T, base string, bearer string, method string, params any) Response {
	t.Helper()
	id := json.RawMessage(`"1"`)
	var rawParams json.RawMessage
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			t.Fatalf("marshal params: %v", err)
		}
		rawParams = raw
	}
	body, _ := json.Marshal(Request{JSONRPC: "2.0", ID: id, Method: method, Params: rawParams})
	req, _ := http.NewRequest(http.MethodPost, base+Path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, raw)
	}
	return out
}

func TestInitializeReturnsCapabilities(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
		"clientInfo":      map[string]string{"name": "ci", "version": "0"},
	})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(raw), `"protocolVersion":"`+ProtocolVersion+`"`) {
		t.Errorf("result lacks protocolVersion: %s", raw)
	}
	if !strings.Contains(string(raw), `"name":"`+ServerName+`"`) {
		t.Errorf("result lacks server name: %s", raw)
	}
	if !strings.Contains(string(raw), `"title":"`+ServerTitle+`"`) {
		t.Errorf("result lacks server title: %s", raw)
	}
	if !strings.Contains(string(raw), `"tools":{}`) {
		t.Errorf("missing tools capability: %s", raw)
	}
	if !strings.Contains(string(raw), `"resources":{}`) {
		t.Errorf("missing resources capability: %s", raw)
	}
	if !strings.Contains(string(raw), `"instructions":"`) {
		t.Errorf("result lacks instructions: %s", raw)
	}
	// Sanity-check the key bits agents need to know.
	for _, needle := range []string{"/_admin/tokens", "Common errors", "Bearer"} {
		if !strings.Contains(string(raw), needle) {
			t.Errorf("instructions missing %q: %s", needle, raw)
		}
	}
}

func TestToolsListEnumeratesEveryRegisteredTool(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/list", nil)
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	for _, name := range []string{
		"list_apis", "list_policies", "get_policy", "dry_run_policy", "propose_policy",
	} {
		if !strings.Contains(string(raw), `"`+name+`"`) {
			t.Errorf("tools/list missing %q: %s", name, raw)
		}
	}
	// Traffic tools are exposed to non-admin (with a redacted view
	// from get_traffic_event); confirm they're listed.
	for _, name := range []string{"list_traffic", "get_traffic_event"} {
		if !strings.Contains(string(raw), `"`+name+`"`) {
			t.Errorf("tools/list missing traffic tool %q: %s", name, raw)
		}
	}
}

// toolText pulls the first text content block out of a tools/call
// result, JSON-decoded into a generic map. Every test that asserts
// on a tool's output round-trips through this so the inner
// JSON-as-string framing doesn't leak into the assertions.
func toolText(t *testing.T, resp Response) map[string]any {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var envelope callToolResult
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode envelope: %v\nraw: %s", err, raw)
	}
	if envelope.IsError {
		t.Fatalf("tool returned isError=true: %+v", envelope.Content)
	}
	if len(envelope.Content) == 0 {
		t.Fatalf("no content blocks: %+v", envelope)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(envelope.Content[0].Text), &out); err != nil {
		// list_apis returns an array — try that shape.
		var arr []any
		if err2 := json.Unmarshal([]byte(envelope.Content[0].Text), &arr); err2 != nil {
			t.Fatalf("decode tool output: %v / %v\ntext: %s", err, err2, envelope.Content[0].Text)
		}
		return map[string]any{"_array": arr}
	}
	return out
}

func TestToolsCallListAPIs(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name": "list_apis",
	})
	got := toolText(t, resp)
	apis, ok := got["apis"].([]any)
	if !ok || len(apis) == 0 {
		t.Fatalf("expected non-empty apis array: %+v", got)
	}
	first, _ := apis[0].(map[string]any)
	if first["Name"] != "stub" {
		t.Errorf("first.Name = %v, want stub", first["Name"])
	}
}

func TestResourcesListIncludesEveryURI(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "resources/list", nil)
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	for _, uri := range []string{URIDocsAgent, URIDocsPolicies, URIDocsAPIs, URIAPIs} {
		if !strings.Contains(string(raw), `"`+uri+`"`) {
			t.Errorf("resources/list missing %q: %s", uri, raw)
		}
	}
}

func TestResourcesReadAgentGuide(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "resources/read", map[string]any{
		"uri": URIDocsAgent,
	})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(raw), `# agent`) {
		t.Errorf("body missing: %s", raw)
	}
}

// TestResourcesReadBundleReadme pins the bundle-README round trip:
// a `bouncer://bundles/<name>/readme` URI surfaces in resources/list
// and serves the registered bytes via resources/read.
func TestResourcesReadBundleReadme(t *testing.T) {
	ts, keys := bundleTestServer(t, map[string][]byte{
		"gws": []byte("# Google Workspace bundle\n"),
	})

	listed := rpc(t, ts.URL, issueAccess(t, keys, false), "resources/list", nil)
	listRaw, _ := json.Marshal(listed.Result)
	if !strings.Contains(string(listRaw), `"`+BundleReadmeURI("gws")+`"`) {
		t.Fatalf("bundle uri missing from list: %s", listRaw)
	}

	read := rpc(t, ts.URL, issueAccess(t, keys, false), "resources/read", map[string]any{
		"uri": BundleReadmeURI("gws"),
	})
	if read.Error != nil {
		t.Fatalf("error: %+v", read.Error)
	}
	readRaw, _ := json.Marshal(read.Result)
	if !strings.Contains(string(readRaw), "Google Workspace") {
		t.Errorf("body missing: %s", readRaw)
	}
}

// bundleTestServer is the testServer twin with BundleReadmes wired
// in so the bundle-resource path has something to serve. Kept minimal
// — no policy store since the bundle path doesn't touch it.
func bundleTestServer(t *testing.T, readmes map[string][]byte) (*httptest.Server, *auth.ServerKeys) {
	t.Helper()
	keys, err := auth.FromSecret(auth.DevStubSecret())
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	rt, err := runtime.NewBuilder().Build()
	if err != nil {
		t.Fatalf("build runtime: %v", err)
	}
	r := chi.NewRouter()
	r.Use(adminAuthMiddleware(keys))
	New(Deps{
		Runtime:       rt,
		BundleReadmes: readmes,
		Docs: Docs{
			AgentGuide:      []byte("# agent\n"),
			PolicyAuthoring: []byte("# policies\n"),
			APIAuthoring:    []byte("# apis\n"),
		},
	}).Mount(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, keys
}

func TestUnknownMethodReturnsMethodNotFound(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "no_such_method", nil)
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Errorf("error = %+v, want method-not-found", resp.Error)
	}
}

func TestMalformedJSONReturnsParseError(t *testing.T) {
	ts, _, _, _ := testServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+Path, bytes.NewReader([]byte("{not-json")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, raw)
	}
	if out.Error == nil || out.Error.Code != codeParseError {
		t.Errorf("error = %+v, want parse-error", out.Error)
	}
}
