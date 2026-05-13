package mcp

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

func TestBuildInstructionsListsServicesSorted(t *testing.T) {
	deps := Deps{
		TokenBundles: []*bundles.BundleToken{
			{Spec: &bundles.Service{Slug: "slack", Title: "Slack", Description: "Slack workspace.\nMore detail."}},
			{Spec: &bundles.Service{Slug: "google", Title: "Google Workspace", Description: "Gmail, Drive, Calendar."}},
		},
	}
	out := buildInstructions(deps)

	if !strings.Contains(out, "# Available services") {
		t.Errorf("missing services header:\n%s", out)
	}
	gi := strings.Index(out, "`google`")
	si := strings.Index(out, "`slack`")
	if gi < 0 || si < 0 {
		t.Fatalf("services missing: google=%d slack=%d\n%s", gi, si, out)
	}
	if gi > si {
		t.Errorf("services not sorted (google should precede slack):\n%s", out)
	}
	// First-line trim: should not include the "More detail." second line.
	if strings.Contains(out, "More detail.") {
		t.Errorf("description not trimmed to first line:\n%s", out)
	}
}

func TestBuildInstructionsOmitsServicesHeaderWhenEmpty(t *testing.T) {
	out := buildInstructions(Deps{})
	if strings.Contains(out, "# Available services") {
		t.Errorf("services header should be omitted with no bundles:\n%s", out)
	}
	for _, needle := range []string{"bouncer-wrap", "setup", "credentials_not_staged", "Common errors"} {
		if !strings.Contains(out, needle) {
			t.Errorf("instructions missing %q:\n%s", needle, out)
		}
	}
}

// TestInitializeIncludesConfiguredServices exercises the full
// initialize JSON-RPC roundtrip with token bundles wired in, pinning
// that the instructions string surfaces the operator-configured
// services to the LLM at handshake.
func TestInitializeIncludesConfiguredServices(t *testing.T) {
	ts, keys := initServerWithBundles(t,
		&bundles.BundleToken{Spec: &bundles.Service{
			Slug:        "google",
			Title:       "Google Workspace",
			Description: "Gmail, Drive, Calendar.",
		}},
		&bundles.BundleToken{Spec: &bundles.Service{
			Slug:        "slack",
			Title:       "Slack",
			Description: "Slack workspace.",
		}},
	)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
	})
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	var got initializeResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	if got.Instructions == "" {
		t.Fatalf("empty instructions: %s", raw)
	}
	for _, needle := range []string{"`google`", "`slack`", "Google Workspace", "Gmail, Drive, Calendar."} {
		if !strings.Contains(got.Instructions, needle) {
			t.Errorf("instructions missing %q:\n%s", needle, got.Instructions)
		}
	}
}

// initServerWithBundles is a slimmer testServer variant that wires
// TokenBundles into Deps so the initialize-with-services path is
// exercisable without bringing in a connections store.
func initServerWithBundles(t *testing.T, tbs ...*bundles.BundleToken) (*httptest.Server, *auth.ServerKeys) {
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
	r := chi.NewRouter()
	r.Use(adminAuthMiddleware(keys))
	New(Deps{
		Runtime:       rt,
		PolicyService: policies.New(rt, policies.NewMemoryStore()),
		Docs: Docs{
			AgentGuide:      []byte("# agent\n"),
			PolicyAuthoring: []byte("# policies\n"),
			APIAuthoring:    []byte("# apis\n"),
		},
		TokenBundles: tbs,
	}).Mount(r)
	ts := httptest.NewServer(r)
	t.Cleanup(func() { ts.Close() })
	return ts, keys
}
