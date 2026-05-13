package mcp

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// TestGetTrafficEventRedactsForNonAdmin pins that a non-admin caller
// receives the denial-equivalent surface (decision, policy, request
// identity) but not the full meta body — no headers, no bodies, no
// binds, no policy-evaluation trace, no meta fetches.
func TestGetTrafficEventRedactsForNonAdmin(t *testing.T) {
	ts, keys, eventID := trafficTestServer(t)

	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name":      "get_traffic_event",
		"arguments": map[string]any{"id": eventID},
	})
	body := toolText(t, resp)

	mustHave := []string{"id", "method", "url", "decision", "policy"}
	for _, k := range mustHave {
		if _, ok := body[k]; !ok {
			t.Errorf("redacted body missing %q: %v", k, body)
		}
	}
	if got := body["decision"]; got != "deny" {
		t.Errorf("decision = %v, want deny", got)
	}
	mustNotHave := []string{
		"request_headers", "request_body",
		"upstream_headers", "upstream_body",
		"binds", "meta_fetches", "policy_evaluations",
	}
	for _, k := range mustNotHave {
		if _, ok := body[k]; ok {
			t.Errorf("redacted body leaks %q: %v", k, body[k])
		}
	}
}

// TestGetTrafficEventFullForAdmin pins that an admin caller still
// gets the full event with headers, bodies, binds, meta fetches, and
// the policy-evaluation trace.
func TestGetTrafficEventFullForAdmin(t *testing.T) {
	ts, keys, eventID := trafficTestServer(t)

	resp := rpc(t, ts.URL, issueAccess(t, keys, true), "tools/call", map[string]any{
		"name":      "get_traffic_event",
		"arguments": map[string]any{"id": eventID},
	})
	body := toolText(t, resp)

	// Admin sees the deeper fields the redaction strips.
	for _, k := range []string{"request_headers", "policy_evaluations"} {
		if _, ok := body[k]; !ok {
			t.Errorf("admin body missing %q: %v", k, body)
		}
	}
}

// trafficTestServer is the shared setup for the two traffic-tool
// redaction tests. Seeds a single denied event so both branches have
// the same data to read.
func trafficTestServer(t *testing.T) (*httptest.Server, *auth.ServerKeys, string) {
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

	store := traffic.NewMemoryStore(traffic.Options{})
	t.Cleanup(func() { _ = store.Close() })
	ev := traffic.Event{
		ID:             "evt-1",
		Timestamp:      time.Now().UTC(),
		Subject:        "ci",
		Method:         "GET",
		URL:            "https://example.invalid/stub/files",
		API:            "stub",
		Action:         "list_files",
		Decision:       traffic.Decision("deny"),
		Policy:         "drive-read-only",
		RequestHeaders: []traffic.KV{{Key: "X-Trace", Value: "abc"}},
		RequestBody:    []byte(`{"sensitive":true}`),
		UpstreamBody:   []byte(`{"private":"data"}`),
		PolicyEvaluations: []traffic.PolicyEvaluation{
			{Policy: "drive-read-only", Action: "list_files", Result: "deny", Fired: true},
		},
	}
	if err := store.Insert(context.Background(), ev); err != nil {
		t.Fatalf("seed traffic: %v", err)
	}

	r := chi.NewRouter()
	r.Use(adminAuthMiddleware(keys))
	New(Deps{
		Runtime:       rt,
		PolicyService: policies.New(rt, policies.NewMemoryStore()),
		TrafficStore:  store,
		Docs: Docs{
			AgentGuide:      []byte("# agent\n"),
			PolicyAuthoring: []byte("# policies\n"),
			APIAuthoring:    []byte("# apis\n"),
		},
	}).Mount(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, keys, string(ev.ID)
}
