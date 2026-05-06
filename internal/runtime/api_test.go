package runtime

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// testdataAPIs returns the path to the bundled-API test fixtures
// (Gmail/Calendar/Drive/Docs/Sheets specs). They mirror what the
// upstream bouncer-gws repo ships and are used by tests that want a
// production-shape API surface without depending on a vendored bundle.
func testdataAPIs(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "apis")
}

// testdataPolicies returns the path to the shared test-policy fixtures
// directory. Operator-managed policies live under top-level /policies/
// in a real deployment; test-only policies live under testdata/ per
// the Go convention.
func testdataPolicies(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "policies")
}

func loadAPIs(t *testing.T) []models.API {
	t.Helper()
	apis, err := models.FromYAMLDir[models.API](testdataAPIs(t))
	if err != nil {
		t.Fatalf("load apis: %v", err)
	}
	return apis
}

// loadCrossApiRuntime builds a multi-API Runtime with every bundled API
// loaded into a shared registry, so cross-API binds (e.g. a sheets
// action that constructs `drive.file{...}`) resolve at compile time.
// Returns the APIRuntime for the named API with the given policies
// registered.
func loadCrossApiRuntime(t *testing.T, apiName string, policies []models.Policy) *APIRuntime {
	t.Helper()
	b := NewBuilder()
	apis := loadAPIs(t)
	for i := range apis {
		if err := b.AddAPI(&apis[i]); err != nil {
			t.Fatalf("AddAPI %q: %v", apis[i].Name, err)
		}
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for i := range policies {
		if err := rt.AddPolicy(&policies[i]); err != nil {
			t.Fatalf("AddPolicy %q: %v", policies[i].Name, err)
		}
	}
	api := rt.API(apiName)
	if api == nil {
		t.Fatalf("api %q not found", apiName)
	}
	return api
}

// TestMatchActionsPreservesDeclaredOrder pins actions
// match in YAML-declared order, not hash-randomised map order. With
// two same-method overlapping templates that both fire on a request,
// the first one declared appears first in the matchedAction slice on
// every call. Without this, the doc claim of "stable order" was
// technically true within a single call but produced different
// orderings across requests, defeating log-replay.
func TestMatchActionsPreservesDeclaredOrder(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "first", Method: "GET", Path: "/svc/{a}"},
			{Name: "second", Method: "GET", Path: "/svc/{b}"},
			{Name: "third", Method: "GET", Path: "/svc/{c}"},
		},
	}
	b := NewBuilder()
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("AddAPI: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ar := rt.API("svc")
	if ar == nil {
		t.Fatal("api not found")
	}
	req := &pb.Request{Method: "GET", Path: "/svc/x", PathSegments: []string{"svc", "x"}}
	want := []string{"first", "second", "third"}
	// Run several times: with a map walk this would fail intermittently.
	for i := 0; i < 20; i++ {
		got, err := ar.matchActions(req)
		if err != nil {
			t.Fatalf("matchActions: %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("got %d matches, want %d", len(got), len(want))
		}
		for j, m := range got {
			if m.name != want[j] {
				t.Fatalf("iteration %d: got[%d] = %q, want %q", i, j, m.name, want[j])
			}
		}
	}
}

// TestEvaluatePrincipalGate pins the end-to-end behaviour of the new
// `principal:` predicate. Two policies with identical action and
// condition but distinct principal predicates must produce different
// decisions for two different callers — agent-1 hits the permit
// policy, agent-2 falls through to the implicit deny.
func TestEvaluatePrincipalGate(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "ping", Method: "GET", Path: "/svc/ping"},
		},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "svc",
		Name:      "agent_1_only",
		Principal: `principal.subject == "agent-1"`,
		Action:    `action.name == "ping"`,
		Condition: "true",
		Result:    models.Permit,
	})

	req := &pb.Request{Method: "GET", Path: "/svc/ping", PathSegments: []string{"svc", "ping"}}

	got, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}), req, &pb.Principal{Subject: "agent-1"})
	if err != nil {
		t.Fatalf("agent-1 evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("agent-1 decision = %s, want Permit", got)
	}

	got, err = rt.Evaluate(t.Context(), constantResolver(staticAPI{}), req, &pb.Principal{Subject: "agent-2"})
	if err != nil {
		t.Fatalf("agent-2 evaluate: %v", err)
	}
	if got != models.Deny {
		t.Fatalf("agent-2 decision = %s, want Deny", got)
	}
}

// TestEvaluatePrincipalShortCircuitsAction pins the predicate ordering:
// principal: runs *before* action:, so a policy whose principal
// rejects the caller must not evaluate the action predicate at all.
// We prove this by giving the policy an action predicate that would
// error if evaluated, and asserting the runtime returns Deny cleanly.
func TestEvaluatePrincipalShortCircuitsAction(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "ping", Method: "GET", Path: "/svc/ping"},
		},
	}
	// `action.notafield` is a runtime no-such-attribute error; the
	// principal predicate must short-circuit before we ever reach it.
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "svc",
		Name:      "wrong_caller",
		Principal: `principal.subject == "agent-1"`,
		Action:    `action.notafield == "x"`,
		Condition: "true",
		Result:    models.Permit,
	})

	got, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}),
		&pb.Request{Method: "GET", Path: "/svc/ping", PathSegments: []string{"svc", "ping"}},
		&pb.Principal{Subject: "agent-2"})
	if err != nil {
		t.Fatalf("evaluate: %v (action predicate must not have run)", err)
	}
	if got != models.Deny {
		t.Fatalf("decision = %s, want Deny", got)
	}
}

// TestEvaluateRejectsNilPrincipal pins the runtime contract that every
// caller must pass a non-nil principal — a stray nil surfaces as a
// clear error, not a CEL-time nil-deref or a silent allow.
func TestEvaluateRejectsNilPrincipal(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Actions:      []models.Action{{Name: "ping", Method: "GET", Path: "/svc/ping"}},
	}
	rt := buildSingleAPI(t, api)

	_, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}),
		&pb.Request{Method: "GET", Path: "/svc/ping"}, nil)
	if err == nil {
		t.Fatal("expected error for nil principal")
	}
}

// TestAccessDeniedStatusRoundTrips pins the model→runtime plumbing
// for the per-API status override: a configured value survives Build
// and is exposed via APIRuntime.AccessDeniedStatus() for the data
// plane to read.
func TestAccessDeniedStatusRoundTrips(t *testing.T) {
	api := &models.API{
		Name:               "svc",
		BaseURL:            "https://svc",
		PathPrefixes:       []string{"/svc"},
		AccessDeniedStatus: 200,
	}
	rt := buildSingleAPI(t, api)
	if got := rt.AccessDeniedStatus(); got != 200 {
		t.Fatalf("AccessDeniedStatus = %d, want 200", got)
	}
}

// TestAccessDeniedStatusDefaultZero pins the default: an unset
// override reads back as 0 so the data-plane fallback to the natural
// 401/403 stays clean.
func TestAccessDeniedStatusDefaultZero(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
	}
	rt := buildSingleAPI(t, api)
	if got := rt.AccessDeniedStatus(); got != 0 {
		t.Errorf("AccessDeniedStatus = %d, want 0", got)
	}
}

func TestAccessDeniedStatusRejectsOutOfRange(t *testing.T) {
	cases := []int{-1, 199, 600, 999}
	for _, s := range cases {
		t.Run(fmt.Sprintf("status_%d", s), func(t *testing.T) {
			api := &models.API{
				Name:               "svc",
				BaseURL:            "https://svc",
				PathPrefixes:       []string{"/svc"},
				AccessDeniedStatus: s,
			}
			b := NewBuilder()
			if err := b.AddAPI(api); err != nil {
				t.Fatalf("AddAPI: %v", err)
			}
			_, err := b.Build()
			if err == nil || !strings.Contains(err.Error(), "must be in [200, 599]") {
				t.Fatalf("err = %v, want range error", err)
			}
		})
	}
}

func TestAllBundledAPIsCompile(t *testing.T) {
	apis := loadAPIs(t)
	names := map[string]bool{}
	for _, a := range apis {
		names[a.Name] = true
	}
	for _, want := range []string{"gmail", "drive", "calendar", "sheets", "docs"} {
		if !names[want] {
			t.Errorf("api %q missing", want)
		}
	}
	// Compile via the multi-API Runtime so cross-API binds resolve.
	b := NewBuilder()
	for i := range apis {
		if err := b.AddAPI(&apis[i]); err != nil {
			t.Fatalf("AddAPI %q: %v", apis[i].Name, err)
		}
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, a := range apis {
		if rt.API(a.Name) == nil {
			t.Errorf("api %q missing from Runtime after Build", a.Name)
		}
	}
}
