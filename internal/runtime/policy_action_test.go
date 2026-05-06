package runtime

import (
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// TestPolicyActionEmptyMatchesEveryAction confirms that omitting the
// `action` field on a policy lets it apply to every matched action.
// This is the default-true behaviour: a policy that wants to gate the
// whole API by request shape alone shouldn't have to enumerate every
// action name.
func TestPolicyActionEmptyMatchesEveryAction(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "list", Method: "GET", Path: "/svc/items"},
			{Name: "get", Method: "GET", Path: "/svc/items/{id}"},
		},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "svc",
		Name:      "open",
		Action:    "", // empty → matches every action
		Condition: "true",
		Result:    models.Permit,
	})

	for _, c := range []struct {
		path string
		segs []string
	}{
		{"/svc/items", []string{"svc", "items"}},
		{"/svc/items/abc", []string{"svc", "items", "abc"}},
	} {
		got, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}), &pb.Request{
			Method: "GET", Path: c.path, PathSegments: c.segs,
		}, stubPrincipal())
		if err != nil {
			t.Fatalf("evaluate %q: %v", c.path, err)
		}
		if got != models.Permit {
			t.Fatalf("path %q: expected Permit, got %s", c.path, got)
		}
	}
}

// TestPolicyActionInListMatchesMultipleActions confirms the new
// CEL-predicate form lets one policy gate several actions. The
// predicate `action.name in ["list", "get"]` permits both reads but
// not the write.
func TestPolicyActionInListMatchesMultipleActions(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "list", Method: "GET", Path: "/svc/items"},
			{Name: "get", Method: "GET", Path: "/svc/items/{id}"},
			{Name: "create", Method: "POST", Path: "/svc/items"},
		},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "svc",
		Name:      "reads",
		Action:    `action.name in ["list", "get"]`,
		Condition: "true",
		Result:    models.Permit,
	})

	for _, c := range []struct {
		method, path string
		segs         []string
		want         models.PolicyResult
	}{
		{"GET", "/svc/items", []string{"svc", "items"}, models.Permit},
		{"GET", "/svc/items/abc", []string{"svc", "items", "abc"}, models.Permit},
		{"POST", "/svc/items", []string{"svc", "items"}, models.Deny},
	} {
		got, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}), &pb.Request{
			Method: c.method, Path: c.path, PathSegments: c.segs,
		}, stubPrincipal())
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		if got != c.want {
			t.Fatalf("%s %s: got %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

// TestPolicyMultiActionWithDistinctBinds covers the multi-action case
// where two actions bind different metas. A single policy spans both
// by guarding each branch with `action.name`: CEL's short-circuit
// evaluation suppresses the "unbound variable" error on the inactive
// branch, so the policy reads each meta only in the branch where the
// action's binds make it available.
//
// This is the answer to "can one policy match action1 (binds meta1,
// meta2) and action2 (binds meta2, meta3)?" — yes, write a guarded
// disjunction.
func TestPolicyMultiActionWithDistinctBinds(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Meta: []models.Metadata{
			{
				Name:    "thing1",
				Kind:    "endpoint",
				Input:   []models.InputField{{Name: "id"}},
				Request: `get('/svc/thing1/' + string(input.id))`,
				Output:  []models.OutputField{{Name: "owner", Expr: "response.body.owner"}},
			},
			{
				Name:    "thing3",
				Kind:    "endpoint",
				Input:   []models.InputField{{Name: "id"}},
				Request: `get('/svc/thing3/' + string(input.id))`,
				Output:  []models.OutputField{{Name: "owner", Expr: "response.body.owner"}},
			},
		},
		Actions: []models.Action{
			{
				Name:   "do_one",
				Method: "GET",
				Path:   "/svc/one/{id}",
				// Binds thing1 only.
				Binds: []models.CelExpression{`thing1{id: match.id}`},
			},
			{
				Name:   "do_two",
				Method: "GET",
				Path:   "/svc/two/{id}",
				// Binds thing3 only.
				Binds: []models.CelExpression{`thing3{id: match.id}`},
			},
		},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:    "svc",
		Name:   "permit_alice_either_action",
		Action: `action.name in ["do_one", "do_two"]`,
		// Each branch reads only the meta that branch's action binds.
		// Short-circuit suppresses unbound-variable errors on the
		// inactive branch.
		Condition: `(action.name == "do_one" && thing1.owner == 'alice') ||
			(action.name == "do_two" && thing3.owner == 'alice')`,
		Result: models.Permit,
	})

	upstream := staticAPI{bodies: map[string]map[string]any{
		"/svc/thing1/x": {"owner": "alice"},
		"/svc/thing3/y": {"owner": "alice"},
	}}

	for _, c := range []struct {
		path string
		segs []string
	}{
		{"/svc/one/x", []string{"svc", "one", "x"}},
		{"/svc/two/y", []string{"svc", "two", "y"}},
	} {
		got, err := rt.Evaluate(t.Context(), constantResolver(upstream), &pb.Request{
			Method: "GET", Path: c.path, PathSegments: c.segs,
		}, stubPrincipal())
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if got != models.Permit {
			t.Fatalf("%s: expected Permit, got %s", c.path, got)
		}
	}
}

// TestDenyPermitPairSharingMetaAccess pins the regression where
// deny + permit policies that share a matched action each call
// SetCompleter on the same bind value. The first policy's condition
// reads the meta and the completer fires; the second policy's
// SetCompleter call must NOT panic — completion is sticky and the
// second wiring is a no-op.
func TestDenyPermitPairSharingMetaAccess(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Meta: []models.Metadata{{
			Name:    "thing",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/svc/thing/' + string(input.id))`,
			Output:  []models.OutputField{{Name: "owner", Expr: "response.body.owner"}},
		}},
		Actions: []models.Action{{
			Name:   "do",
			Method: "GET",
			Path:   "/svc/thing/{id}",
			Binds:  []models.CelExpression{`thing{id: match.id}`},
		}},
	}
	rt := buildSingleAPI(t, api,
		models.Policy{
			API:       "svc",
			Name:      "deny_legal_hold",
			Action:    `action.name == "do"`,
			Condition: `thing.owner == 'legal_hold'`,
			Result:    models.Deny,
		},
		models.Policy{
			API:       "svc",
			Name:      "permit_alice",
			Action:    `action.name == "do"`,
			Condition: `thing.owner == 'alice'`,
			Result:    models.Permit,
		},
	)

	upstream := staticAPI{bodies: map[string]map[string]any{
		"/svc/thing/x": {"owner": "alice"},
	}}
	got, err := rt.Evaluate(t.Context(), constantResolver(upstream), &pb.Request{
		Method: "GET", Path: "/svc/thing/x", PathSegments: []string{"svc", "thing", "x"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit (deny condition false, permit condition true), got %s", got)
	}
}

// TestPolicyActionPredicateSeesMatchCaptures pins // `match` is in scope inside the action predicate, so a policy can
// gate by URL captures without paying for the upstream meta fetch the
// condition would trigger. unusedAPI panics on Call, so reaching the
// physical at all fails the test — proving the predicate rejected the
// request *before* any bind fired.
func TestPolicyActionPredicateSeesMatchCaptures(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Meta: []models.Metadata{{
			Name:    "thing",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/svc/thing/' + string(input.id))`,
			Output:  []models.OutputField{{Name: "owner", Expr: "response.body.owner"}},
		}},
		Actions: []models.Action{{
			Name:   "do",
			Method: "GET",
			Path:   "/svc/thing/{id}",
			Binds:  []models.CelExpression{`thing{id: match.id}`},
		}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "svc",
		Name:      "permit_self",
		Action:    `match.id == 'me'`,
		Condition: "true",
		Result:    models.Permit,
	})

	got, err := rt.Evaluate(t.Context(), constantResolver(unusedAPI{}), &pb.Request{
		Method: "GET", Path: "/svc/thing/other", PathSegments: []string{"svc", "thing", "other"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Deny {
		t.Fatalf("expected Deny (predicate match.id != 'me'), got %s", got)
	}
}

// TestPolicyConditionErrorsOnAbsentMeta pins the contract: the policy
// author writes the action predicate to gate which actions a condition
// is valid for. If the condition reads a meta that the matched action
// did not bind, eval surfaces an error rather than silently denying —
// keeping config bugs loud.
func TestPolicyConditionErrorsOnAbsentMeta(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Meta: []models.Metadata{{
			Name:    "message",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/svc/messages/' + string(input.id))`,
			Output:  []models.OutputField{{Name: "owner", Expr: "response.body.owner"}},
		}},
		Actions: []models.Action{{
			Name:   "ping",
			Method: "GET",
			Path:   "/svc/ping",
			// No bind: the action does not provide `message`.
		}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "svc",
		Name:      "buggy_owner_alice",
		Action:    `action.name == "ping"`,
		Condition: `message.owner == 'alice'`, // refers to an unbound meta
		Result:    models.Permit,
	})

	_, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}), &pb.Request{
		Method:       "GET",
		Path:         "/svc/ping",
		PathSegments: []string{"svc", "ping"},
	}, stubPrincipal())
	if err == nil {
		t.Fatal("expected eval error reading unbound meta, got nil")
	}
}
