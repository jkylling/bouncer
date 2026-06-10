package runtime

import (
	"context"
	"reflect"
	"sync"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// trivialAPI has no metas and one match-all action — enough surface to
// exercise the policy-mutation path without dragging upstream side
// calls into the test.
func trivialAPI(name string) *models.API {
	return &models.API{
		Name:         name,
		BaseURL:      "https://" + name + ".invalid",
		PathPrefixes: []string{"/" + name},
		Actions: []models.Action{{
			Name:   "any",
			Filter: "true",
		}},
	}
}

func policy(api, name string, result models.PolicyResult, condition string) models.Policy {
	return models.Policy{
		API:       api,
		Name:      name,
		Action:    "true",
		Condition: condition,
		Result:    result,
	}
}

func newRuntime(t *testing.T, apis ...*models.API) *Runtime {
	t.Helper()
	b := NewBuilder()
	for _, a := range apis {
		if err := b.AddAPI(a); err != nil {
			t.Fatalf("add api %q: %v", a.Name, err)
		}
	}
	r, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return r
}

func TestRuntimeReplacePolicyUpsertsByName(t *testing.T) {
	r := newRuntime(t, trivialAPI("svc"))

	if existed, err := r.ReplacePolicy(ptr(policy("svc", "p1", models.Permit, "true"))); err != nil {
		t.Fatalf("first replace: %v", err)
	} else if existed {
		t.Fatalf("first replace must report existed=false")
	}

	// Same name, different condition + bucket: must swap in place
	// (one entry in the store, condition reflects the new value).
	if existed, err := r.ReplacePolicy(ptr(policy("svc", "p1", models.Deny, "false"))); err != nil {
		t.Fatalf("second replace: %v", err)
	} else if !existed {
		t.Fatalf("second replace must report existed=true")
	}
	got := r.ListPolicies()
	if len(got) != 1 {
		t.Fatalf("policies: got %d, want 1: %+v", len(got), got)
	}
	if got[0].Result != models.Deny || got[0].Condition != "false" {
		t.Errorf("got %+v, want updated policy", got[0])
	}
}

func TestRuntimeReplacePolicyCompileErrorLeavesStateUntouched(t *testing.T) {
	r := newRuntime(t, trivialAPI("svc"))
	if _, err := r.ReplacePolicy(ptr(policy("svc", "p1", models.Permit, "true"))); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// `condition: nope` references an unknown identifier — fails CEL compile.
	if _, err := r.ReplacePolicy(ptr(policy("svc", "p1", models.Permit, "nope"))); err == nil {
		t.Fatal("expected compile error")
	}
	got := r.ListPolicies()
	if len(got) != 1 || got[0].Condition != "true" {
		t.Errorf("seed policy must survive failed replace: got %+v", got)
	}
}

func TestRuntimeRemovePolicyIdempotent(t *testing.T) {
	r := newRuntime(t, trivialAPI("svc"))
	if _, err := r.ReplacePolicy(ptr(policy("svc", "p1", models.Permit, "true"))); err != nil {
		t.Fatalf("seed: %v", err)
	}
	hit, err := r.RemovePolicy("svc", "p1")
	if err != nil || !hit {
		t.Fatalf("first remove: hit=%v err=%v", hit, err)
	}
	hit, err = r.RemovePolicy("svc", "p1")
	if err != nil || hit {
		t.Fatalf("second remove must report hit=false, err=nil; got hit=%v err=%v", hit, err)
	}
	if got := r.ListPolicies(); len(got) != 0 {
		t.Errorf("policies after remove: %+v", got)
	}
}

func TestRuntimeListPoliciesIsDenyFirst(t *testing.T) {
	r := newRuntime(t, trivialAPI("svc"))
	for _, p := range []models.Policy{
		policy("svc", "permit-1", models.Permit, "true"),
		policy("svc", "deny-1", models.Deny, "true"),
		policy("svc", "permit-2", models.Permit, "true"),
		policy("svc", "deny-2", models.Deny, "true"),
	} {
		if _, err := r.ReplacePolicy(&p); err != nil {
			t.Fatalf("seed %q: %v", p.Name, err)
		}
	}
	var got []string
	for _, p := range r.ListPolicies() {
		got = append(got, string(p.Result)+":"+p.Name)
	}
	want := []string{"deny:deny-1", "deny:deny-2", "permit:permit-1", "permit:permit-2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// TestRuntimeReplacePolicyKeepsPosition pins the in-place swap:
// editing a policy must not move it within its bucket. Eval aborts on
// the first erroring policy, so a same-bucket edit that reordered
// evaluation could flip an unrelated request's outcome — and
// ListPolicies promises diff-based clients a stable order.
func TestRuntimeReplacePolicyKeepsPosition(t *testing.T) {
	r := newRuntime(t, trivialAPI("svc"))
	for _, name := range []string{"a", "b", "c"} {
		if _, err := r.ReplacePolicy(ptr(policy("svc", name, models.Permit, "true"))); err != nil {
			t.Fatalf("seed %q: %v", name, err)
		}
	}

	if _, err := r.ReplacePolicy(ptr(policy("svc", "b", models.Permit, "false"))); err != nil {
		t.Fatalf("edit b: %v", err)
	}
	var got []string
	for _, p := range r.ListPolicies() {
		got = append(got, p.Name)
	}
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("order after same-bucket edit = %v, want %v", got, want)
	}

	// A result flip is the one case that relocates: b leaves the
	// permit bucket and lands in deny (which lists first).
	if _, err := r.ReplacePolicy(ptr(policy("svc", "b", models.Deny, "true"))); err != nil {
		t.Fatalf("flip b: %v", err)
	}
	got = nil
	for _, p := range r.ListPolicies() {
		got = append(got, p.Name)
	}
	if want := []string{"b", "a", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("order after bucket flip = %v, want %v", got, want)
	}
}

// TestRuntimeListPoliciesStableAcrossAPIs pins the
// cross-API order is alphabetical-by-API, not Go-map-iteration. A
// diff-based control-plane client should never see policies "move"
// between two consecutive Lists.
func TestRuntimeListPoliciesStableAcrossAPIs(t *testing.T) {
	r := newRuntime(t,
		trivialAPI("zeta"),
		trivialAPI("alpha"),
		trivialAPI("mu"),
	)
	for _, p := range []models.Policy{
		policy("zeta", "p1", models.Permit, "true"),
		policy("alpha", "p1", models.Permit, "true"),
		policy("mu", "p1", models.Permit, "true"),
	} {
		if _, err := r.ReplacePolicy(&p); err != nil {
			t.Fatalf("seed %q: %v", p.API, err)
		}
	}
	for i := 0; i < 8; i++ {
		var apis []string
		for _, p := range r.ListPolicies() {
			apis = append(apis, p.API)
		}
		want := []string{"alpha", "mu", "zeta"}
		if !reflect.DeepEqual(apis, want) {
			t.Errorf("ListPolicies API order on iteration %d = %v, want %v", i, apis, want)
		}
	}
}

// TestPolicyStoreIsConcurrentSafe exercises the lock: many goroutines
// upsert/remove/list/evaluate while one runs Evaluate against a no-op
// resolver. Run with `go test -race` to catch data races.
func TestPolicyStoreIsConcurrentSafe(t *testing.T) {
	r := newRuntime(t, trivialAPI("svc"))
	req := &pb.Request{Method: "GET", Path: "/svc/anything"}
	resolve := constantResolver(nil)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := policy("svc", "p", models.Permit, "true")
			for j := 0; j < 100; j++ {
				_, _ = r.ReplacePolicy(&p)
				_, _ = r.RemovePolicy("svc", "p")
				_ = r.ListPolicies()
				_, _, _ = r.Evaluate(context.Background(), resolve, req, stubPrincipal())
			}
		}(i)
	}
	wg.Wait()
}

func ptr[T any](v T) *T { return &v }
