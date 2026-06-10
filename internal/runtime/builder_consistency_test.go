package runtime

import (
	pb "github.com/jkylling/bouncer/internal/pb"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// TestAddAPIRejectsOverlappingMetaFields pins the field-name guard: a
// name declared as both input and output would silently shadow the
// output (Value.Get consults inputs first), so the typo must fail at
// load instead of surfacing as "input field not set" at request time.
func TestAddAPIRejectsOverlappingMetaFields(t *testing.T) {
	cases := []struct {
		name string
		meta models.Metadata
		want string
	}{
		{
			name: "input output overlap",
			meta: models.Metadata{
				Name:    "file",
				Input:   []models.InputField{{Name: "id"}},
				Request: `get("/files/" + string(input.id))`,
				Output:  []models.OutputField{{Name: "id", Expr: "response.body"}},
			},
			want: "both input and output",
		},
		{
			name: "duplicate input",
			meta: models.Metadata{
				Name:    "file",
				Input:   []models.InputField{{Name: "id"}, {Name: "id"}},
				Request: `get("/files/" + string(input.id))`,
			},
			want: "duplicate input field",
		},
		{
			name: "duplicate output",
			meta: models.Metadata{
				Name:    "file",
				Input:   []models.InputField{{Name: "id"}},
				Request: `get("/files/" + string(input.id))`,
				Output: []models.OutputField{
					{Name: "size", Expr: "response.body"},
					{Name: "size", Expr: "response.body"},
				},
			},
			want: "duplicate output field",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuilder()
			err := b.AddAPI(&models.API{
				Name:         "svc",
				BaseURL:      "https://svc.invalid",
				PathPrefixes: []string{"/svc"},
				Meta:         []models.Metadata{tc.meta},
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("AddAPI err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// TestFailedAddAPILeavesRegistryClean pins builder consistency: a
// rejected AddAPI must not strand its earlier metas in the shared
// registry. The second AddAPI reuses the failed API's name and meta
// full name — under the old register-as-you-go behaviour the stranded
// `svc.a` type made it collide.
func TestFailedAddAPILeavesRegistryClean(t *testing.T) {
	b := NewBuilder()
	bad := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc.invalid",
		PathPrefixes: []string{"/svc"},
		Meta: []models.Metadata{
			{Name: "a", Request: `get("/a")`},
			{Name: "dup", Request: `get("/d")`},
			{Name: "dup", Request: `get("/d")`},
		},
	}
	if err := b.AddAPI(bad); err == nil {
		t.Fatal("AddAPI with duplicate metas must error")
	}

	good := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc.invalid",
		PathPrefixes: []string{"/svc"},
		Actions:      []models.Action{{Name: "any", Filter: "true"}},
		Meta:         []models.Metadata{{Name: "a", Request: `get("/a")`}},
	}
	if err := b.AddAPI(good); err != nil {
		t.Fatalf("AddAPI after failed sibling: %v (registry was left partially populated)", err)
	}
	if _, err := b.Build(); err != nil {
		t.Fatalf("Build: %v", err)
	}
}

// TestZeroMatchedActionsSkipsPrincipalPredicates pins the early
// return: when no action matches, evaluation is a clean default Deny
// without running any per-policy CEL — pinned via a principal
// predicate that errors at eval time, which must only surface on a
// request that actually matches an action.
func TestZeroMatchedActionsSkipsPrincipalPredicates(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc.invalid",
		PathPrefixes: []string{"/svc"},
		Actions:      []models.Action{{Name: "upload", Method: "POST", Path: "/svc/upload"}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "svc",
		Name:      "exploding-principal",
		Principal: `"".matches("(")`, // compiles; errors at eval (bad regex)
		Condition: "true",
		Result:    models.Permit,
	})

	got, err := rt.Evaluate(t.Context(), constantResolver(nil), &pb.Request{
		Method: "GET", Path: "/svc/nothing", PathSegments: []string{"svc", "nothing"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("unmatched request must not evaluate principal predicates; got err: %v", err)
	}
	if got != models.Deny {
		t.Fatalf("unmatched request: got %v, want Deny", got)
	}

	_, err = rt.Evaluate(t.Context(), constantResolver(nil), &pb.Request{
		Method: "POST", Path: "/svc/upload", PathSegments: []string{"svc", "upload"},
	}, stubPrincipal())
	if err == nil {
		t.Fatal("matched request must surface the erroring principal predicate")
	}
}
