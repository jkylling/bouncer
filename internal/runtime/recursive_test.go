package runtime

import (
	"context"
	"strconv"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// recursiveAPI returns a body whose `parent` is `id-1` (or null at id 0)
// and whose `name` is the integer id, matching the rust-impl test fixture.
type recursiveAPI struct{}

var _ compiled.PhysicalAPI = recursiveAPI{}

func (recursiveAPI) Call(_ context.Context, req *pb.MetaRequest) (*pb.Response, error) {
	id, err := strconv.Atoi(req.GetPath())
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"name": float64(id),
	}
	if id > 0 {
		body["parent"] = float64(id - 1)
	}
	s, err := structpb.NewValue(body)
	if err != nil {
		return nil, err
	}
	return &pb.Response{Body: s}, nil
}

// TestRecursiveMeta ports rust-impl/src/runtime/api_runtime.rs::recursive_meta
// adapted to bouncer's cel-go semantics:
//
//   - Optional handling. The rust source uses
//     `recursive{ id: response.body.?parent }` — cel-cxx unwraps the
//     optional; cel-go does not. The idiomatic cel-go form is the
//     optional field-init syntax `?id: response.body.?parent`, which
//     skip-sets the field when the optional is absent.
//
//   - Walk endpoint. Rust's assertion `recursive.parent.parent.name == 0`
//     only succeeds in rust because the runtime values are proto
//     StructValues, so unset int fields default to 0; the test
//     incidentally satisfies the comparison via proto defaults rather
//     than by walking the chain. messages.Value errors on missing
//     output fields by design (so callers cannot accidentally treat an
//     unfetched meta as zero), so a faithful walk from `id=3` lands on
//     `id=1`'s name. The assertion below reflects that — and uniquely
//     exercises the lazy completion at every step (3 → 2 → 1).
func TestRecursiveMeta(t *testing.T) {
	api := &models.API{
		Name:    "test",
		BaseURL: "test",
		Meta: []models.Metadata{{
			Name: "recursive",
			Kind: "endpoint",
			Input: []models.InputField{
				{Name: "id"},
			},
			Request: `get(string(input.id))`,
			Output: []models.OutputField{
				{Name: "name", Expr: "response.body.name"},
				{Name: "parent", Expr: "recursive{?id: response.body.?parent}"},
			},
		}},
		Actions: []models.Action{{
			Name:   "test_action",
			Filter: `request.path == "/test/3"`,
			Bind:   "recursive{id: 3}",
		}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "test",
		Name:      "test_policy",
		Action:    `action.name == "test_action"`,
		Condition: `recursive.parent.parent.name == 1.0`,
		Result:    models.Permit,
	})
	req := &pb.Request{
		Method:       "GET",
		Path:         "/test/3",
		PathSegments: []string{"test"},
	}
	got, err := rt.Evaluate(t.Context(), constantResolver(recursiveAPI{}), req, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit, got %s", got)
	}
}

// chainAPI is a non-optional cousin of recursiveAPI: every id (including
// 0) reports a `parent` field, with id=0 acting as its own parent. That
// lets the recursive constructor `chain{id: response.body.parent}` keep
// id as a plain int, side-stepping the optional-unwrap issue.
type chainAPI struct {
	calls *[]int
}

var _ compiled.PhysicalAPI = chainAPI{}

func (a chainAPI) Call(_ context.Context, req *pb.MetaRequest) (*pb.Response, error) {
	id, err := strconv.Atoi(req.GetPath())
	if err != nil {
		return nil, err
	}
	if a.calls != nil {
		*a.calls = append(*a.calls, id)
	}
	parent := id - 1
	if parent < 0 {
		parent = 0
	}
	s, err := structpb.NewValue(map[string]any{
		"name":   float64(id),
		"parent": float64(parent),
	})
	if err != nil {
		return nil, err
	}
	return &pb.Response{Body: s}, nil
}

// TestLazyRecursiveCompletion exercises the recursive-completer
// machinery: a bind value `chain{id: 3}` with completer attached, where
// each .parent access materialises a child Value carrying its own
// completer pointing at the same upstream API. The condition
// `chain.parent.parent.name == 1` lands on id=1 after two .parent steps.
func TestLazyRecursiveCompletion(t *testing.T) {
	api := &models.API{
		Name:    "test",
		BaseURL: "test",
		Meta: []models.Metadata{{
			Name: "chain",
			Kind: "endpoint",
			Input: []models.InputField{
				{Name: "id"},
			},
			Request: `get(string(input.id))`,
			Output: []models.OutputField{
				{Name: "name", Expr: "response.body.name"},
				{Name: "parent", Expr: "chain{ id: response.body.parent }"},
			},
		}},
		Actions: []models.Action{{
			Name:   "test_action",
			Filter: `request.path == "/test"`,
			Bind:   "chain{id: 3}",
		}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "test",
		Name:      "lazy_chain",
		Action:    `action.name == "test_action"`,
		Condition: `chain.parent.parent.name == 1.0`,
		Result:    models.Permit,
	})
	var calls []int
	got, err := rt.Evaluate(t.Context(), constantResolver(chainAPI{calls: &calls}), &pb.Request{
		Method:       "GET",
		Path:         "/test",
		PathSegments: []string{"test"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit, got %s", got)
	}
	// Walking .parent.parent.name fires the completer for ids 3, 2, 1
	// (the access path) — and no more.
	want := []int{3, 2, 1}
	if len(calls) != len(want) {
		t.Fatalf("upstream calls: got %v, want %v", calls, want)
	}
	for i, id := range want {
		if calls[i] != id {
			t.Fatalf("upstream calls: got %v, want %v", calls, want)
		}
	}
}

// TestSelfReferentialMetaFromRequestBody seeds a self-referential meta
// from the action's request body — `file{parent: file{id:
// request.body.parent_id}}`. The chain is built lazily: only the
// links the policy actually walks are fetched, terminating when the
// policy stops descending.
func TestSelfReferentialMetaFromRequestBody(t *testing.T) {
	api := &models.API{
		Name:    "test",
		BaseURL: "test",
		Meta: []models.Metadata{{
			Name: "file",
			Kind: "endpoint",
			Input: []models.InputField{
				{Name: "id"},
			},
			Request: `get(string(input.id))`,
			Output: []models.OutputField{
				{Name: "name", Expr: "response.body.name"},
				// Self-reference: `parent` is another `file` whose id
				// comes from the upstream body. Lazy → no loop.
				{Name: "parent", Expr: "file{ id: response.body.parent }"},
			},
		}},
		Actions: []models.Action{{
			Name:   "create",
			Method: "POST",
			Path:   "/files",
			// Bind reads the request body to seed the head of the chain.
			Bind: "file{ id: request.body.parent_id }",
		}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "test",
		Name:      "permit_under_alice",
		Action:    `action.name == "create"`,
		Condition: `file.parent.parent.name == 1.0`,
		Result:    models.Permit,
	})

	body, _ := structpb.NewValue(map[string]any{"parent_id": float64(3)})
	var calls []int
	got, err := rt.Evaluate(t.Context(), constantResolver(chainAPI{calls: &calls}), &pb.Request{
		Method:       "POST",
		Path:         "/files",
		PathSegments: []string{"files"},
		Body:         body,
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit, got %s", got)
	}
	// Walks 3 → 2 → 1 (.parent.parent.name lands on id=1). Eager
	// recursion would have called id=0 too — or worse, looped.
	if len(calls) != 3 {
		t.Fatalf("upstream calls: got %v, want exactly [3 2 1]", calls)
	}
}
