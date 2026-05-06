package runtime

import (
	"context"
	"strconv"
	"sync"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// scopedAPI lets each goroutine present its own request-scoped value
// to the policy. The completer reads from the api, so a leaked
// completer between goroutines would either trip the race detector or
// flip the policy's decision (the condition compares the inline meta's
// output to the request's path segments).
type scopedAPI struct{ id int }

var _ compiled.PhysicalAPI = scopedAPI{}

func (a scopedAPI) Call(_ context.Context, _ *pb.MetaRequest) (*pb.Response, error) {
	body, err := structpb.NewValue(map[string]any{"name": strconv.Itoa(a.id)})
	if err != nil {
		return nil, err
	}
	return &pb.Response{Body: body}, nil
}

// TestPolicyEvaluateIsRaceFree drives the same compiled runtime from
// many goroutines at once with each goroutine carrying a distinct
// request-scoped credential (`scopedAPI.id`). The condition's
// `ping{id: 0}.name` constructs a Value inline — that's the exact
// path that used to share `PolicyProvider.OnNewValue` across
// goroutines and could attach a stale request's completer to a
// freshly-built Value.
//
// Under -race, a leaked closure surfaces as a data race; without it,
// a cross-goroutine credential leak surfaces as a wrong id and a
// Deny.
func TestPolicyEvaluateIsRaceFree(t *testing.T) {
	api := &models.API{
		Name:         "scoped",
		BaseURL:      "test",
		PathPrefixes: []string{"/p"},
		Meta: []models.Metadata{{
			Name: "ping",
			Kind: "endpoint",
			Input: []models.InputField{
				{Name: "id"},
			},
			Request: `get("/p")`,
			Output: []models.OutputField{
				{Name: "name", Expr: "response.body.name"},
			},
		}},
		Actions: []models.Action{{
			Name:   "act",
			Filter: `request.path == "/p"`,
		}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "scoped",
		Name:      "p",
		Action:    `action.name == "act"`,
		Condition: `ping{id: 0}.name == request.path_segments[0]`,
		Result:    models.Permit,
	})

	const goroutines = 32
	const itersPerG = 16
	ctx := t.Context()
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*itersPerG)
	for g := 0; g < goroutines; g++ {
		id := g
		go func() {
			defer wg.Done()
			for i := 0; i < itersPerG; i++ {
				req := &pb.Request{
					Method:       "GET",
					Path:         "/p",
					PathSegments: []string{strconv.Itoa(id)},
				}
				got, err := rt.Evaluate(ctx, constantResolver(scopedAPI{id: id}), req, stubPrincipal())
				if err != nil {
					errs <- err
					return
				}
				if got != models.Permit {
					errs <- nil // sentinel: wrong decision
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		} else {
			t.Fatalf("expected Permit on every goroutine — got Deny (cross-goroutine state leak?)")
		}
	}
}
