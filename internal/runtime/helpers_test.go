package runtime

import (
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// stubPrincipal returns a non-nil *pb.Principal for tests that don't
// care about identity gating. The runtime asserts non-nil at every
// Evaluate boundary, so test bodies that focused on routing or
// per-action behaviour stay readable by calling this once at the top
// of the test.
func stubPrincipal() *pb.Principal { return &pb.Principal{} }

// constantResolver returns a PhysicalAPIResolver that hands back api
// for every API name. Tests typically have a single physical mock, so
// the routing dimension of the multi-API Runtime is uninteresting and
// this keeps test bodies focused on the policy-eval behaviour.
func constantResolver(api compiled.PhysicalAPI) PhysicalAPIResolver {
	return func(string) (compiled.PhysicalAPI, error) { return api, nil }
}

// buildSingleAPI compiles `api` (and any policies whose API field
// matches) into a runnable APIRuntime via the public Runtime API. It
// exists so tests can stay focused on the behaviour under test rather
// than the runtime-construction incantation.
func buildSingleAPI(t *testing.T, api *models.API, policies ...models.Policy) *APIRuntime {
	t.Helper()
	b := NewBuilder()
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i := range policies {
		if policies[i].API != api.Name {
			continue
		}
		if err := rt.AddPolicy(&policies[i]); err != nil {
			t.Fatalf("add policy %q: %v", policies[i].Name, err)
		}
	}
	out := rt.API(api.Name)
	if out == nil {
		t.Fatalf("api %q missing after build", api.Name)
	}
	return out
}
