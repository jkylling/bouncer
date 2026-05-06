package runtime

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// fetchRecord captures one observed side call as the test asserts on
// it. Mirrors the wire shape but keeps the runtime types so the
// runtime test doesn't have to know about the recorder package.
type fetchRecord struct {
	meta, api, method, path string
	err                     string
	responseHas             bool
}

// observers is the test's drop-in for the recorder hook: it records
// firing pair + every fetch into local state for the test body to
// inspect.
type observers struct {
	action, policy string
	binds          []compiled.BoundValue
	fetches        []fetchRecord
}

func (o *observers) onFetch(meta, api string, mr *pb.MetaRequest, resp *pb.Response, err error, _ time.Duration) {
	rec := fetchRecord{
		meta:        meta,
		api:         api,
		method:      mr.GetMethod(),
		path:        mr.GetPath(),
		responseHas: resp.GetBody() != nil,
	}
	if err != nil {
		rec.err = err.Error()
	}
	o.fetches = append(o.fetches, rec)
}

func (o *observers) onFiring(action, policy string, binds []compiled.BoundValue) {
	o.action = action
	o.policy = policy
	o.binds = binds
}

func (o *observers) attach(ctx context.Context) context.Context {
	ctx = compiled.WithFetchObserver(ctx, o.onFetch)
	ctx = compiled.WithFiringObserver(ctx, o.onFiring)
	return ctx
}

// TestObserversCaptureFiringAndRecursiveFetches drives a recursive
// chain (id=3 → 2 → 1) and asserts every level lands on the fetch
// observer. Recursive captures are the user's stated requirement;
// pinning them here keeps the per-completer ctx propagation honest.
func TestObserversCaptureFiringAndRecursiveFetches(t *testing.T) {
	api := &models.API{
		Name:    "test",
		BaseURL: "test",
		Meta: []models.Metadata{{
			Name:    "recursive",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
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

	obs := &observers{}
	got, err := rt.Evaluate(obs.attach(context.Background()), constantResolver(recursiveAPI{}), &pb.Request{
		Method: "GET", Path: "/test/3", PathSegments: []string{"test"},
	}, stubPrincipal())
	require.NoError(t, err)
	assert.Equal(t, models.Permit, got)

	assert.Equal(t, "test_action", obs.action)
	assert.Equal(t, "test_policy", obs.policy)
	require.Len(t, obs.binds, 1)
	assert.Equal(t, "test.recursive", obs.binds[0].Name)

	require.Len(t, obs.fetches, 3)
	for i, want := range []string{"3", "2", "1"} {
		assert.Equal(t, want, obs.fetches[i].path, "fetch %d path", i)
		assert.Equal(t, "GET", obs.fetches[i].method)
		assert.Equal(t, "test.recursive", obs.fetches[i].meta)
		assert.Empty(t, obs.fetches[i].err)
		assert.True(t, obs.fetches[i].responseHas, "fetch %d should have a response body", i)
	}
}

// TestObserverSeesUpstreamCallError pins that an upstream-failed
// call still lands on the fetch observer with the original error
// preserved. The recorder's job to peel a typed status from it is
// covered by server-package tests; here we just verify the runtime
// fires the hook.
func TestObserverSeesUpstreamCallError(t *testing.T) {
	api := &models.API{
		Name:    "test",
		BaseURL: "test",
		Meta: []models.Metadata{{
			Name:    "thing",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get(string(input.id))`,
			Output:  []models.OutputField{{Name: "name", Expr: "response.body.name"}},
		}},
		Actions: []models.Action{{
			Name:   "act",
			Filter: `request.path == "/x"`,
			Bind:   "thing{id: 1}",
		}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "test",
		Name:      "p",
		Action:    `action.name == "act"`,
		Condition: `thing.name == "ok"`,
		Result:    models.Permit,
	})

	obs := &observers{}
	_, err := rt.Evaluate(obs.attach(context.Background()), constantResolver(stubFailAPI{msg: "boom"}), &pb.Request{
		Method: "GET", Path: "/x", PathSegments: []string{"x"},
	}, stubPrincipal())
	require.Error(t, err)
	require.Len(t, obs.fetches, 1)
	assert.Contains(t, obs.fetches[0].err, "boom")
}

// TestObserverCapturesInlineMetaConstruction proves that an ad-hoc
// `Type{id: ...}` literal in a policy condition is observed the
// same way a declared bind is. The condition here doesn't bind
// `thing` on the action — it constructs a fresh Value inline and
// walks `.name`. The completer for the inline Value gets installed
// by the policy env's installer hook (compiled/policy.go), which
// threads ctx — and therefore the fetch observer — through to
// api.Call.
//
// Without this, a policy could write `drive.file{id: X}.name == ...`
// and the resulting upstream call would be invisible in the traffic
// viewer. The test pins that behaviour rather than trusting the
// code path.
func TestObserverCapturesInlineMetaConstruction(t *testing.T) {
	api := &models.API{
		Name:    "test",
		BaseURL: "test",
		Meta: []models.Metadata{{
			Name:    "thing",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get("/things/" + string(input.id))`,
			Output:  []models.OutputField{{Name: "name", Expr: "response.body.name"}},
		}},
		Actions: []models.Action{{
			Name:   "act",
			Filter: `request.path == "/x"`,
			// Deliberately no bind — the policy condition constructs
			// the meta inline.
		}},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "test",
		Name:      "p",
		Action:    `action.name == "act"`,
		Condition: `test.thing{id: 99}.name == "hello"`,
		Result:    models.Permit,
	})

	obs := &observers{}
	got, err := rt.Evaluate(obs.attach(context.Background()), constantResolver(inlineThingAPI{}), &pb.Request{
		Method: "GET", Path: "/x", PathSegments: []string{"x"},
	}, stubPrincipal())
	require.NoError(t, err)
	assert.Equal(t, models.Permit, got)

	// No bind list (the action declared none), but the inline
	// construction must show up as a captured side call.
	assert.Empty(t, obs.binds)
	require.Len(t, obs.fetches, 1)
	assert.Equal(t, "test.thing", obs.fetches[0].meta)
	assert.Equal(t, "/things/99", obs.fetches[0].path)
}

type stubFailAPI struct{ msg string }

func (s stubFailAPI) Call(_ context.Context, _ *pb.MetaRequest) (*pb.Response, error) {
	return nil, fmt.Errorf("%s", s.msg)
}

type inlineThingAPI struct{}

func (inlineThingAPI) Call(_ context.Context, _ *pb.MetaRequest) (*pb.Response, error) {
	body, err := structpb.NewValue(map[string]any{"name": "hello"})
	if err != nil {
		return nil, err
	}
	return &pb.Response{Body: body}, nil
}
