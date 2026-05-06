package runtime

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// staticAPI returns a fixed body for any meta request, keyed by path.
type staticAPI struct {
	bodies map[string]map[string]any
}

var _ compiled.PhysicalAPI = staticAPI{}

func (s staticAPI) Call(_ context.Context, req *pb.MetaRequest) (*pb.Response, error) {
	body, ok := s.bodies[req.GetPath()]
	if !ok {
		return nil, fmt.Errorf("staticAPI: unexpected path %q", req.GetPath())
	}
	pbBody, err := structpb.NewValue(body)
	if err != nil {
		return nil, err
	}
	return &pb.Response{Body: pbBody}, nil
}

// TestRuntimeSharesRegistryAcrossApis confirms that two APIs registered
// against the same Runtime see each other's meta types in their CEL
// envs. The drive meta is referenced by full name from inside a gmail
// output expression, so the lookup has to flow through the shared
// FullProvider.
func TestRuntimeSharesRegistryAcrossApis(t *testing.T) {
	b := NewBuilder()

	driveAPI := &models.API{
		Name:         "google.drive",
		BaseURL:      "https://drive",
		PathPrefixes: []string{"/drive"},
		Meta: []models.Metadata{{
			Name: "file",
			Kind: "endpoint",
			Input: []models.InputField{
				{Name: "id"},
			},
			Request: `get('/drive/' + string(input.id))`,
			Output: []models.OutputField{
				{Name: "owner", Expr: "response.body.owner"},
			},
		}},
		Actions: []models.Action{{
			Name:   "get_file",
			Filter: `request.path.startsWith('/drive/')`,
			Bind:   "file{id: 'doc-1'}",
		}},
	}
	gmailAPI := &models.API{
		Name:         "google.gmail",
		BaseURL:      "https://gmail",
		PathPrefixes: []string{"/gmail"},
		Meta: []models.Metadata{{
			Name: "message",
			Kind: "endpoint",
			Input: []models.InputField{
				{Name: "user_id"},
				{Name: "file_id"},
			},
			Request: `get('/gmail/' + string(input.user_id) + '/' + string(input.file_id))`,
			Output: []models.OutputField{
				// References google.drive.file across API boundaries —
				// only resolves because the registry is shared.
				{Name: "linked_file", Expr: "google.drive.file{id: input.file_id}"},
			},
		}},
		Actions: []models.Action{{
			Name:   "get_message",
			Filter: `request.path.startsWith('/gmail/')`,
			Bind:   `message{user_id: 'me', file_id: 'doc-1'}`,
		}},
	}

	if err := b.AddAPI(driveAPI); err != nil {
		t.Fatalf("add drive: %v", err)
	}
	if err := b.AddAPI(gmailAPI); err != nil {
		t.Fatalf("add gmail: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Policy walks message → linked_file (a google.drive.file Value) →
	// owner (lazily fetched via the shared completer machinery). The
	// completer for the cross-API child is installed because the
	// global metas map is visible to gmail's runtime.
	if err := rt.AddPolicy(&models.Policy{
		API:       "google.gmail",
		Name:      "owned_by_alice",
		Action:    `action.name == "get_message"`,
		Condition: `message.linked_file.owner == 'alice'`,
		Result:    models.Permit,
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	api := staticAPI{bodies: map[string]map[string]any{
		"/gmail/me/doc-1": {},
		"/drive/doc-1":    {"owner": "alice"},
	}}
	_, got, err := rt.Evaluate(t.Context(), constantResolver(api), &pb.Request{
		Method:       "GET",
		Path:         "/gmail/x",
		PathSegments: []string{"gmail", "x"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit, got %s", got)
	}
}

// TestRuntimeDispatchesByMatchingAPI exercises Runtime.Evaluate's
// routing layer: with two APIs claiming disjoint paths, only the API
// whose actions match a given request is asked to evaluate. The
// returned apiName tells the caller which upstream to forward to.
func TestRuntimeDispatchesByMatchingAPI(t *testing.T) {
	apiA := &models.API{
		Name:         "alpha",
		BaseURL:      "https://alpha",
		PathPrefixes: []string{"/alpha"},
		Actions:      []models.Action{{Name: "any", Method: "GET", Path: "/alpha/{id}"}},
	}
	apiB := &models.API{
		Name:         "beta",
		BaseURL:      "https://beta",
		PathPrefixes: []string{"/beta"},
		Actions:      []models.Action{{Name: "any", Method: "GET", Path: "/beta/{id}"}},
	}
	b := NewBuilder()
	if err := b.AddAPI(apiA); err != nil {
		t.Fatalf("alpha: %v", err)
	}
	if err := b.AddAPI(apiB); err != nil {
		t.Fatalf("beta: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, p := range []models.Policy{
		{API: "alpha", Name: "open_a", Action: `action.name == "any"`, Condition: "true", Result: models.Permit},
		{API: "beta", Name: "open_b", Action: `action.name == "any"`, Condition: "true", Result: models.Permit},
	} {
		if err := rt.AddPolicy(&p); err != nil {
			t.Fatalf("add policy: %v", err)
		}
	}

	resolver := constantResolver(staticAPI{})

	name, decision, err := rt.Evaluate(t.Context(), resolver, &pb.Request{
		Method: "GET", Path: "/alpha/1", PathSegments: []string{"alpha", "1"},
	}, stubPrincipal())
	if err != nil || name != "alpha" || decision != models.Permit {
		t.Fatalf("alpha dispatch: name=%q decision=%s err=%v", name, decision, err)
	}
	name, decision, err = rt.Evaluate(t.Context(), resolver, &pb.Request{
		Method: "GET", Path: "/beta/2", PathSegments: []string{"beta", "2"},
	}, stubPrincipal())
	if err != nil || name != "beta" || decision != models.Permit {
		t.Fatalf("beta dispatch: name=%q decision=%s err=%v", name, decision, err)
	}
	// No API claims this path → empty name + Deny.
	name, decision, err = rt.Evaluate(t.Context(), resolver, &pb.Request{
		Method: "GET", Path: "/gamma/3", PathSegments: []string{"gamma", "3"},
	}, stubPrincipal())
	if err != nil || name != "" || decision != models.Deny {
		t.Fatalf("unmatched: name=%q decision=%s err=%v", name, decision, err)
	}
}

// TestRoutingIsSegmentAware confirms that `/drive` does not claim
// `/drives/...`: prefix matching splits on `/` rather than doing a raw
// byte-level startsWith. This is the property that keeps a typo-prone
// prefix like `/api` from accidentally swallowing `/api2/x`.
func TestRoutingIsSegmentAware(t *testing.T) {
	api := &models.API{
		Name:         "drive",
		BaseURL:      "https://drive",
		PathPrefixes: []string{"/drive"},
		Actions:      []models.Action{{Name: "any", Method: "GET", Path: "/drive/{id}"}},
	}
	b := NewBuilder()
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("add: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := rt.AddPolicy(&models.Policy{
		API: "drive", Name: "open", Action: `action.name == "any"`,
		Condition: "true", Result: models.Permit,
	}); err != nil {
		t.Fatalf("policy: %v", err)
	}

	// Same byte-prefix but a different first segment must not route.
	name, decision, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}), &pb.Request{
		Method: "GET", Path: "/drives/1", PathSegments: []string{"drives", "1"},
	}, stubPrincipal())
	if err != nil || name != "" || decision != models.Deny {
		t.Fatalf("/drives/1: name=%q decision=%s err=%v", name, decision, err)
	}

	// Exact prefix-segment match routes; the action's path template still
	// gates whether the policy fires.
	name, decision, err = rt.Evaluate(t.Context(), constantResolver(staticAPI{}), &pb.Request{
		Method: "GET", Path: "/drive/1", PathSegments: []string{"drive", "1"},
	}, stubPrincipal())
	if err != nil || name != "drive" || decision != models.Permit {
		t.Fatalf("/drive/1: name=%q decision=%s err=%v", name, decision, err)
	}
}

// TestRoutingHonoursMultiplePrefixes covers Drive's real-world shape:
// one API claims two disjoint prefixes (`/drive/v3` and
// `/upload/drive/v3`). Both must route to the same APIRuntime so the
// upload-scoped actions evaluate against the same policies as the
// canonical ones.
func TestRoutingHonoursMultiplePrefixes(t *testing.T) {
	api := &models.API{
		Name:         "drive",
		BaseURL:      "https://drive",
		PathPrefixes: []string{"/drive/v3", "/upload/drive/v3"},
		Actions: []models.Action{
			{Name: "get", Method: "GET", Path: "/drive/v3/files/{id}"},
			{Name: "upload", Method: "POST", Path: "/upload/drive/v3/files"},
		},
	}
	b := NewBuilder()
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("add: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, p := range []models.Policy{
		{API: "drive", Name: "ok_get", Action: `action.name == "get"`, Condition: "true", Result: models.Permit},
		{API: "drive", Name: "ok_upload", Action: `action.name == "upload"`, Condition: "true", Result: models.Permit},
	} {
		if err := rt.AddPolicy(&p); err != nil {
			t.Fatalf("policy: %v", err)
		}
	}

	cases := []struct {
		method, path string
		segs         []string
	}{
		{"GET", "/drive/v3/files/abc", []string{"drive", "v3", "files", "abc"}},
		{"POST", "/upload/drive/v3/files", []string{"upload", "drive", "v3", "files"}},
	}
	for _, c := range cases {
		name, decision, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}), &pb.Request{
			Method: c.method, Path: c.path, PathSegments: c.segs,
		}, stubPrincipal())
		if err != nil || name != "drive" || decision != models.Permit {
			t.Errorf("%s %s: name=%q decision=%s err=%v", c.method, c.path, name, decision, err)
		}
	}
}

// TestRuntimeFlagsAmbiguousRouting builds two APIs that declare the
// same path prefix and confirms Build rejects the configuration.
// Catching the conflict at compile time is stronger than the previous
// per-request ambiguity check: a misconfigured deployment never starts
// instead of returning 500 on the first request that hits the overlap.
func TestRuntimeFlagsAmbiguousRouting(t *testing.T) {
	apiA := &models.API{
		Name:         "alpha",
		BaseURL:      "https://alpha",
		PathPrefixes: []string{"/shared"},
		Actions:      []models.Action{{Name: "any", Method: "GET", Path: "/shared/{id}"}},
	}
	apiB := &models.API{
		Name:         "beta",
		BaseURL:      "https://beta",
		PathPrefixes: []string{"/shared"},
		Actions:      []models.Action{{Name: "any", Method: "GET", Path: "/shared/{id}"}},
	}
	b := NewBuilder()
	if err := b.AddAPI(apiA); err != nil {
		t.Fatalf("alpha: %v", err)
	}
	if err := b.AddAPI(apiB); err != nil {
		t.Fatalf("beta: %v", err)
	}
	if _, err := b.Build(); err == nil {
		t.Fatal("expected build error for overlapping path_prefixes, got nil")
	}
}

// TestRuntimeFlagsPrefixOfPrefix rejects the subtler case where one
// API's prefix is a strict segment-wise prefix of another's. With both
// configured, "/api/v2/x" would match both — the runtime would have to
// pick a winner, and any choice is wrong from one of the APIs' point
// of view.
func TestRuntimeFlagsPrefixOfPrefix(t *testing.T) {
	apiA := &models.API{
		Name:         "outer",
		BaseURL:      "https://outer",
		PathPrefixes: []string{"/api"},
	}
	apiB := &models.API{
		Name:         "inner",
		BaseURL:      "https://inner",
		PathPrefixes: []string{"/api/v2"},
	}
	b := NewBuilder()
	if err := b.AddAPI(apiA); err != nil {
		t.Fatalf("outer: %v", err)
	}
	if err := b.AddAPI(apiB); err != nil {
		t.Fatalf("inner: %v", err)
	}
	if _, err := b.Build(); err == nil {
		t.Fatal("expected build error for nested prefixes, got nil")
	}
}

// TestRuntimeAddApiOrderIndependence verifies that an API whose
// expressions reference another API's meta types compiles even when it
// is added *before* the API it depends on. This is the entire reason
// Runtime defers compilation: registering all APIs' types first means
// every expression's CEL env sees every meta at compile time.
func TestRuntimeAddApiOrderIndependence(t *testing.T) {
	driveAPI := &models.API{
		Name:    "google.drive",
		BaseURL: "https://drive",
		Meta: []models.Metadata{{
			Name:    "file",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/drive/' + string(input.id))`,
			Output: []models.OutputField{
				{Name: "owner", Expr: "response.body.owner"},
			},
		}},
	}
	gmailAPI := &models.API{
		Name:    "google.gmail",
		BaseURL: "https://gmail",
		Meta: []models.Metadata{{
			Name: "message",
			Kind: "endpoint",
			Input: []models.InputField{
				{Name: "user_id"},
				{Name: "file_id"},
			},
			Request: `get('/gmail/' + string(input.user_id) + '/' + string(input.file_id))`,
			Output: []models.OutputField{
				// Forward reference: gmail compiles before drive is added.
				{Name: "linked_file", Expr: "google.drive.file{id: input.file_id}"},
			},
		}},
	}

	b := NewBuilder()
	if err := b.AddAPI(gmailAPI); err != nil {
		t.Fatalf("add gmail (forward ref): %v", err)
	}
	if err := b.AddAPI(driveAPI); err != nil {
		t.Fatalf("add drive: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rt.API("google.gmail") == nil {
		t.Fatal("gmail not compiled after Build")
	}
	if rt.API("google.drive") == nil {
		t.Fatal("drive not compiled after Build")
	}
}

// TestRuntimeMutualCrossApiReferences exercises the harder
// circular-reference case: sheets.sheet builds a drive.file in one of
// its outputs, and drive.file builds a sheets.sheet in one of its
// outputs. Neither order succeeds with a single-phase compile (whichever
// API is compiled first cannot see the other's types yet); the
// two-phase split — register every type, then compile every
// expression — makes both directions resolve.
func TestRuntimeMutualCrossApiReferences(t *testing.T) {
	driveAPI := &models.API{
		Name:    "google.drive",
		BaseURL: "https://drive",
		Meta: []models.Metadata{{
			Name:    "file",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/drive/' + string(input.id))`,
			Output: []models.OutputField{
				{Name: "sheet", Expr: "google.sheets.sheet{id: response.body.sheet_id}"},
			},
		}},
	}
	sheetsAPI := &models.API{
		Name:    "google.sheets",
		BaseURL: "https://sheets",
		Meta: []models.Metadata{{
			Name:    "sheet",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/sheets/' + string(input.id))`,
			Output: []models.OutputField{
				{Name: "file", Expr: "google.drive.file{id: response.body.file_id}"},
			},
		}},
	}

	b := NewBuilder()
	if err := b.AddAPI(driveAPI); err != nil {
		t.Fatalf("add drive: %v", err)
	}
	if err := b.AddAPI(sheetsAPI); err != nil {
		t.Fatalf("add sheets: %v", err)
	}
	if _, err := b.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
}

// TestRuntimeRejectsDuplicateAPI verifies the basic registration guard.
func TestRuntimeRejectsDuplicateAPI(t *testing.T) {
	b := NewBuilder()
	api := &models.API{Name: "x"}
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := b.AddAPI(api); err == nil {
		t.Fatal("expected duplicate-api error")
	}
}

// TestRuntimeRejectsReservedMetaName pins the AddAPI guard against
// declaring a meta whose name collides with a top-level CEL variable
// in any predicate env. Under cel.Container(apiName), a meta named
// `principal` registers as `<api>.principal`, which is the
// fully-qualified form of the policy env's `principal` variable;
// the same shadowing risk applies to `request`, `action`, `match`,
// `input`, and `response`.
func TestRuntimeRejectsReservedMetaName(t *testing.T) {
	for _, name := range []string{"principal", "request", "action", "match", "input", "response"} {
		t.Run(name, func(t *testing.T) {
			b := NewBuilder()
			api := &models.API{
				Name: "x",
				Meta: []models.Metadata{{Name: name}},
			}
			if err := b.AddAPI(api); err == nil {
				t.Fatalf("expected error for reserved meta name %q", name)
			}
		})
	}
}

// TestRuntimeRejectsReservedAPIName pins the symmetric guard
// against an API whose own name collides with a reserved top-level
// CEL variable. cel.Container("principal") makes every meta on the
// API register under that prefix and turns bare-name resolution
// into a container-search-dependent precedence question.
func TestRuntimeRejectsReservedAPIName(t *testing.T) {
	for _, name := range []string{"principal", "request", "action", "match", "input", "response"} {
		t.Run(name, func(t *testing.T) {
			b := NewBuilder()
			if err := b.AddAPI(&models.API{Name: name}); err == nil {
				t.Fatalf("expected error for reserved api name %q", name)
			}
		})
	}
}

// TestBuilderIsOneShot pins A3: a Builder consumed by Build refuses
// further AddAPI or Build calls. This stops a misuse from quietly
// producing a second Runtime that shares the registry of the first.
func TestBuilderIsOneShot(t *testing.T) {
	b := NewBuilder()
	if _, err := b.Build(); err != nil {
		t.Fatalf("first build: %v", err)
	}
	if _, err := b.Build(); err == nil {
		t.Fatal("second Build must fail")
	}
	if err := b.AddAPI(&models.API{Name: "x"}); err == nil {
		t.Fatal("AddAPI after Build must fail")
	}
}

// TestRuntimeRejectsPolicyForUnknownAPI covers the missing-api dispatch path.
func TestRuntimeRejectsPolicyForUnknownAPI(t *testing.T) {
	rt, err := NewBuilder().Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := rt.AddPolicy(&models.Policy{API: "missing"}); err == nil {
		t.Fatal("expected unknown-api error")
	}
}

// TestPolicyCanConstructCrossApiMeta verifies that a policy condition
// can build a Type{...} literal — both for its own API's meta (short
// name via container) and for another API's meta (fully qualified).
// This guards the design choice to use fully-qualified bind variable
// names in policies: the constructor still finds the type, because
// struct-literal lookups go through the type provider regardless of
// any same-named variable declaration.
func TestPolicyCanConstructCrossApiMeta(t *testing.T) {
	b := NewBuilder()

	driveAPI := &models.API{
		Name:         "google.drive",
		BaseURL:      "https://drive",
		PathPrefixes: []string{"/drive"},
		Meta: []models.Metadata{{
			Name:    "file",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/drive/' + string(input.id))`,
			Output: []models.OutputField{
				{Name: "owner", Expr: "response.body.owner"},
			},
		}},
		Actions: []models.Action{{
			Name:   "get_file",
			Filter: `request.path.startsWith('/drive/')`,
			Bind:   "file{id: 'doc-1'}",
		}},
	}
	gmailAPI := &models.API{
		Name:         "google.gmail",
		BaseURL:      "https://gmail",
		PathPrefixes: []string{"/gmail"},
		Meta: []models.Metadata{{
			Name: "message",
			Kind: "endpoint",
			Input: []models.InputField{
				{Name: "user_id"},
				{Name: "file_id"},
			},
			Request: `get('/gmail/' + string(input.user_id) + '/' + string(input.file_id))`,
			Output: []models.OutputField{
				{Name: "attachment_id", Expr: "response.body.attachment_id"},
			},
		}},
		Actions: []models.Action{{
			Name:   "get_message",
			Filter: `request.path.startsWith('/gmail/')`,
			Bind:   `message{user_id: 'me', file_id: 'doc-1'}`,
		}},
	}

	if err := b.AddAPI(driveAPI); err != nil {
		t.Fatalf("add drive: %v", err)
	}
	if err := b.AddAPI(gmailAPI); err != nil {
		t.Fatalf("add gmail: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Policy constructs a google.drive.file inline using only the
	// message's attachment_id, then asserts on its owner. This is the
	// "policy can construct types" case — both leaf-name access on the
	// bind variable and fully-qualified construction of a different
	// API's type live in the same condition.
	if err := rt.AddPolicy(&models.Policy{
		API:       "google.gmail",
		Name:      "via_constructed_file",
		Action:    `action.name == "get_message"`,
		Condition: `google.drive.file{id: message.attachment_id}.owner == 'alice'`,
		Result:    models.Permit,
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	api := staticAPI{bodies: map[string]map[string]any{
		"/gmail/me/doc-1": {"attachment_id": "doc-1"},
		"/drive/doc-1":    {"owner": "alice"},
	}}
	_, got, err := rt.Evaluate(t.Context(), constantResolver(api), &pb.Request{
		Method:       "GET",
		Path:         "/gmail/x",
		PathSegments: []string{"gmail", "x"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit, got %s", got)
	}
}

// TestCrossApiCompleterUsesMetasOwnPhysical pins the B2 fix: a policy
// on API A that reads a meta defined on API B must call B's
// PhysicalAPI, not A's. Before the fix, the routed-request API leaked
// into the completer for every bind, so a `gmail` policy reading
// `google.drive.file{...}` would issue the GET against the gmail
// upstream.
func TestCrossApiCompleterUsesMetasOwnPhysical(t *testing.T) {
	driveAPI := &models.API{
		Name:         "google.drive",
		BaseURL:      "https://drive",
		PathPrefixes: []string{"/drive"},
		Meta: []models.Metadata{{
			Name:    "file",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/drive/' + string(input.id))`,
			Output:  []models.OutputField{{Name: "owner", Expr: "response.body.owner"}},
		}},
		Actions: []models.Action{{
			Name:   "get_file",
			Filter: `request.path.startsWith('/drive/')`,
			Bind:   "file{id: 'doc-1'}",
		}},
	}
	gmailAPI := &models.API{
		Name:         "google.gmail",
		BaseURL:      "https://gmail",
		PathPrefixes: []string{"/gmail"},
		Actions: []models.Action{{
			Name:   "any",
			Filter: `request.path.startsWith('/gmail/')`,
			Bind:   `google.drive.file{id: 'doc-1'}`,
		}},
	}
	b := NewBuilder()
	if err := b.AddAPI(driveAPI); err != nil {
		t.Fatalf("add drive: %v", err)
	}
	if err := b.AddAPI(gmailAPI); err != nil {
		t.Fatalf("add gmail: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := rt.AddPolicy(&models.Policy{
		API:       "google.gmail",
		Name:      "owner_alice",
		Action:    `action.name == "any"`,
		Condition: `google.drive.file.owner == 'alice'`,
		Result:    models.Permit,
	}); err != nil {
		t.Fatalf("policy: %v", err)
	}

	// Each physical only knows how to answer for its own API. A
	// gmail-routed inbound request that reads google.drive.file must
	// call the drive physical.
	drivePhys := staticAPI{bodies: map[string]map[string]any{
		"/drive/doc-1": {"owner": "alice"},
	}}
	gmailPhys := staticAPI{bodies: map[string]map[string]any{}} // no recipes
	resolve := func(name string) (compiled.PhysicalAPI, error) {
		switch name {
		case "google.drive":
			return drivePhys, nil
		case "google.gmail":
			return gmailPhys, nil
		}
		t.Fatalf("unexpected resolve(%q)", name)
		return nil, nil
	}

	_, got, err := rt.Evaluate(t.Context(), resolve, &pb.Request{
		Method:       "GET",
		Path:         "/gmail/x",
		PathSegments: []string{"gmail", "x"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit (drive physical answered), got %s", got)
	}
}

// TestMemoizeResolverCachesHitsAndErrors pins memoizeResolver's two
// contracts: identical names share one resolver call within an
// Evaluate, and an error result is sticky (no silent retry that
// could mask a transient upstream-construction failure).
func TestMemoizeResolverCachesHitsAndErrors(t *testing.T) {
	calls := map[string]int{}
	stub := staticAPI{bodies: map[string]map[string]any{}}
	resolve := func(name string) (compiled.PhysicalAPI, error) {
		calls[name]++
		if name == "broken" {
			return nil, fmt.Errorf("boom")
		}
		return stub, nil
	}

	memo := memoizeResolver(resolve)
	if _, err := memo("a"); err != nil {
		t.Fatalf("first a: %v", err)
	}
	if _, err := memo("a"); err != nil {
		t.Fatalf("second a: %v", err)
	}
	if calls["a"] != 1 {
		t.Errorf("calls[a] = %d, want 1", calls["a"])
	}

	if _, err := memo("broken"); err == nil {
		t.Fatal("first broken: want error")
	}
	if _, err := memo("broken"); err == nil {
		t.Fatal("second broken: want error")
	}
	if calls["broken"] != 1 {
		t.Errorf("calls[broken] = %d, want 1 (errors must stick)", calls["broken"])
	}
}
