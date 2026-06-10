package runtime

import (
	"context"
	"fmt"
	"sort"
	"strings"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/messages"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Builder collects API specs and produces a Runtime via Build. Once
// Build returns, the API/meta surface is frozen; only policies (which
// are self-contained) can be added afterwards.
type Builder struct {
	registry *messages.Registry
	pending  map[string]pendingAPI
	built    bool
}

// pendingAPI pairs a raw API spec with the per-meta Type lookup
// produced when its types were registered, so Build can pass them
// straight to the compile pipeline without re-walking the spec.
type pendingAPI struct {
	spec  *models.API
	types map[string]*messages.Type
}

// NewBuilder returns an empty Builder.
func NewBuilder() *Builder {
	return &Builder{
		registry: messages.NewRegistry(),
		pending:  map[string]pendingAPI{},
	}
}

// AddAPI registers api's meta types in the shared registry and queues
// it for compilation. The expressions are compiled when Build runs;
// queueing the work makes cross-API references resolve regardless of
// insertion order.
//
// Returns an error if api.Name is already registered, if Build has
// already consumed the builder, or if any meta type collides with one
// already in the registry.
func (b *Builder) AddAPI(api *models.API) error {
	if b.built {
		return fmt.Errorf("api %q: builder already consumed by Build", api.Name)
	}
	if _, exists := b.pending[api.Name]; exists {
		return fmt.Errorf("api %q already registered", api.Name)
	}
	// Reject names that would collide with a top-level CEL variable
	// (see reservedTopLevelCEL). Under cel.Container(apiName) the
	// bare identifier resolves via ancestor search, and a meta
	// named e.g. "principal" would silently shadow the real
	// principal variable.
	if _, bad := reservedTopLevelCEL[api.Name]; bad {
		return fmt.Errorf("api %q: name collides with a reserved top-level CEL variable", api.Name)
	}
	for _, m := range api.Meta {
		if _, bad := reservedTopLevelCEL[m.Name]; bad {
			return fmt.Errorf("api %q: meta name %q collides with a reserved top-level CEL variable", api.Name, m.Name)
		}
	}
	types, err := registerAPITypes(api, b.registry)
	if err != nil {
		return err
	}
	b.pending[api.Name] = pendingAPI{spec: api, types: types}
	return nil
}

// reservedTopLevelCEL enumerates the bare identifiers any predicate
// env declares as a top-level variable today. Any meta or API
// matching one of these names introduces a container-ancestor-search
// collision under `cel.Container(apiName)` and is rejected at load.
// Add new entries here whenever a predicate env grows a new
// top-level — the test suite has paired coverage for each name.
var reservedTopLevelCEL = map[string]struct{}{
	"principal": {},
	"request":   {},
	"action":    {},
	"match":     {},
	"input":     {},
	"response":  {},
	"now":       {},
}

// Build compiles every registered API in two passes (metas first, then
// actions, so cross-API binds resolve) and returns the finalised
// Runtime. The Builder is consumed: subsequent AddAPI or Build calls
// fail explicitly so a misuse can't silently corrupt the second
// runtime. Construct a fresh Builder to start over.
//
// Iteration order is deterministic (sorted by api name) so a config
// that produces multiple compile errors surfaces the same one on
// every run, and prefix-conflict messages name a stable "first vs
// second" pair.
func (b *Builder) Build() (*Runtime, error) {
	if b.built {
		return nil, fmt.Errorf("Builder.Build: already consumed")
	}
	b.built = true
	pending := b.sortedPending()
	apis := make(map[string]*APIRuntime, len(pending))
	specs := make(map[string]*models.API, len(pending))
	metas := map[string]*compiled.Meta{}
	for _, p := range pending {
		ms, err := compileAPIMetas(p.spec, b.registry, p.types)
		if err != nil {
			return nil, err
		}
		for fullName, m := range ms {
			metas[fullName] = m
		}
	}
	for _, p := range pending {
		rt, err := compileAPIActions(p.spec, b.registry, metas)
		if err != nil {
			return nil, err
		}
		apis[p.spec.Name] = rt
		specs[p.spec.Name] = p.spec
	}
	routes, err := buildPrefixRoutes(pending)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		registry: b.registry,
		apis:     apis,
		specs:    specs,
		metas:    metas,
		routes:   routes,
	}, nil
}

// sortedPending returns the Builder's pending APIs sorted by name,
// for deterministic iteration in Build / buildPrefixRoutes.
func (b *Builder) sortedPending() []pendingAPI {
	out := make([]pendingAPI, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].spec.Name < out[j].spec.Name })
	return out
}

// Runtime owns the compiled API surface produced by Builder.Build.
// One messages.Registry is shared across every APIRuntime so an
// expression on one API can reference meta types defined on another
// (e.g. a gmail policy reading `google.drive.file{...}`).
//
// Concurrency contract: apis / metas / routes are populated by Build
// and never mutated afterwards, so Evaluate reads them without a
// lock. Per-API policy mutation (AddPolicy / ReplacePolicy /
// RemovePolicy) goes through the per-API policyStore's own RWMutex.
// Anyone adding a post-Build mutator on these fields must also add
// the lock for the readers.
type Runtime struct {
	registry *messages.Registry
	apis     map[string]*APIRuntime
	// specs keeps the YAML-shaped *models.API around post-Build for
	// the control-plane handlers (/_api/apis, /_api/docs).
	specs  map[string]*models.API
	metas  map[string]*compiled.Meta
	routes []prefixRoute
}

// prefixRoute pairs a pre-split path prefix with the API name that
// claims it. Pre-splitting at Build time lets routing avoid any
// per-request string work.
type prefixRoute struct {
	segments []string
	apiName  string
	source   string // original prefix string, kept for diagnostics
}

// AddPolicy registers a policy under the matching APIRuntime.
func (r *Runtime) AddPolicy(policy *models.Policy) error {
	rt, ok := r.apis[policy.API]
	if !ok {
		return fmt.Errorf("policy %q targets api %q, which is not registered", policy.Name, policy.API)
	}
	return rt.Add(policy)
}

// ReplacePolicy upserts a policy: if a policy with the same (api, name)
// already exists, its compiled form is swapped in place — evaluation
// and ListPolicies order are stable across edits unless the edit flips
// the result (deny ↔ permit), which moves the policy to the end of its
// new bucket. A new policy is appended. Compile errors leave the
// runtime untouched.
//
// The returned bool reports whether a previous policy was replaced —
// callers that distinguish create from update (e.g. CRUD endpoints
// returning 201 vs 200) read this signal.
func (r *Runtime) ReplacePolicy(policy *models.Policy) (bool, error) {
	rt, ok := r.apis[policy.API]
	if !ok {
		return false, fmt.Errorf("policy %q targets api %q, which is not registered", policy.Name, policy.API)
	}
	return rt.Replace(policy)
}

// RemovePolicy deletes the policy named (api, name). Returns true if a
// policy was removed. Removing a non-existent policy is not an error;
// the bool lets a caller surface 404 when the operation was a no-op.
func (r *Runtime) RemovePolicy(api, name string) (bool, error) {
	rt, ok := r.apis[api]
	if !ok {
		return false, fmt.Errorf("api %q is not registered", api)
	}
	return rt.Remove(name), nil
}

// ListPolicies returns a snapshot of every policy across every API.
// API names are visited in lexicographic order; per-API policies
// preserve their evaluation order (deny-first then permit, declared
// order). The stable cross-API order matters because the
// control-plane's GET /_api/policies returns this list verbatim —
// re-sorting on every poll would defeat any diff-based "did anything
// change?" client.
func (r *Runtime) ListPolicies() []models.Policy {
	names := make([]string, 0, len(r.apis))
	for name := range r.apis {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []models.Policy{}
	for _, name := range names {
		out = append(out, r.apis[name].List()...)
	}
	return out
}

// ValidatePolicy runs the same compile pipeline as ReplacePolicy but
// discards the result, returning only the validation error (if any).
// The control plane uses this for `:dryRun` and per-keystroke editor
// feedback so a bad policy never has to round-trip through Put before
// the author sees the error.
func (r *Runtime) ValidatePolicy(policy *models.Policy) error {
	rt, ok := r.apis[policy.API]
	if !ok {
		return fmt.Errorf("policy %q targets api %q, which is not registered", policy.Name, policy.API)
	}
	_, err := rt.compile(policy)
	return err
}

// API returns the APIRuntime for the given name, or nil if not
// registered.
func (r *Runtime) API(name string) *APIRuntime { return r.apis[name] }

// APISpecs returns every registered API's spec, sorted
// alphabetically by name so the control-plane API listing is
// stable across calls.
func (r *Runtime) APISpecs() []*models.API {
	names := make([]string, 0, len(r.specs))
	for name := range r.specs {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*models.API, 0, len(names))
	for _, name := range names {
		out = append(out, r.specs[name])
	}
	return out
}

// APINames returns the names of every registered API in unspecified
// order. Returning a fresh slice rather than the internal map prevents
// callers from accidentally mutating the runtime's API surface
// post-Build, and is enough for the only caller (logging on startup).
func (r *Runtime) APINames() []string {
	out := make([]string, 0, len(r.apis))
	for name := range r.apis {
		out = append(out, name)
	}
	return out
}

// PhysicalAPIResolver builds the per-API upstream client. Re-exported
// from compiled so callers don't have to import that package directly.
type PhysicalAPIResolver = compiled.PhysicalAPIResolver

// Evaluate routes req by matching its path against each API's declared
// `path_prefixes` and evaluates its policies. The returned apiName
// tells the caller which API was hit (used by the server to forward
// upstream); ("", Deny, nil) means no API claimed the request. Prefix
// ambiguity is rejected at Build time, so routing never errors here.
//
// Cross-API completion is fully supported: a `gmail` policy that
// binds `google.drive.file{...}` calls `resolve("google.drive")`, not
// the routed API. The resolver is wrapped in a per-evaluation memoizer
// so any given API name is built at most once per inbound request even
// when multiple metas on the same API fire.
func (r *Runtime) Evaluate(ctx context.Context, resolve PhysicalAPIResolver, req *pb.Request, principal *pb.Principal) (string, models.PolicyResult, error) {
	if principal == nil {
		return "", models.Deny, fmt.Errorf("principal is required")
	}
	apiName := r.routeRequest(req)
	if apiName == "" {
		return "", models.Deny, nil
	}
	memo := memoizeResolver(resolve)
	decision, err := r.apis[apiName].Evaluate(ctx, memo, req, principal)
	return apiName, decision, err
}

// APIForPath returns the API name whose declared path_prefixes
// claim path, or "" when no API matches. The data plane uses this
// before authenticate() so a per-API access_denied_status override
// can be looked up on the 401 path (where Evaluate hasn't run yet
// and apiName isn't otherwise available).
//
// Cheap by design: a SplitPath + segment-wise route scan, no
// upstream IO and no policy evaluation.
func (r *Runtime) APIForPath(path string) string {
	return r.routeRequest(&pb.Request{PathSegments: compiled.SplitPath(path)})
}

// MatchedActions reports which action names fire on req, scoped to
// the API its path-prefix routes to. Returns "" / nil when no API
// claims the path. Used by the data plane to enrich a deny body
// with "your request matched action X — write a policy that gates
// X if you want it to permit".
//
// Cheap by design: in-memory match + bind evaluation only, no
// upstream metas. Safe to call after Evaluate without a noticeable
// latency hit.
func (r *Runtime) MatchedActions(req *pb.Request) (string, []string, error) {
	apiName := r.routeRequest(req)
	if apiName == "" {
		return "", nil, nil
	}
	actions, err := r.apis[apiName].MatchedActions(req)
	if err != nil {
		return apiName, nil, err
	}
	return apiName, actions, nil
}

// memoizeResolver wraps `resolve` so each apiName is built at most
// once per inbound request. Successful builds and errors are both
// cached for the duration of the evaluation: an upstream-construction
// failure on one meta side call must not be silently retried by the
// next.
func memoizeResolver(resolve PhysicalAPIResolver) PhysicalAPIResolver {
	type entry struct {
		api compiled.PhysicalAPI
		err error
	}
	cache := map[string]entry{}
	return func(name string) (compiled.PhysicalAPI, error) {
		if e, ok := cache[name]; ok {
			return e.api, e.err
		}
		api, err := resolve(name)
		cache[name] = entry{api: api, err: err}
		return api, err
	}
}

// routeRequest selects the API whose declared `path_prefixes` claim
// req's path. Pre-split prefixes are matched segment-wise against
// req.PathSegments so "/drive" claims "/drive/v3/..." but not
// "/drives/...". Build-time validation guarantees at most one prefix
// matches any path, so this is an O(N) scan with no tie-breaking.
// Returns "" when no prefix claims the request (the caller translates
// that to Deny).
func (r *Runtime) routeRequest(req *pb.Request) string {
	segs := req.GetPathSegments()
	for _, route := range r.routes {
		if hasSegmentPrefix(segs, route.segments) {
			return route.apiName
		}
	}
	return ""
}

// hasSegmentPrefix reports whether prefix is a segment-wise prefix of
// path: same length-or-longer, and each prefix segment matches byte
// for byte.
//
// An empty prefix matches *nothing*. The Builder normally rejects
// zero-segment routes at AddAPI time (see buildPrefixRoutes), but
// safe-by-construction here means a future caller (a test helper, a
// serialisation round-trip) cannot accidentally cause every inbound
// request to be routed to the wrong API.
func hasSegmentPrefix(path, prefix []string) bool {
	if len(prefix) == 0 || len(path) < len(prefix) {
		return false
	}
	for i, s := range prefix {
		if path[i] != s {
			return false
		}
	}
	return true
}

// buildPrefixRoutes flattens every API's PathPrefixes into a single
// ordered list and rejects ambiguous configurations. Two prefixes
// conflict when one is a segment-wise prefix of another (including
// equality) — that would let one request match two APIs and make
// routing depend on traversal order.
//
// Caller passes a sorted-by-name pending slice so the conflict
// message names a stable lexicographically-smaller-first pair.
func buildPrefixRoutes(pending []pendingAPI) ([]prefixRoute, error) {
	var routes []prefixRoute
	for _, p := range pending {
		for _, raw := range p.spec.PathPrefixes {
			if raw == "" || !strings.HasPrefix(raw, "/") {
				return nil, fmt.Errorf("api %q: path_prefix %q must start with %q", p.spec.Name, raw, "/")
			}
			// A trailing slash produces an empty final segment, which
			// would require the request's matching segment to be empty
			// too — silently unroutable. Fail loud at load instead.
			if strings.HasSuffix(raw, "/") {
				return nil, fmt.Errorf("api %q: path_prefix %q must not end with %q", p.spec.Name, raw, "/")
			}
			segs := compiled.SplitPath(raw)
			if len(segs) == 0 {
				return nil, fmt.Errorf("api %q: path_prefix %q has no segments", p.spec.Name, raw)
			}
			routes = append(routes, prefixRoute{
				segments: segs,
				apiName:  p.spec.Name,
				source:   raw,
			})
		}
	}
	for i := range routes {
		for j := range routes {
			if i == j {
				continue
			}
			if hasSegmentPrefix(routes[j].segments, routes[i].segments) {
				return nil, fmt.Errorf(
					"path_prefix conflict: api %q prefix %q is a prefix of api %q prefix %q",
					routes[i].apiName, routes[i].source,
					routes[j].apiName, routes[j].source,
				)
			}
		}
	}
	return routes, nil
}
