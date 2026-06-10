// Package runtime ties the YAML-loaded API and policy schema to a
// CEL-based evaluator. Mirrors `rust-impl/src/runtime/api_runtime.rs`.
package runtime

import (
	"context"
	"fmt"
	"iter"
	"net/url"
	"sync"
	"time"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/messages"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// APIRuntime evaluates incoming requests against a single API's actions
// and policies. Mirrors `rust-impl/src/runtime/api_runtime.rs::APIRuntime`.
//
// The registry and the global metas map are typically shared across
// every APIRuntime in a Runtime, so cross-API binds (e.g. a sheets
// action binding `drive.file{...}`) and cross-API completers resolve
// without per-API duplication. The standalone New constructor (used by
// tests) gives an APIRuntime a private registry containing only its
// own types.
type APIRuntime struct {
	name string
	// baseURL is the raw YAML-declared upstream; parsedBaseURL is
	// the same value parsed once at compile time so the forward
	// path doesn't re-parse per request.
	baseURL       string
	parsedBaseURL *url.URL
	// accessDeniedStatus is the HTTP status the data plane returns
	// on auth-fail and policy-deny for this API; 0 means "use
	// default" (401/403). Cached at compile time so the data-plane
	// hot path doesn't re-read the spec.
	accessDeniedStatus int
	// authOptional is the models.API.AuthOptional() snapshot. When
	// true, the data plane admits anonymous (no-Bearer) requests on
	// this API and runs them through policy with an anonymous
	// principal. See models.API.Auth.
	authOptional bool
	registry     *messages.Registry
	metas        map[string]*compiled.Meta // keyed by full name (e.g. "gmail.message")
	// actions is a slice in YAML-declared order so log-replay across
	// requests is stable. The runtime walks every action on every
	// request and never looks one up by name, so the slice is also
	// cheaper than a map.
	actions []*compiled.Action
	store   *policyStore
	// now returns the wall-clock value injected as the `now` CEL
	// variable on every policy evaluation. Captured once per
	// `Evaluate` call so all predicates and conditions on the same
	// request see the same value. Defaults to time.Now; tests
	// override for determinism.
	now func() time.Time
}

// registerAPITypes performs Phase 1 of API compilation: install every
// meta's Type in reg. Splitting this out lets a multi-API host
// (Runtime) register every API's types before any expression
// compilation runs, so output expressions on one API can reference
// types defined on another regardless of insertion order.
//
// Returns a map keyed by meta short name, used by compileAPI as the
// per-meta Type lookup.
func registerAPITypes(api *models.API, reg *messages.Registry) (map[string]*messages.Type, error) {
	types := make(map[string]*messages.Type, len(api.Meta))
	for i := range api.Meta {
		m := &api.Meta[i]
		t, err := compiled.RegisterMetaType(m, api.Name, reg)
		if err != nil {
			return nil, fmt.Errorf("api %q: %w", api.Name, err)
		}
		types[m.Name] = t
	}
	return types, nil
}

// compileAPIMetas performs Phase 2a: compile every meta's request and
// output programs against reg. Returned map is keyed by meta full name
// (e.g. "gmail.message"), suitable for merging into a cross-API metas
// map before any action compilation begins.
func compileAPIMetas(api *models.API, reg *messages.Registry, types map[string]*messages.Type) (map[string]*compiled.Meta, error) {
	metas := make(map[string]*compiled.Meta, len(api.Meta))
	for i := range api.Meta {
		m := &api.Meta[i]
		cm, err := compiled.CompileMeta(m, api.Name, types[m.Name], reg)
		if err != nil {
			return nil, fmt.Errorf("api %q: %w", api.Name, err)
		}
		metas[cm.Type.FullName] = cm
	}
	return metas, nil
}

// compileAPIActions performs Phase 2b: compile every action's filter
// and bind programs against reg. allMetas must include every API's
// metas (not just this one's), so cross-API binds can resolve their
// output type to a Meta entry. The returned APIRuntime is wired with
// allMetas so completers also resolve cross-API child Values.
func compileAPIActions(api *models.API, reg *messages.Registry, allMetas map[string]*compiled.Meta) (*APIRuntime, error) {
	actions := make([]*compiled.Action, 0, len(api.Actions))
	for i := range api.Actions {
		a := &api.Actions[i]
		ca, err := compiled.NewAction(a, api.Name, reg, allMetas)
		if err != nil {
			return nil, fmt.Errorf("api %q action %q: %w", api.Name, a.Name, err)
		}
		actions = append(actions, ca)
	}
	parsed, err := url.Parse(api.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("api %q base_url: %w", api.Name, err)
	}
	if err := validateAccessDeniedStatus(api); err != nil {
		return nil, err
	}
	if err := validateAuth(api); err != nil {
		return nil, err
	}
	return &APIRuntime{
		name:               api.Name,
		baseURL:            api.BaseURL,
		parsedBaseURL:      parsed,
		accessDeniedStatus: api.AccessDeniedStatus,
		authOptional:       api.AuthOptional(),
		registry:           reg,
		metas:              allMetas,
		actions:            actions,
		store:              newPolicyStore(),
		now:                time.Now,
	}, nil
}

// validateAccessDeniedStatus rejects an obviously-wrong override: a
// success-or-redirect status on a denial path is fine (Slack uses
// 200), but anything outside [200, 599] or below 200 is a typo, not
// a deliberate choice. Default 0 means "use natural status" and is
// always allowed.
func validateAccessDeniedStatus(api *models.API) error {
	s := api.AccessDeniedStatus
	if s == 0 {
		return nil
	}
	if s < 200 || s > 599 {
		return fmt.Errorf("api %q access_denied_status %d: must be in [200, 599]", api.Name, s)
	}
	return nil
}

// validateAuth rejects an unknown auth: value. "" / "required" /
// "optional" are the supported settings; anything else is a typo
// that would silently fall back to the required default and surprise
// the operator.
func validateAuth(api *models.API) error {
	switch api.Auth {
	case "", "required", "optional":
		return nil
	default:
		return fmt.Errorf("api %q auth %q: must be one of required|optional", api.Name, api.Auth)
	}
}

// Add registers a policy. The policy's API field must match this
// runtime's name. The `policy.Action` field is no longer a literal
// action reference — it is a CEL bool predicate evaluated per matched
// action at request time (compiled inside NewPolicy), so there is no
// "unknown action" check here.
//
// Add appends; a second call with the same name produces a duplicate.
// Use Replace for upsert semantics.
func (r *APIRuntime) Add(policy *models.Policy) error {
	cp, err := r.compile(policy)
	if err != nil {
		return err
	}
	r.store.add(cp)
	return nil
}

// Replace inserts policy if no policy with the same name is registered,
// otherwise swaps the existing one in place. Returns true if a previous
// policy was replaced. The compile step runs before any mutation so a
// failing compile leaves the existing policy untouched.
func (r *APIRuntime) Replace(policy *models.Policy) (bool, error) {
	cp, err := r.compile(policy)
	if err != nil {
		return false, err
	}
	return r.store.replace(cp), nil
}

// Remove deletes the policy with the given name (if any). Returns true
// if a policy was removed. Idempotent: removing a non-existent policy
// is not an error.
func (r *APIRuntime) Remove(name string) bool {
	return r.store.remove(name)
}

// List returns the policies registered under this API in evaluation
// order (deny first, then permit). The returned slice is a fresh
// snapshot so callers may retain or mutate it without affecting the
// runtime.
func (r *APIRuntime) List() []models.Policy {
	return r.store.list()
}

// compile validates the API field and runs the CEL compile pipeline.
// Splitting this out of Add lets Replace share the same compile path
// without duplicating the API-name check.
func (r *APIRuntime) compile(policy *models.Policy) (*compiled.Policy, error) {
	if policy.API != r.name {
		return nil, fmt.Errorf("policy %q targets api %q, runtime is for %q", policy.Name, policy.API, r.name)
	}
	return compiled.NewPolicy(policy, r.name, r.registry)
}

// BaseURL returns the API's upstream base URL.
func (r *APIRuntime) BaseURL() string { return r.baseURL }

// ParsedBaseURL returns the upstream base URL parsed once at compile
// time, so the forward path doesn't re-parse it per request.
func (r *APIRuntime) ParsedBaseURL() *url.URL { return r.parsedBaseURL }

// AccessDeniedStatus returns the operator-configured override for
// the HTTP status the data plane returns on auth-fail / policy-deny
// paths, or 0 if unset. The data plane interprets 0 as "use the
// natural status" (401 / 403 respectively).
func (r *APIRuntime) AccessDeniedStatus() int { return r.accessDeniedStatus }

// AuthOptional reports whether the API admits anonymous (no-Bearer)
// requests. The data plane reads this to decide whether to skip the
// 401 gate for an inbound request matched to this API. See
// models.API.Auth.
func (r *APIRuntime) AuthOptional() bool { return r.authOptional }

// Evaluate selects the matching actions for the request, then walks
// the candidate policies (deny-first, permit-second). For each policy,
// every matched action is filtered through the policy's action
// predicate; the condition runs once per (policy, accepted action)
// pair. The first true condition returns that policy's result. If no
// policy fires, returns Deny.
//
// Per-action condition eval (rather than a single union over all
// matched actions) keeps the bind shape predictable — each invocation
// sees one action's binds expressed as Some(value) and every other
// meta as the absent optional, so a condition's optional accessors
// have a coherent context.
//
// ctx is the inbound request's context — propagated to upstream side
// calls so cancelling the inbound request aborts pending fetches.
//
// `resolve` is the per-API PhysicalAPI lookup, threaded into Policy
// evaluation so cross-API binds and inline `Type{...}` literals call
// the *meta's* upstream rather than this APIRuntime's. A test that
// only exercises one API may pass a resolver that returns the same
// physical for every name (see runtime/helpers_test.go).
func (r *APIRuntime) Evaluate(ctx context.Context, resolve compiled.PhysicalAPIResolver, req *pb.Request, principal *pb.Principal) (models.PolicyResult, error) {
	if principal == nil {
		return models.Deny, fmt.Errorf("principal is required")
	}
	matchedActions, err := r.matchActions(req)
	if err != nil {
		return models.Deny, err
	}

	// Capture wall-clock once per request so every policy that reads
	// `now` sees the same value. Drift between the principal predicate
	// and the (later) condition would let a request straddle a
	// boundary in opposite directions across two policies; sharing one
	// `now` removes that whole class of inconsistency. Tests can swap
	// r.now to inject a deterministic clock.
	now := r.now()

	firing := compiled.FiringObserverFrom(ctx)
	condEval := compiled.ConditionEvalObserverFrom(ctx)
	for p := range r.store.all() {
		// principal: gates the whole policy and runs first because it
		// is the cheapest filter — a policy that only fires for a
		// specific caller short-circuits before the per-action loop.
		ok, err := p.AppliesToPrincipal(req, principal, now)
		if err != nil {
			return models.Deny, err
		}
		if !ok {
			continue
		}
		for _, m := range matchedActions {
			ok, err := p.AppliesTo(m.name, req, m.match, principal, now)
			if err != nil {
				return models.Deny, err
			}
			if !ok {
				continue
			}
			fired, err := p.Evaluate(ctx, resolve, m.name, req, principal, now, m.binds, r.registry, r.metas)
			if condEval != nil {
				condEval(m.name, p.Name, p.Result, fired, err)
			}
			if err != nil {
				return models.Deny, err
			}
			if fired {
				if firing != nil {
					firing(m.name, p.Name, m.binds)
				}
				return p.Result, nil
			}
		}
	}
	return models.Deny, nil
}

// matchedAction bundles everything an action's match produced — the
// captures and the resolved binds — so the per-policy loop in Evaluate
// can hand both to the predicate (`match` for path-shape gating) and
// the condition (`binds` for the meta values).
type matchedAction struct {
	name  string
	match map[string]string
	binds []compiled.BoundValue
}

// MatchedActions returns the names of every action whose match logic
// fires on req, in the same YAML-declared order Evaluate uses. It is
// the cheap "what did the request look like to the runtime?" probe
// the deny path uses to enrich its response — rerunning matchActions
// is in-memory CEL evaluation only; binds are evaluated but no
// upstream metas are fetched.
func (r *APIRuntime) MatchedActions(req *pb.Request) ([]string, error) {
	matches, err := r.matchActions(req)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.name)
	}
	return out, nil
}

// matchActions runs every action's match logic against req. Walks the
// actions in YAML-declared order so the resulting matchedAction slice
// is deterministic across requests — log-replay and policy-debugging
// flows are easier when "first matched action" is stable.
func (r *APIRuntime) matchActions(req *pb.Request) ([]matchedAction, error) {
	var out []matchedAction
	for _, a := range r.actions {
		match, ok, err := a.Match(req)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		binds, err := a.EvalBinds(req, match)
		if err != nil {
			return nil, err
		}
		out = append(out, matchedAction{name: a.Name, match: match, binds: binds})
	}
	return out, nil
}

// policyStore keeps deny policies before permit policies so deny wins
// when both apply. The split is maintained at mutate time so the
// per-request iteration is just two slice walks.
//
// The mutex guards both slices. Reads (Evaluate) take a snapshot under
// the read lock and iterate the snapshot, so the lock is never held
// during CEL evaluation — which fans out to upstream meta side calls
// and could otherwise stall a writer for the duration of an HTTP
// round trip.
type policyStore struct {
	mu     sync.RWMutex
	deny   []*compiled.Policy
	permit []*compiled.Policy
}

func newPolicyStore() *policyStore { return &policyStore{} }

func (s *policyStore) add(p *compiled.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendLocked(p)
}

// replace upserts p by name. Returns true if a previous policy with
// the same name was swapped out. The result-bucket may change between
// the old and new policy (deny ↔ permit) — handled by removing from
// whichever bucket the existing entry sits in and re-appending to the
// new policy's bucket.
func (s *policyStore) replace(p *compiled.Policy) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	existed := s.removeLocked(p.Name)
	s.appendLocked(p)
	return existed
}

// remove deletes the policy with the given name. Returns true if a
// policy was removed.
func (s *policyStore) remove(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeLocked(name)
}

// list returns a fresh slice of the policies' source models in
// evaluation order (deny then permit).
func (s *policyStore) list() []models.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.Policy, 0, len(s.deny)+len(s.permit))
	for _, p := range s.deny {
		out = append(out, p.Source())
	}
	for _, p := range s.permit {
		out = append(out, p.Source())
	}
	return out
}

func (s *policyStore) appendLocked(p *compiled.Policy) {
	if p.Result == models.Deny {
		s.deny = append(s.deny, p)
	} else {
		s.permit = append(s.permit, p)
	}
}

// removeLocked drops the first policy with the given name from
// whichever bucket holds it. Returns true on hit.
func (s *policyStore) removeLocked(name string) bool {
	if i := indexByName(s.deny, name); i >= 0 {
		s.deny = append(s.deny[:i], s.deny[i+1:]...)
		return true
	}
	if i := indexByName(s.permit, name); i >= 0 {
		s.permit = append(s.permit[:i], s.permit[i+1:]...)
		return true
	}
	return false
}

func indexByName(ps []*compiled.Policy, name string) int {
	for i, p := range ps {
		if p.Name == name {
			return i
		}
	}
	return -1
}

// all yields every registered policy, deny-first then permit, from a
// snapshot taken under the read lock. The snapshot is cheap (a single
// slice copy) and lets evaluation run without holding the lock — so
// upstream side calls during condition eval do not block writers.
func (s *policyStore) all() iter.Seq[*compiled.Policy] {
	s.mu.RLock()
	snap := make([]*compiled.Policy, 0, len(s.deny)+len(s.permit))
	snap = append(snap, s.deny...)
	snap = append(snap, s.permit...)
	s.mu.RUnlock()
	return func(yield func(*compiled.Policy) bool) {
		for _, p := range snap {
			if !yield(p) {
				return
			}
		}
	}
}
