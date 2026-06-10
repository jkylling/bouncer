package compiled

import (
	"context"
	"fmt"
	"time"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Policy is the compiled form of a `Policy`. It pairs a CEL action
// predicate with the policy's bool condition.
//
// A policy may apply to many actions: at evaluate time the predicate
// runs against each (matched action, request) pair, and the condition
// runs once for each pair the predicate accepts. The condition env
// declares every meta in the registry as a plain variable; bound
// values from the current action's binds are placed in the activation,
// and metas the action doesn't bind are simply absent. A condition
// that reads an absent meta surfaces a CEL no-such-attribute error —
// the contract is that the policy author writes the action predicate
// to gate which actions a given condition is valid for.
type Policy struct {
	API           string
	Name          string
	Result        models.PolicyResult
	principalPred *CompiledPrincipalPredicate
	predicate     *CompiledActionPredicate
	condition     *CompiledCondition

	// source is the YAML-shaped policy this compiled form was built
	// from. Kept so the control plane can list/edit policies without
	// re-reading the on-disk file: the runtime is the source of truth
	// at request time, and the round-trip preserves CEL source text
	// (the compiled programs are not re-renderable into YAML).
	source models.Policy
}

// Source returns a copy of the original models.Policy this compiled
// form was built from. Used by the control plane to list policies in
// their YAML-shaped form.
func (p *Policy) Source() models.Policy { return p.source }

// NewPolicy compiles a policy's action predicate and condition. The
// result field is validated first so a config typo (e.g. `result:
// dney`) fails loudly rather than silently routing the policy to the
// permit slice in policyStore.add.
//
// Both the predicate and the condition are compiled against API-level
// envs (apiName + reg), not against any specific action. The
// `policy.Action` field is interpreted as a CEL bool expression with
// access to `action.name` and `request`; an empty `policy.Action`
// means "applies to every action this API matches" (compiled as the
// constant `true` — see NewActionPredicate).
func NewPolicy(policy *models.Policy, apiName string, reg *messages.Registry) (*Policy, error) {
	if err := policy.Result.Validate(); err != nil {
		return nil, fmt.Errorf("policy %q: %w", policy.Name, err)
	}
	princEnv, err := principalPredicateEnv()
	if err != nil {
		return nil, fmt.Errorf("policy %q: principal env: %w", policy.Name, err)
	}
	princ, err := NewPrincipalPredicate(princEnv, policy.Principal)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", policy.Name, err)
	}
	predEnv, err := actionPredicateEnv()
	if err != nil {
		return nil, fmt.Errorf("policy %q: action env: %w", policy.Name, err)
	}
	pred, err := NewActionPredicate(predEnv, policy.Action)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", policy.Name, err)
	}
	condEnv, err := policyEnv(apiName, reg)
	if err != nil {
		return nil, fmt.Errorf("policy %q: condition env: %w", policy.Name, err)
	}
	cc, err := NewCondition(condEnv, policy.Condition)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", policy.Name, err)
	}
	return &Policy{
		API:           policy.API,
		Name:          policy.Name,
		Result:        policy.Result,
		principalPred: princ,
		predicate:     pred,
		condition:     cc,
		source:        *policy,
	}, nil
}

// AppliesToPrincipal reports whether the policy's principal predicate
// accepts the calling principal for the given request. The runtime
// calls this once per (policy, request) pair, before any per-action
// loop, so a policy that only applies to specific callers
// short-circuits cheaply. An empty `principal:` source compiles to
// the constant `true`, so a policy that doesn't gate by principal
// matches every caller without a per-call cost beyond the bool
// program eval.
func (p *Policy) AppliesToPrincipal(req *pb.Request, principal *pb.Principal, now time.Time) (bool, error) {
	ok, err := p.principalPred.Eval(req, principal, now)
	if err != nil {
		return false, fmt.Errorf("policy %q: %w", p.Name, err)
	}
	return ok, nil
}

// AppliesTo reports whether the policy's action predicate accepts the
// matched action for the given request. The runtime calls this once
// per (policy, matched action) pair, before the heavier condition.
//
// `match` is the path-template captures the action produced; the
// predicate sees it as `match: map<string, string>`, so a policy can
// gate by URL parts (`match.user_id == 'me'`) without paying for the
// upstream side calls a condition would trigger.
func (p *Policy) AppliesTo(actionName string, req *pb.Request, match map[string]string, principal *pb.Principal, now time.Time) (bool, error) {
	ok, err := p.predicate.Eval(actionName, req, match, principal, now)
	if err != nil {
		return false, fmt.Errorf("policy %q: %w", p.Name, err)
	}
	return ok, nil
}

// Evaluate installs an upstream-aware completer on each bind value
// then runs the policy condition. Bind Values are produced once per
// request (matchActions) and shared across every policy that
// evaluates the same matched action, so a completed upstream fetch is
// memoised on the Value — the deny+permit pair on one action pays for
// each meta side call once. Fresh state comes from the per-request
// rebuild, not from this function: SetCompleter is a deliberate no-op
// once a fetch has completed (see messages.Value), so installing a
// completer here never resets another policy's already-resolved view.
//
// `resolve` maps API name → PhysicalAPI. Each Meta records its own
// API; the completer asks the resolver for that API so cross-API binds
// and inline `Type{...}` literals on a different API hit the *correct*
// upstream regardless of which API routed the inbound request.
//
// In addition, an onNewValue hook is wired into the policy's type
// provider for the duration of the evaluation so that Values
// constructed inline by the policy expression (e.g. `google.drive.file{
// id: ...}`) also receive a completer and can resolve their output
// fields lazily.
//
// The activation only contains the metas this action binds. Reading an
// unbound meta in the condition surfaces a CEL no-such-attribute error
// — the contract is that the policy's action predicate gates which
// actions any given condition is valid for.
func (p *Policy) Evaluate(ctx context.Context, resolve PhysicalAPIResolver, actionName string, req *pb.Request, principal *pb.Principal, now time.Time, binds []BoundValue, reg *messages.Registry, metas map[string]*Meta) (bool, error) {
	bindMap := make(map[string]any, len(binds))
	for _, bv := range binds {
		meta, ok := metas[bv.Name]
		if !ok {
			return false, fmt.Errorf("policy %q: bind %q references unknown meta", p.Name, bv.Name)
		}
		bv.Value.SetCompleter(meta.CompleterFor(ctx, bv.Value, reg, metas, resolve, req))
		bindMap[bv.Name] = bv.Value
	}
	installer := func(v *messages.Value) {
		if !v.IsFullView() {
			return
		}
		m, ok := metas[v.MetaType().FullName]
		if !ok {
			return
		}
		v.SetCompleter(m.CompleterFor(ctx, v, reg, metas, resolve, req))
	}
	got, err := p.condition.Eval(actionName, req, principal, now, bindMap, installer)
	if err != nil {
		return false, fmt.Errorf("policy %q: %w", p.Name, err)
	}
	return got, nil
}
