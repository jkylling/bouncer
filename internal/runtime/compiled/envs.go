package compiled

import (
	"github.com/google/cel-go/cel"

	"github.com/jkylling/bouncer/internal/runtime/celenv"
	"github.com/jkylling/bouncer/internal/runtime/messages"
)

// requestEnv returns the cel.Env used to compile a meta's request
// expression.
//
//   - input: typed as the meta's input view (`<meta>.__input__`).
//   - Provider: RequestProvider — exposes only the input view of this
//     meta. Cross-meta or cross-API references are blocked at compile
//     time.
//   - Container: apiName, so identifiers resolve via cel-go's ancestor
//     search (e.g. `Request{...}` finds the proto's full name).
//   - HTTPHelpers: get/post/... verbs are available here only.
func requestEnv(apiName string, meta *messages.Type) (*cel.Env, error) {
	base := celenv.NewProtoRegistry()
	provider := messages.NewRequestProvider(base, meta)
	opts := append(celenv.LanguageOptions(),
		celenv.HTTPHelpers(),
		cel.CustomTypeAdapter(base),
		cel.CustomTypeProvider(provider),
		cel.Container(apiName),
		cel.Variable("input", cel.ObjectType(meta.InputViewName())),
	)
	return cel.NewEnv(opts...)
}

// outputEnv returns the cel.Env used to compile a meta's output-field
// expressions. Output expressions can reference the meta's input as
// well as the upstream request/response, and may construct any meta in
// the registry via `Type{...}` literals (the recursion mechanism).
//
//   - input: meta's input view.
//   - request: the originating Request.
//   - response: the response returned by the upstream HTTP call.
//   - Provider: FullProvider — every meta in the registry, both views.
//   - Container: apiName.
func outputEnv(apiName string, meta *messages.Type, reg *messages.Registry) (*cel.Env, error) {
	base := celenv.NewProtoRegistry()
	provider := messages.NewFullProvider(base, reg)
	opts := append(celenv.LanguageOptions(),
		cel.CustomTypeAdapter(base),
		cel.CustomTypeProvider(provider),
		cel.Container(apiName),
		cel.Variable("input", cel.ObjectType(meta.InputViewName())),
		cel.Variable("request", cel.ObjectType("bouncer.Request")),
		cel.Variable("response", cel.ObjectType("bouncer.Response")),
	)
	return cel.NewEnv(opts...)
}

// filterEnv returns the cel.Env used to compile an action's filter
// expression. Filtering happens before any meta is fetched, so the env
// is deliberately bare: only the request and the path-template captures
// (`match`) are in scope, and no meta types are exposed.
func filterEnv() (*cel.Env, error) {
	base := celenv.NewProtoRegistry()
	opts := append(celenv.LanguageOptions(),
		cel.CustomTypeAdapter(base),
		cel.CustomTypeProvider(base),
		cel.Variable("request", cel.ObjectType("bouncer.Request")),
		cel.Variable("match", cel.MapType(cel.StringType, cel.StringType)),
	)
	return cel.NewEnv(opts...)
}

// bindEnv returns the cel.Env used to compile an action's bind
// expressions. Each bind is a CEL expression that produces a meta
// Value (typically `Type{...}` or a function call).
//
//   - request: the originating Request.
//   - match: the captures from the action's path template (or empty
//     when the action only uses `filter:`). Typed as map(string, string)
//     so bind expressions can write `match.user_id` (CEL field-selection
//     on string-keyed maps).
//   - Provider: FullProvider — every meta in the registry.
//   - Container: apiName.
func bindEnv(apiName string, reg *messages.Registry) (*cel.Env, error) {
	base := celenv.NewProtoRegistry()
	provider := messages.NewFullProvider(base, reg)
	opts := append(celenv.LanguageOptions(),
		cel.CustomTypeAdapter(base),
		cel.CustomTypeProvider(provider),
		cel.Container(apiName),
		cel.Variable("request", cel.ObjectType("bouncer.Request")),
		cel.Variable("match", cel.MapType(cel.StringType, cel.StringType)),
	)
	return cel.NewEnv(opts...)
}

// policyEnv builds the cel.Env used to evaluate a policy condition.
// Every meta in the registry is exposed as a variable typed as the meta
// itself (not as optional<MetaType>), so conditions read fields with
// the natural `message.labelIds` shape.
//
// # Contract for multi-action policies
//
// At evaluate time the activation contains only the metas the matched
// action binds; reading an unbound meta surfaces a CEL no-such-
// attribute error. A policy spanning actions with disjoint bind sets
// must guard each branch so short-circuit evaluation suppresses the
// unbound-variable error:
//
//	(action.name == "a" && meta_a.x) ||
//	(action.name == "b" && meta_b.y)
//
// TestPolicyMultiActionWithDistinctBinds in internal/runtime pins this.
//
// # Variable vs. type resolution under cel.Container
//
// cel.Container(apiName) enables ancestor search so a leaf `message`
// resolves to the qualified `gmail.message`. We declare the variable
// at the full qualified name so it wins over the same-named type at
// the longest qualified level — TestPolicyEnvLeafResolvesToVariable
// NotType pins this. Declaring under the leaf name instead would
// collide with the type and surface as "type does not support field
// selection" at compile time.
//
// One env+provider is shared across every Eval; the per-call completer
// installer is threaded through the activation
// (installCompleterDecorator), not the provider, so the shared env
// stays goroutine-safe.
func policyEnv(apiName string, reg *messages.Registry) (*cel.Env, error) {
	base := celenv.NewProtoRegistry()
	provider := messages.NewFullProvider(base, reg)
	opts := append(celenv.LanguageOptions(),
		cel.CustomTypeAdapter(base),
		cel.CustomTypeProvider(provider),
		cel.Container(apiName),
		cel.Variable("request", cel.ObjectType("bouncer.Request")),
		cel.Variable("action", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("principal", cel.ObjectType("bouncer.Principal")),
		cel.Variable("now", cel.TimestampType),
	)
	for _, t := range reg.All() {
		opts = append(opts, cel.Variable(t.FullName, cel.ObjectType(t.FullName)))
	}
	return cel.NewEnv(opts...)
}

// actionPredicateEnv is the cel.Env used to compile a policy's `action`
// expression — a bool predicate that decides which of an API's actions
// the policy applies to. The env is deliberately bare:
//
//   - action: map<string, dyn> — currently `{name: <action name>}`.
//     Future fields (mutating, read_only, scope, ...) slot in as extra
//     keys without a schema change.
//   - request: the originating Request, so per-request gating is
//     possible without falling back to the condition.
//   - match: map<string, string> — the path-template captures the
//     matched action produced. Lets a predicate gate by URL parts
//     (`match.user_id == 'me'`) without paying for the upstream side
//     calls a condition would trigger.
//
// Bare CEL primitives only: no meta types, no http helpers. The
// predicate runs once per (policy, matched action) pair, before the
// (heavier) condition.
func actionPredicateEnv() (*cel.Env, error) {
	base := celenv.NewProtoRegistry()
	opts := append(celenv.LanguageOptions(),
		cel.CustomTypeAdapter(base),
		cel.CustomTypeProvider(base),
		cel.Variable("action", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.ObjectType("bouncer.Request")),
		cel.Variable("match", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("principal", cel.ObjectType("bouncer.Principal")),
		cel.Variable("now", cel.TimestampType),
	)
	return cel.NewEnv(opts...)
}

// principalPredicateEnv is the cel.Env used to compile a policy's
// `principal:` expression — a bool predicate that decides whether the
// policy applies to the calling principal at all. It runs once per
// policy per request, before any action-level evaluation, so the env
// is deliberately the cheapest of the predicate envs:
//
//   - principal: the caller identity (top-level, not nested under
//     `request`).
//   - request: the originating Request, so a predicate may also gate by
//     request shape if it wants to short-circuit the action loop
//     entirely.
//
// Bare CEL primitives only: no meta types, no `action`, no `match` (the
// matched-action set is not yet known at this point in evaluation).
func principalPredicateEnv() (*cel.Env, error) {
	base := celenv.NewProtoRegistry()
	opts := append(celenv.LanguageOptions(),
		cel.CustomTypeAdapter(base),
		cel.CustomTypeProvider(base),
		cel.Variable("request", cel.ObjectType("bouncer.Request")),
		cel.Variable("principal", cel.ObjectType("bouncer.Principal")),
		cel.Variable("now", cel.TimestampType),
	)
	return cel.NewEnv(opts...)
}
