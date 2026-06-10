// Package compiled wraps cel.Programs in a uniform "compiled artifact"
// presentation: each Compiled* type holds one program and exposes one
// typed Eval method that takes the variables it needs and returns a
// strongly-typed result.
//
// Activations and ref.Val unwrapping are hidden behind Eval; callers
// only see Go-native types (messages.Value, *pb.Request, etc).
package compiled

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
)

// metaRequestTypeName is the cel-go type name reported by the HTTP
// helper functions (get/post/...). Used to typecheck a request
// expression's output before we accept it.
const metaRequestTypeName = "bouncer.MetaRequest"

// CompiledRequest is a meta's `request:` expression compiled and ready
// to evaluate. It produces the MetaRequest that the upstream HTTP layer
// will issue on the meta's behalf.
type CompiledRequest struct {
	program cel.Program
}

// NewRequest compiles the source against env. The expression must
// return bouncer.MetaRequest (the type the HTTP helpers produce).
func NewRequest(env *cel.Env, source string) (*CompiledRequest, error) {
	prg, _, err := compileChecked(env, source, cel.ObjectType(metaRequestTypeName))
	if err != nil {
		return nil, fmt.Errorf("compile request: %w", err)
	}
	return &CompiledRequest{program: prg}, nil
}

// Eval runs the request expression with the given input value and
// extracts the resulting MetaRequest.
func (c *CompiledRequest) Eval(input *messages.Value) (*pb.MetaRequest, error) {
	out, _, err := c.program.Eval(map[string]any{"input": input})
	if err != nil {
		return nil, fmt.Errorf("eval request: %w", err)
	}
	if e, ok := out.(*types.Err); ok {
		return nil, fmt.Errorf("eval request: %s", e.String())
	}
	mr, ok := out.Value().(*pb.MetaRequest)
	if !ok {
		return nil, fmt.Errorf("request expression returned %T, want *pb.MetaRequest", out.Value())
	}
	return mr, nil
}

// CompiledOutput is a single output-field expression on a meta. The
// value returned is whatever the expression evaluates to: a primitive,
// a *messages.Value (for `Type{...}` literals — the recursion case), or
// any other ref.Val.
type CompiledOutput struct {
	program         cel.Program
	usesRequestBody bool
}

// UsesRequestBody reports whether the output expression can observe
// the inbound request's body.
func (c *CompiledOutput) UsesRequestBody() bool { return c.usesRequestBody }

// NewOutput compiles source against env. Output expressions are not
// type-checked: an output field can be a primitive, a `Type{...}`
// literal (for the recursion case), an optional, or anything else the
// expression evaluates to. The caller stores the resulting ref.Val on
// the parent Value without further validation.
func NewOutput(env *cel.Env, source string) (*CompiledOutput, error) {
	ast, iss := env.Compile(source)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile output: %w", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("compile output: %w", err)
	}
	return &CompiledOutput{program: prg, usesRequestBody: astUsesRequestBody(ast)}, nil
}

// Eval runs the output expression with the meta's input plus the
// upstream request and response. The returned ref.Val is suitable for
// SetField on a *messages.Value.
func (c *CompiledOutput) Eval(input *messages.Value, req *pb.Request, resp *pb.Response) (ref.Val, error) {
	out, _, err := c.program.Eval(map[string]any{
		"input":    input,
		"request":  req,
		"response": resp,
	})
	if err != nil {
		return nil, fmt.Errorf("eval output: %w", err)
	}
	if e, ok := out.(*types.Err); ok {
		return nil, fmt.Errorf("eval output: %s", e.String())
	}
	return out, nil
}

// CompiledFilter is an action's filter predicate.
type CompiledFilter struct {
	program         cel.Program
	usesRequestBody bool
}

// UsesRequestBody reports whether the filter can observe the inbound
// request's body.
func (c *CompiledFilter) UsesRequestBody() bool { return c.usesRequestBody }

// NewFilter compiles a bool-returning filter expression.
func NewFilter(env *cel.Env, source string) (*CompiledFilter, error) {
	prg, ast, err := compileChecked(env, source, cel.BoolType)
	if err != nil {
		return nil, fmt.Errorf("compile filter: %w", err)
	}
	return &CompiledFilter{program: prg, usesRequestBody: astUsesRequestBody(ast)}, nil
}

// Eval runs the filter against the request and the path-template
// captures, returning the bool result. `match` may be nil; an empty
// map is materialized so the CEL activation always has the variable.
func (c *CompiledFilter) Eval(req *pb.Request, match map[string]string) (bool, error) {
	if match == nil {
		match = map[string]string{}
	}
	out, _, err := c.program.Eval(map[string]any{
		"request": req,
		"match":   match,
	})
	if err != nil {
		return false, fmt.Errorf("eval filter: %w", err)
	}
	if e, ok := out.(*types.Err); ok {
		return false, fmt.Errorf("eval filter: %s", e.String())
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("filter returned %T, want bool", out)
	}
	return bool(b), nil
}

// CompiledActionPredicate is a policy's `action:` expression compiled
// against actionPredicateEnv. It returns bool, and decides — once per
// (policy, matched action) pair — whether the policy applies to a
// given action of an inbound request.
//
// An empty source compiles to a predicate that returns true for every
// action: the YAML-level shorthand for "this policy applies to any
// action this API matches."
type CompiledActionPredicate struct {
	program         cel.Program
	usesRequestBody bool
}

// UsesRequestBody reports whether the predicate can observe the
// inbound request's body.
func (c *CompiledActionPredicate) UsesRequestBody() bool { return c.usesRequestBody }

// NewActionPredicate compiles source against env. Source must evaluate
// to bool. The empty source is interpreted as the constant `true` —
// see CompiledActionPredicate's doc for rationale.
func NewActionPredicate(env *cel.Env, source string) (*CompiledActionPredicate, error) {
	if source == "" {
		source = "true"
	}
	prg, ast, err := compileChecked(env, source, cel.BoolType)
	if err != nil {
		return nil, fmt.Errorf("compile action predicate: %w", err)
	}
	return &CompiledActionPredicate{program: prg, usesRequestBody: astUsesRequestBody(ast)}, nil
}

// Eval runs the predicate against the named action, request, the
// path-template captures the action produced, and the calling
// principal. `action` is exposed as a map<string, dyn> so future
// fields (mutating, read_only, scope, ...) slot in without an env
// churn. `match` may be nil; an empty map is materialised so the
// activation always has the variable. `principal` must be non-nil:
// the runtime asserts it at the outer entry point, and we double-
// check here so a stray test caller surfaces a clear error.
func (c *CompiledActionPredicate) Eval(actionName string, req *pb.Request, match map[string]string, principal *pb.Principal, now time.Time) (bool, error) {
	if principal == nil {
		return false, fmt.Errorf("eval action predicate: principal is required")
	}
	if match == nil {
		match = map[string]string{}
	}
	out, _, err := c.program.Eval(map[string]any{
		"action":    map[string]any{"name": actionName},
		"request":   req,
		"match":     match,
		"principal": principal,
		"now":       now,
	})
	if err != nil {
		return false, fmt.Errorf("eval action predicate: %w", err)
	}
	if e, ok := out.(*types.Err); ok {
		return false, fmt.Errorf("eval action predicate: %s", e.String())
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("action predicate returned %T, want bool", out)
	}
	return bool(b), nil
}

// CompiledPrincipalPredicate is a policy's `principal:` expression
// compiled against principalPredicateEnv. It returns bool, and decides
// — once per (policy, request) pair — whether the policy applies to
// the calling principal. The runtime evaluates it before the (heavier)
// per-action loop so a policy that only applies to specific callers
// short-circuits cheaply.
//
// An empty source compiles to a predicate that returns true for every
// principal: the YAML-level shorthand for "this policy applies to any
// caller". Same convention as CompiledActionPredicate so authors don't
// have to remember which fields default which way.
type CompiledPrincipalPredicate struct {
	program         cel.Program
	usesRequestBody bool
}

// UsesRequestBody reports whether the predicate can observe the
// inbound request's body.
func (c *CompiledPrincipalPredicate) UsesRequestBody() bool { return c.usesRequestBody }

// NewPrincipalPredicate compiles source against env. Source must
// evaluate to bool. The empty source is interpreted as the constant
// `true` — see CompiledPrincipalPredicate's doc for rationale.
func NewPrincipalPredicate(env *cel.Env, source string) (*CompiledPrincipalPredicate, error) {
	if source == "" {
		source = "true"
	}
	prg, ast, err := compileChecked(env, source, cel.BoolType)
	if err != nil {
		return nil, fmt.Errorf("compile principal predicate: %w", err)
	}
	return &CompiledPrincipalPredicate{program: prg, usesRequestBody: astUsesRequestBody(ast)}, nil
}

// Eval runs the predicate against the request and the principal. The
// principal must be non-nil — the runtime asserts this at its outer
// entry points (Runtime.Evaluate / APIRuntime.Evaluate) so a Principal
// is always available here, but we also guard so a misuse from a unit
// test surfaces with a clear error rather than a CEL nil-deref.
func (c *CompiledPrincipalPredicate) Eval(req *pb.Request, principal *pb.Principal, now time.Time) (bool, error) {
	if principal == nil {
		return false, fmt.Errorf("eval principal predicate: principal is required")
	}
	out, _, err := c.program.Eval(map[string]any{
		"request":   req,
		"principal": principal,
		"now":       now,
	})
	if err != nil {
		return false, fmt.Errorf("eval principal predicate: %w", err)
	}
	if e, ok := out.(*types.Err); ok {
		return false, fmt.Errorf("eval principal predicate: %s", e.String())
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("principal predicate returned %T, want bool", out)
	}
	return bool(b), nil
}

// CompiledBind is an action's bind expression. It evaluates to the
// initial messages.Value that the policy will close over (typically a
// `Type{...}` literal).
type CompiledBind struct {
	program         cel.Program
	outputType      *cel.Type
	usesRequestBody bool
}

// UsesRequestBody reports whether the bind expression can observe the
// inbound request's body.
func (c *CompiledBind) UsesRequestBody() bool { return c.usesRequestBody }

// NewBind compiles a bind expression. The result must be a
// *messages.Value at runtime; this is checked at Eval time rather than
// compile time so cross-API forms can flow through dyn types.
func NewBind(env *cel.Env, source string) (*CompiledBind, error) {
	ast, iss := env.Compile(source)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile bind: %w", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("compile bind: %w", err)
	}
	return &CompiledBind{program: prg, outputType: ast.OutputType(), usesRequestBody: astUsesRequestBody(ast)}, nil
}

// OutputType returns the static type the bind's expression evaluates
// to. The runtime uses this to associate the bind with the meta type
// it produces (e.g. `gmail.message` -> registry lookup).
func (c *CompiledBind) OutputType() *cel.Type { return c.outputType }

// Eval runs the bind expression with the request and the
// path-template captures, recovering the produced messages.Value.
// `match` may be nil; an empty map is materialized so the CEL
// activation always has the variable.
func (c *CompiledBind) Eval(req *pb.Request, match map[string]string) (*messages.Value, error) {
	if match == nil {
		match = map[string]string{}
	}
	out, _, err := c.program.Eval(map[string]any{
		"request": req,
		"match":   match,
	})
	if err != nil {
		return nil, fmt.Errorf("eval bind: %w", err)
	}
	if e, ok := out.(*types.Err); ok {
		return nil, fmt.Errorf("eval bind: %s", e.String())
	}
	v, ok := out.(*messages.Value)
	if !ok {
		return nil, fmt.Errorf("bind expression returned %T, want *messages.Value", out)
	}
	return v, nil
}

// CompiledCondition is a policy's condition expression compiled and
// ready to evaluate. Returns bool.
//
// One (env, program) is built at NewCondition and reused across every
// Eval. Concurrent-safety for the inline-Type case comes from the
// activation: each Eval threads its own completer installer through
// the activation under installerActivationKey, where
// installCompleterDecorator picks it up — no per-call rebuild and no
// shared mutable state.
type CompiledCondition struct {
	program         cel.Program
	usesRequestBody bool
}

// UsesRequestBody reports whether the condition can observe the
// inbound request's body.
func (c *CompiledCondition) UsesRequestBody() bool { return c.usesRequestBody }

// NewCondition compiles a bool-returning policy condition against env.
// A custom decorator is wired in so that, at Eval time, any
// `Type{...}` literal the condition constructs has the per-Eval
// installer (passed via activation) applied to the resulting Value.
func NewCondition(env *cel.Env, source string) (*CompiledCondition, error) {
	ast, err := checkAst(env, source, cel.BoolType)
	if err != nil {
		return nil, fmt.Errorf("compile condition: %w", err)
	}
	prg, err := env.Program(ast, cel.CustomDecorator(installCompleterDecorator))
	if err != nil {
		return nil, fmt.Errorf("compile condition: %w", err)
	}
	return &CompiledCondition{program: prg, usesRequestBody: astUsesRequestBody(ast)}, nil
}

// Eval runs the condition with the request and the action's bind
// values. Each entry in binds is exposed as the variable of the same
// name. The onNewValue callback (if non-nil) is invoked synchronously
// for every *messages.Value the condition constructs via a `Type{...}`
// literal — the runtime uses this hook to install completers so
// output-field access on those Values triggers the upstream fetch.
//
// onNewValue is threaded through the activation (under
// installerActivationKey) rather than baked into the program. That
// keeps the program/env reusable across goroutines: no two concurrent
// Evals see each other's installer, but they share the expensive
// cel.NewEnv / env.Program(ast) work that used to run per-call.
//
// See condition_bench_test.go for the cost numbers; the shared-program
// path is roughly 500× cheaper than the per-Eval env+program rebuild
// it replaces.
func (c *CompiledCondition) Eval(actionName string, req *pb.Request, principal *pb.Principal, now time.Time, binds map[string]any, onNewValue func(*messages.Value)) (bool, error) {
	if principal == nil {
		return false, fmt.Errorf("eval condition: principal is required")
	}
	activation := make(map[string]any, len(binds)+5)
	activation["request"] = req
	activation["action"] = map[string]any{"name": actionName}
	activation["principal"] = principal
	activation["now"] = now
	for name, v := range binds {
		activation[name] = v
	}
	if onNewValue != nil {
		activation[installerActivationKey] = onNewValue
	}
	out, _, err := c.program.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("eval condition: %w", err)
	}
	if e, ok := out.(*types.Err); ok {
		return false, fmt.Errorf("eval condition: %s", e.String())
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("condition returned %T, want bool", out)
	}
	return bool(b), nil
}

// --- helpers ---------------------------------------------------------------

// checkAst compiles source against env and asserts the output type
// matches want. Returns the checked AST so the caller can attach
// program options (e.g. cel.CustomDecorator for CompiledCondition)
// before building the program.
func checkAst(env *cel.Env, source string, want *cel.Type) (*cel.Ast, error) {
	ast, iss := env.Compile(source)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	if got := ast.OutputType(); !got.IsEquivalentType(want) {
		return nil, fmt.Errorf("expected %s, got %s", want, got)
	}
	return ast, nil
}

// compileChecked compiles + type-checks source and returns the program
// alongside its AST, so constructors can derive static facts (e.g.
// astUsesRequestBody) without re-parsing.
func compileChecked(env *cel.Env, source string, want *cel.Type) (cel.Program, *cel.Ast, error) {
	ast, err := checkAst(env, source, want)
	if err != nil {
		return nil, nil, err
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, nil, err
	}
	return prg, ast, nil
}
