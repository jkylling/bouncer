package compiled

import (
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"

	"github.com/jkylling/bouncer/internal/runtime/messages"
)

// installerActivationKey is the activation variable name under which
// CompiledCondition.Eval threads the per-call completer installer to
// the decorator-wrapped struct constructors. The leading underscores
// (illegal in CEL identifiers) keep it from colliding with any user
// variable. See compiled.go for the broader rationale.
const installerActivationKey = "__messages_completer_installer__"

// installerFromActivation pulls the per-Eval installer out of act, if
// one was set. Returns nil for the (legitimate) compile-time
// type-checking pass that ships no activation, and for evaluations that
// don't care about inline `Type{...}` values.
func installerFromActivation(act interpreter.Activation) func(*messages.Value) {
	raw, ok := act.ResolveName(installerActivationKey)
	if !ok || raw == nil {
		return nil
	}
	fn, ok := raw.(func(*messages.Value))
	if !ok {
		return nil
	}
	return fn
}

// installCompleterDecorator is the cel.CustomDecorator that wraps every
// struct-constructor node so that, at Eval time, freshly-built
// *messages.Values get a completer installed by the activation-supplied
// hook. This replaces the per-Eval env+program rebuild that used to
// route the installer through a fresh PolicyProvider closure.
//
// Decorators see the program plan once at env.Program time, so the
// shared (env, program) pair built in NewCondition stays goroutine-safe
// — per-Eval state lives only on the activation each goroutine passes
// in.
func installCompleterDecorator(i interpreter.Interpretable) (interpreter.Interpretable, error) {
	ctor, ok := i.(interpreter.InterpretableConstructor)
	if !ok {
		return i, nil
	}
	return &installingCtor{InterpretableConstructor: ctor}, nil
}

// installingCtor wraps an InterpretableConstructor so that, after the
// underlying Eval produces a value, we run the per-Eval installer (if
// any) when the result is a freshly-built full-view *messages.Value.
//
// We embed the constructor and override only Eval — InitVals(), Type(),
// and ID() pass through unchanged so cel-go optimisers that introspect
// constructor nodes (e.g. constant-folding) keep working.
type installingCtor struct {
	interpreter.InterpretableConstructor
}

func (c *installingCtor) Eval(act interpreter.Activation) ref.Val {
	out := c.InterpretableConstructor.Eval(act)
	v, ok := out.(*messages.Value)
	if !ok {
		return out
	}
	if !v.IsFullView() {
		return out
	}
	if fn := installerFromActivation(act); fn != nil {
		fn(v)
	}
	return out
}
