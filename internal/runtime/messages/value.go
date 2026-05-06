package messages

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// view distinguishes a full-view Value from an input-view Value. The
// distinction matters for two things:
//
//   - The `Type()` cel-go reports (used by typecheck round-trips).
//   - Whether output-field access triggers lazy completion or fails.
type view int

const (
	fullView view = iota
	inputView
)

// Value is a runtime value of one of the meta type views. It implements
// `ref.Val` and `traits.Indexer`, the minimal cel-go surface needed to
// support `value.field` access.
//
// Lifecycle of a full-view Value:
//
//  1. Construction (Registry.NewFullValue or FullProvider.NewValue) —
//     input fields are recorded once and never written again. The
//     output map starts empty.
//  2. Wiring (SetCompleter) — the runtime installs a one-shot closure
//     that captures the per-evaluation context (PhysicalAPI, request,
//     compiled programs).
//  3. Use — the first read of any output field fires the completer.
//     The completer's success/failure is recorded on the embedded
//     completion and is sticky for the rest of the Value's lifetime.
//     Subsequent output reads either return the populated field or
//     surface the sticky error; calling SetCompleter again at this
//     point panics, since the new completer would be silently shadowed
//     by the sticky state.
//
// An input-view Value has no output fields, no completer, and no
// completion machinery; reads of unknown names error.
//
// Concurrency: a single Value is owned by one evaluation and is not
// safe for concurrent use across goroutines. The cel-go env+program
// pair *is* shared across goroutines (an `APIRuntime` is a single
// shared instance), but each Eval call gets a fresh activation and
// therefore fresh Values; the per-eval mutable pieces (the outputs
// map, the embedded `completion.done` flag) are never touched from
// more than one goroutine. The Registry and Type are read-only post
// Build, so concurrent reads of inputs are fine — what is unsafe is
// running two evaluations against the *same* Value.
type Value struct {
	typ     *Type
	view    view
	nameStr string

	// inputs holds input-field values fixed at construction. Reads hit
	// this map first regardless of view. For an input-view Value it is
	// the entire field set.
	inputs map[string]ref.Val

	// outputs holds output-field values populated by the completer.
	// Empty until the first output-field read fires completion. Nil for
	// an input-view Value.
	outputs map[string]ref.Val

	// complete encapsulates the one-shot lazy-completion state. Nil for
	// an input-view Value; non-nil (with a possibly-nil fn) for full
	// view. Splitting this out collapses what used to be three
	// independent fields (completer, completed, completeErr) into one
	// state machine that fires at most once.
	complete *completion
}

// completion is the one-shot lazy-completion state for a full-view
// Value. fn runs at most once; the resulting err is sticky for the rest
// of the Value's lifetime.
type completion struct {
	fn   func() error
	done bool
	err  error
}

// run fires the completer the first time it's called and returns the
// recorded result on every subsequent call. A nil fn is reported as a
// sentinel error so callers can produce a clear "no completer wired"
// message — without that distinction the caller would see a successful
// run that left output fields empty.
func (c *completion) run() error {
	if c.done {
		return c.err
	}
	c.done = true
	if c.fn == nil {
		c.err = errNoCompleter
		return c.err
	}
	c.err = c.fn()
	return c.err
}

// errNoCompleter signals that completion was attempted on a Value whose
// completer was never wired. Surfaced by Get as a typed cel error.
var errNoCompleter = errors.New("no completer wired")

// Compile-time interface assertions.
var (
	_ ref.Val        = (*Value)(nil)
	_ traits.Indexer = (*Value)(nil)
)

// Type returns the cel-go type-token corresponding to this Value's view.
func (v *Value) Type() ref.Type { return types.NewObjectType(v.nameStr) }

// Value returns the receiver as the underlying Go value (so cel-go's
// reflection paths can recover the *Value).
func (v *Value) Value() any { return v }

// MetaType returns the underlying Type metadata.
func (v *Value) MetaType() *Type { return v.typ }

// IsFullView reports whether this Value is a full view (vs input-only).
func (v *Value) IsFullView() bool { return v.view == fullView }

// SetField stores a value on a declared output field. Intended for
// completers populating their parent Value during lazy completion.
//
// Calling SetField on an input-view Value, or with a name that isn't a
// declared output field, is a programmer error and panics — the field
// would otherwise leak into reads via the inputs/outputs lookup chain
// without any check that the meta declared it.
//
// Optional values are unwrapped at the boundary: a present optional is
// stored as its inner value, an absent one as types.NullValue. This
// hides cel-go's `optional_type(dyn)` from policy expressions, which
// can then write `event.summary.contains(...)` even though the YAML
// output expression uses `response.body.?summary`.
func (v *Value) SetField(name string, val ref.Val) {
	if v.view != fullView {
		panic(fmt.Sprintf("messages.Value %s: SetField on input view", v.nameStr))
	}
	if !v.typ.HasOutputField(name) {
		panic(fmt.Sprintf("messages.Value %s: SetField on non-output field %q", v.nameStr, name))
	}
	v.outputs[name] = unwrapOptional(val)
}

// unwrapOptional collapses an Optional to its wrapped value (or null).
// Non-optionals pass through. Applied at SetField time so subsequent
// reads return a primitive ref.Val and field-traversal expressions
// don't have to litter `.orValue(...)` everywhere.
func unwrapOptional(val ref.Val) ref.Val {
	opt, ok := val.(*types.Optional)
	if !ok {
		return val
	}
	if !opt.HasValue() {
		return types.NullValue
	}
	return opt.GetValue()
}

// SetCompleter wires the lazy-completion closure on this full-view
// Value. The runtime calls this once per Value, after construction and
// before any output-field is read, with a closure that captures the
// per-evaluation context (PhysicalAPI, originating request, the meta's
// compiled programs).
//
// On an input-view Value, SetCompleter is a no-op — there are no
// output fields to lazily fetch. On a full-view Value, re-wiring
// before the first read replaces the previous closure; re-wiring
// *after* completion has already fired is a no-op (the cached
// success/failure stays sticky). The no-op-after-fire branch matters
// because a single bind value is shared across every policy that
// matches an action — the deny+permit pair on one action is the
// canonical case — and the second policy must not panic when the
// first policy's condition has already triggered the upstream fetch.
// Re-wiring is still rejected at compile time for the surprising
// "retry after sticky failure" pattern that B8 of the second-pass
// review flagged: nothing observable changes when the second closure
// is dropped, since the cached result wins.
func (v *Value) SetCompleter(c func() error) {
	if v.complete == nil {
		return
	}
	if v.complete.done {
		return
	}
	v.complete.fn = c
}

// InputFields returns a snapshot of the immutable input-field map.
// Used by the runtime when materialising an input view from an
// existing full-view Value (see compiled.Meta.CompleterFor) — it needs
// the raw input map to feed Registry.NewInputValue without
// re-evaluating the bind.
func (v *Value) InputFields() map[string]ref.Val {
	out := make(map[string]ref.Val, len(v.inputs))
	for k, val := range v.inputs {
		out[k] = val
	}
	return out
}

// ConvertToNative is required by ref.Val. Meta values are not natively
// representable, so we report an error rather than guess.
func (v *Value) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("messages.Value: native conversion not supported")
}

// ConvertToType is required by ref.Val. Only identity conversion is
// supported.
func (v *Value) ConvertToType(t ref.Type) ref.Val {
	if t.TypeName() == v.nameStr {
		return v
	}
	if t == types.TypeType {
		return v.Type().(ref.Val)
	}
	return types.NewErr("cannot convert %s to %s", v.nameStr, t.TypeName())
}

// Equal compares by identity-of-type and field equality. Two Values are
// equal iff they share a type name and every set field — across both
// inputs and outputs — compares equal.
func (v *Value) Equal(other ref.Val) ref.Val {
	o, ok := other.(*Value)
	if !ok || o.nameStr != v.nameStr {
		return types.False
	}
	if !mapsEqual(v.inputs, o.inputs) || !mapsEqual(v.outputs, o.outputs) {
		return types.False
	}
	return types.True
}

func mapsEqual(a, b map[string]ref.Val) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if eq, ok := av.Equal(bv).(types.Bool); !ok || !bool(eq) {
			return false
		}
	}
	return true
}

// Get implements traits.Indexer: cel-go calls this on every
// `value.field` access. Inputs are checked first (they're set at
// construction and never lazy); outputs trigger lazy completion on the
// first miss.
func (v *Value) Get(key ref.Val) ref.Val {
	name, ok := key.(types.String)
	if !ok {
		return types.NewErr("messages.Value: expected string field name, got %T", key)
	}
	field := string(name)
	if val, ok := v.inputs[field]; ok {
		return val
	}
	if v.view == inputView {
		return v.missingInputViewField(field)
	}
	return v.getFullViewField(field)
}

// missingInputViewField formats the error returned for a Get on an
// input-view Value when the field isn't present in the inputs map.
func (v *Value) missingInputViewField(field string) ref.Val {
	if v.typ.HasInputField(field) {
		return types.NewErr("messages.Value %s: input field %q not set", v.nameStr, field)
	}
	return types.NewErr("messages.Value %s: no field %q", v.nameStr, field)
}

// getFullViewField handles a `value.field` access on a full-view Value
// when the inputs map didn't already answer it. Output fields trigger
// lazy completion: the first such access fires the completer once;
// subsequent accesses either read the populated field or surface the
// sticky completion error.
//
// Lazy recursion falls out for free — a completer that stores another
// Value as an output only triggers that child's completion when the
// caller walks into it.
func (v *Value) getFullViewField(field string) ref.Val {
	if v.typ.HasOutputField(field) {
		if err := v.complete.run(); err != nil {
			if errors.Is(err, errNoCompleter) {
				// No completer was ever wired. This means the Value
				// was constructed by the full provider but the runtime
				// never wired a completer onto it — typically a
				// `Type{...}` literal whose meta isn't in the global
				// metas map. Surface a clear runtime error rather than
				// a silent zero so the misconfiguration is obvious.
				return types.NewErr("messages.Value %s: output field %q has no completer", v.nameStr, field)
			}
			// WrapErr (vs. NewErr "%s") preserves the underlying error
			// chain so callers can errors.As back to typed errors —
			// the proxy's apiclient.UpstreamError relies on this to
			// classify upstream HTTP failures into client-facing
			// status codes.
			return types.WrapErr(fmt.Errorf("messages.Value %s: complete: %w", v.nameStr, err))
		}
		if val, ok := v.outputs[field]; ok {
			return val
		}
		return types.NewErr("messages.Value %s: completer did not set output field %q", v.nameStr, field)
	}
	if v.typ.HasInputField(field) {
		// Reached when a `Type{...}` literal omitted a declared input
		// field. Construction itself accepts partial input maps so
		// callers can build a value with only the keys their bind
		// expression provides; if the policy then walks into a
		// missing input field we surface a clear error rather than a
		// silent zero value.
		return types.NewErr("messages.Value %s: input field %q not set", v.nameStr, field)
	}
	return types.NewErr("messages.Value %s: no field %q", v.nameStr, field)
}

// String renders a debug representation. Not stable across versions.
func (v *Value) String() string {
	return fmt.Sprintf("messages.Value(%s, inputs=%v, outputs=%v)", v.nameStr, v.inputs, v.outputs)
}
