package messages

import (
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// RequestProvider is the cel-go types.Provider used for the env in which
// meta request and output expressions are compiled. It exposes only one
// type — the input view of the meta being compiled — so that policies
// cannot accidentally depend on full-view types from inside a meta
// definition.
//
// The embedded Provider handles every other type lookup, including
// primitives and the general request/response protos.
type RequestProvider struct {
	types.Provider

	t *Type
}

// Compile-time interface assertion.
var _ types.Provider = (*RequestProvider)(nil)

// NewRequestProvider returns a provider that exposes the input view of t
// in addition to whatever base resolves.
func NewRequestProvider(base types.Provider, t *Type) *RequestProvider {
	return &RequestProvider{Provider: base, t: t}
}

// FindStructType reports the input view's type token.
func (p *RequestProvider) FindStructType(name string) (*types.Type, bool) {
	if name == p.t.InputViewName() {
		return types.NewTypeTypeWithParam(types.NewObjectType(name)), true
	}
	return p.Provider.FindStructType(name)
}

// FindStructFieldType resolves an input-field name on the input view.
func (p *RequestProvider) FindStructFieldType(structType, field string) (*types.FieldType, bool) {
	if structType == p.t.InputViewName() {
		if p.t.HasInputField(field) {
			return dynFieldType, true
		}
		return nil, false
	}
	return p.Provider.FindStructFieldType(structType, field)
}

// FindStructFieldNames lists input-field names of the input view.
func (p *RequestProvider) FindStructFieldNames(structType string) ([]string, bool) {
	if structType == p.t.InputViewName() {
		return append([]string(nil), p.t.InputFields...), true
	}
	return p.Provider.FindStructFieldNames(structType)
}

// NewValue is unsupported on the input view: the runtime hands the
// `input` variable in already-bound, users never construct one.
func (p *RequestProvider) NewValue(structType string, fields map[string]ref.Val) ref.Val {
	if structType == p.t.InputViewName() {
		return types.NewErr("messages.RequestProvider: cannot construct input view %q at runtime", structType)
	}
	return p.Provider.NewValue(structType, fields)
}

// FullProvider exposes every Type in a Registry under both views: the
// full view (constructible) and the input view (used as the type of the
// `input` variable inside meta expressions). Used in the bind, output, and
// policy envs.
type FullProvider struct {
	types.Provider

	registry *Registry
}

// Compile-time interface assertion.
var _ types.Provider = (*FullProvider)(nil)

// NewFullProvider returns a provider that exposes every meta in the
// registry under both views. base handles primitives, request/response
// protos, etc.
func NewFullProvider(base types.Provider, r *Registry) *FullProvider {
	return &FullProvider{Provider: base, registry: r}
}

// FindStructType resolves the full view, the input view, or falls through.
func (p *FullProvider) FindStructType(name string) (*types.Type, bool) {
	if _, _, ok := p.lookup(name); ok {
		return types.NewTypeTypeWithParam(types.NewObjectType(name)), true
	}
	return p.Provider.FindStructType(name)
}

// FindStructFieldType resolves a field on either view.
func (p *FullProvider) FindStructFieldType(structType, field string) (*types.FieldType, bool) {
	t, view, ok := p.lookup(structType)
	if !ok {
		return p.Provider.FindStructFieldType(structType, field)
	}
	if view == inputView {
		if t.HasInputField(field) {
			return dynFieldType, true
		}
		return nil, false
	}
	if t.HasInputField(field) || t.HasOutputField(field) {
		return dynFieldType, true
	}
	return nil, false
}

// FindStructFieldNames lists the field names on either view.
func (p *FullProvider) FindStructFieldNames(structType string) ([]string, bool) {
	t, view, ok := p.lookup(structType)
	if !ok {
		return p.Provider.FindStructFieldNames(structType)
	}
	if view == inputView {
		return append([]string(nil), t.InputFields...), true
	}
	out := make([]string, 0, len(t.InputFields)+len(t.OutputFields))
	out = append(out, t.InputFields...)
	out = append(out, t.OutputFields...)
	return out, true
}

// NewValue constructs a full-view Value from a `Type{...}` literal. The
// fields map is taken as the *input* fields; output fields are filled in
// later by the runtime-installed completer on first access. Constructing
// an input view at runtime is not allowed.
//
// Output-field names are rejected on purpose: `Type{...}` is the
// constructor for the input view, and accepting an output literal would
// let a hostile or buggy YAML author bypass the completer entirely
// (e.g. `google.drive.file{id:"x", name:"shadow"}.name == "shadow"`
// returning true without ever calling Drive). Tests that need to
// pre-populate output fields should build the Value directly via
// `Registry.NewFullValue` + `SetField`; policies should never need to.
func (p *FullProvider) NewValue(structType string, fields map[string]ref.Val) ref.Val {
	t, view, ok := p.lookup(structType)
	if !ok {
		return p.Provider.NewValue(structType, fields)
	}
	if view == inputView {
		return types.NewErr("messages.FullProvider: cannot construct input view %q at runtime", structType)
	}
	for name := range fields {
		if !t.HasInputField(name) {
			if t.HasOutputField(name) {
				return types.NewErr("messages.FullProvider: %s: %q is an output field; only input fields may appear in Type{...} literals", t.FullName, name)
			}
			return types.NewErr("messages.FullProvider: %s has no field %q", t.FullName, name)
		}
	}
	v, err := p.registry.NewFullValue(t.FullName, fields)
	if err != nil {
		return types.NewErr("%s", err.Error())
	}
	return v
}

// lookup resolves a type name to (Type, view) for either the full or
// input view. Returns (nil, _, false) if not in the registry.
func (p *FullProvider) lookup(name string) (*Type, view, bool) {
	if t, ok := p.registry.Get(name); ok {
		return t, fullView, true
	}
	if base, ok := strings.CutSuffix(name, InputViewSuffix); ok && base != "" {
		if t, ok := p.registry.Get(base); ok {
			return t, inputView, true
		}
	}
	return nil, fullView, false
}

// dynFieldType is the FieldType used for every meta field. We don't
// care about anything but the Type field for typecheck purposes — meta
// fields are dyn — and cel-go reads but never mutates this, so a single
// shared instance is safe.
var dynFieldType = &types.FieldType{Type: types.DynType}
