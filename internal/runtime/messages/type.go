// Package messages defines the dynamic message types that policies and
// metas operate on, plus two cel-go type-provider views over a registry of
// such types. It replaces the dynamicpb-based machinery in internal/celenv.
//
// A meta has two "views":
//
//   - The full view  (FullName, e.g. "google.mail.message") combines input
//     and output fields. Constructible from CEL via the dotted-name literal
//     syntax: `mail.message{id: 1}`. Output fields are populated lazily on
//     first access via the Type's Complete hook.
//
//   - The input view (FullName + ".__input__") exposes only input fields.
//     Used as the type of the `input` variable inside meta request/output
//     expressions. Never typed by user code, never has output fields.
//
// All field values are dyn-typed: cel-go's checker can't statically verify
// the shape of meta payloads, so we lean on runtime errors when a field is
// missing.
package messages

import "github.com/google/cel-go/common/types/ref"

// InputViewSuffix is appended to a Type's FullName to obtain the type name
// of its input-only view.
const InputViewSuffix = ".__input__"

// Type describes a single meta. One Type instance is shared by all Values
// of that meta across both views (full and input).
type Type struct {
	// FullName is the fully-scoped name of the meta, e.g.
	// "google.mail.message". The input view's type name is FullName + ".__input__".
	FullName string

	// InputFields lists the names of input fields. Order is significant
	// only for the output of FindStructFieldNames.
	InputFields []string

	// OutputFields lists the names of output fields. Output fields exist
	// only on the full view; the input view has none.
	OutputFields []string
}

// InputViewName returns the type name of this Type's input-only view.
func (t *Type) InputViewName() string { return t.FullName + InputViewSuffix }

// HasInputField reports whether the given field name is declared as an
// input field.
func (t *Type) HasInputField(name string) bool {
	for _, f := range t.InputFields {
		if f == name {
			return true
		}
	}
	return false
}

// HasOutputField reports whether the given field name is declared as an
// output field.
func (t *Type) HasOutputField(name string) bool {
	for _, f := range t.OutputFields {
		if f == name {
			return true
		}
	}
	return false
}

// Registry is the set of meta Types known to the runtime. It is the source
// of truth for both Provider views.
type Registry struct {
	types map[string]*Type
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{types: map[string]*Type{}}
}

// Register adds a Type to the registry. The Type's FullName must be
// non-empty and unique within the registry.
func (r *Registry) Register(t *Type) error {
	if t == nil {
		return errNilType
	}
	if t.FullName == "" {
		return errEmptyFullName
	}
	if _, exists := r.types[t.FullName]; exists {
		return &duplicateTypeError{name: t.FullName}
	}
	r.types[t.FullName] = t
	return nil
}

// Get returns the Type with the given full name, or (nil, false) if absent.
func (r *Registry) Get(fullName string) (*Type, bool) {
	t, ok := r.types[fullName]
	return t, ok
}

// All returns every registered Type, in unspecified order.
func (r *Registry) All() []*Type {
	out := make([]*Type, 0, len(r.types))
	for _, t := range r.types {
		out = append(out, t)
	}
	return out
}

// NewInputValue constructs an input-view Value for the named meta with the
// given input fields. Used to bind the `input` variable inside meta
// request and output expressions.
func (r *Registry) NewInputValue(fullName string, fields map[string]ref.Val) (*Value, error) {
	t, ok := r.types[fullName]
	if !ok {
		return nil, &unknownTypeError{name: fullName}
	}
	return &Value{
		typ:     t,
		view:    inputView,
		inputs:  copyFields(fields),
		nameStr: t.InputViewName(),
	}, nil
}

// NewFullValue constructs a full-view Value for the named meta,
// populating the input fields from the given map. Output fields start
// empty; the runtime wires a completer via Value.SetCompleter and the
// first output-field read fires it.
func (r *Registry) NewFullValue(fullName string, inputFields map[string]ref.Val) (*Value, error) {
	t, ok := r.types[fullName]
	if !ok {
		return nil, &unknownTypeError{name: fullName}
	}
	return &Value{
		typ:      t,
		view:     fullView,
		inputs:   copyFields(inputFields),
		outputs:  map[string]ref.Val{},
		complete: &completion{},
		nameStr:  t.FullName,
	}, nil
}

func copyFields(in map[string]ref.Val) map[string]ref.Val {
	out := make(map[string]ref.Val, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
