package messages

import (
	"errors"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRegistry returns a registry pre-populated with two simple types,
// useful for the provider tests below.
func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	require.NoError(t, r.Register(&Type{
		FullName:     "google.mail.message",
		InputFields:  []string{"id"},
		OutputFields: []string{"sender", "subject"},
	}))
	require.NoError(t, r.Register(&Type{
		FullName:     "google.drive.file",
		InputFields:  []string{"id"},
		OutputFields: []string{"name", "parent"},
	}))
	return r
}

// baseProvider is a minimal types.Provider used as the embedded base for
// the test providers. We can't use *types.Registry directly because the
// concrete registry isn't exported; cel.NewEnv supplies one, but we want
// to test the provider in isolation. This stub returns "not found" for
// everything, mirroring the contract that the embedded provider only
// handles unknown types.
type baseProvider struct{}

func (baseProvider) EnumValue(name string) ref.Val             { return types.NewErr("no enum %q", name) }
func (baseProvider) FindIdent(name string) (ref.Val, bool)     { return nil, false }
func (baseProvider) FindStructType(string) (*types.Type, bool) { return nil, false }
func (baseProvider) FindStructFieldNames(string) ([]string, bool) {
	return nil, false
}
func (baseProvider) FindStructFieldType(string, string) (*types.FieldType, bool) {
	return nil, false
}
func (baseProvider) NewValue(name string, _ map[string]ref.Val) ref.Val {
	return types.NewErr("baseProvider: cannot construct %q", name)
}

// --- Registry --------------------------------------------------------------

func TestRegistryRegister(t *testing.T) {
	r := NewRegistry()
	typ := &Type{FullName: "google.mail.message"}
	require.NoError(t, r.Register(typ))

	got, ok := r.Get("google.mail.message")
	require.True(t, ok)
	assert.Same(t, typ, got)
}

func TestRegistryRegisterRejectsDuplicates(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&Type{FullName: "x"}))
	err := r.Register(&Type{FullName: "x"})
	assert.ErrorContains(t, err, `already registered`)
}

func TestRegistryRegisterRejectsEmptyName(t *testing.T) {
	err := NewRegistry().Register(&Type{})
	assert.ErrorIs(t, err, errEmptyFullName)
}

// --- Value as ref.Val ------------------------------------------------------

func TestValueGetReturnsSetField(t *testing.T) {
	r := newTestRegistry(t)
	v, err := r.NewFullValue("google.mail.message", map[string]ref.Val{
		"id": types.Int(7),
	})
	require.NoError(t, err)

	assert.Equal(t, types.Int(7), v.Get(types.String("id")))
}

func TestValueGetUnknownFieldErrors(t *testing.T) {
	r := newTestRegistry(t)
	v, err := r.NewFullValue("google.mail.message", nil)
	require.NoError(t, err)

	res := v.Get(types.String("nope"))
	_, isErr := res.(*types.Err)
	assert.True(t, isErr, "expected types.Err for unknown field, got %T", res)
}

func TestValueInputViewHasNoOutputFields(t *testing.T) {
	r := newTestRegistry(t)
	v, err := r.NewInputValue("google.mail.message", map[string]ref.Val{
		"id": types.Int(1),
	})
	require.NoError(t, err)

	assert.Equal(t, types.Int(1), v.Get(types.String("id")))
	res := v.Get(types.String("sender"))
	_, isErr := res.(*types.Err)
	assert.True(t, isErr, "input view must reject output-field reads, got %T", res)
}

// --- Lazy completion -------------------------------------------------------

func TestValueLazyCompletionRunsOnce(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&Type{
		FullName:     "x",
		InputFields:  []string{"id"},
		OutputFields: []string{"name", "subject"},
	}))

	v, err := r.NewFullValue("x", map[string]ref.Val{"id": types.Int(1)})
	require.NoError(t, err)

	calls := 0
	v.SetCompleter(func() error {
		calls++
		v.SetField("name", types.String("hello"))
		v.SetField("subject", types.String("world"))
		return nil
	})

	assert.Equal(t, types.String("hello"), v.Get(types.String("name")))
	assert.Equal(t, types.String("world"), v.Get(types.String("subject")))
	// Reading the input field doesn't trigger the completer.
	assert.Equal(t, types.Int(1), v.Get(types.String("id")))
	assert.Equal(t, 1, calls, "completer must run exactly once across all field reads")
}

func TestValueLazyCompletionNotTriggeredForInputFields(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&Type{
		FullName:     "x",
		InputFields:  []string{"id"},
		OutputFields: []string{"name"},
	}))

	v, err := r.NewFullValue("x", map[string]ref.Val{"id": types.Int(2)})
	require.NoError(t, err)
	calls := 0
	v.SetCompleter(func() error {
		calls++
		v.SetField("name", types.String("hi"))
		return nil
	})
	_ = v.Get(types.String("id"))
	assert.Equal(t, 0, calls, "input field reads must not trigger completer")
}

func TestValueLazyCompletionPropagatesError(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&Type{
		FullName:     "x",
		OutputFields: []string{"name"},
	}))

	v, err := r.NewFullValue("x", nil)
	require.NoError(t, err)
	v.SetCompleter(func() error { return errors.New("boom") })

	res := v.Get(types.String("name"))
	celErr, ok := res.(*types.Err)
	require.True(t, ok, "expected types.Err, got %T", res)
	assert.Contains(t, celErr.String(), "boom")
}

// TestSetCompleterIsNoOpAfterFire pins the contract that supports the
// shared-bind-value case: a single bind value is reused
// across every policy that matches its action, and once the first
// policy's condition has fired the completer the cached
// success/failure stays sticky. A subsequent SetCompleter from another
// policy is a no-op rather than a panic — the second closure would
// have been silently shadowed by the cached result either way, so
// dropping it has no observable effect and avoids a programmer-error
// crash for what is in fact a normal multi-policy interleave.
func TestSetCompleterIsNoOpAfterFire(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&Type{
		FullName:     "x",
		OutputFields: []string{"name"},
	}))
	v, err := r.NewFullValue("x", nil)
	require.NoError(t, err)
	v.SetCompleter(func() error {
		v.SetField("name", types.String("first"))
		return nil
	})
	_ = v.Get(types.String("name")) // fires the completer

	// Second wiring is silently dropped; the cached field stays.
	v.SetCompleter(func() error {
		v.SetField("name", types.String("second"))
		return nil
	})
	assert.Equal(t, types.String("first"), v.Get(types.String("name")))
}

// TestSetCompleterReplaceableBeforeFire confirms the wiring half of
// the B8 contract: re-wiring is allowed while no output-field has been
// read, so callers that stage a placeholder and then a real completer
// don't have to coordinate.
func TestSetCompleterReplaceableBeforeFire(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&Type{
		FullName:     "x",
		OutputFields: []string{"name"},
	}))
	v, err := r.NewFullValue("x", nil)
	require.NoError(t, err)

	v.SetCompleter(func() error { return errors.New("placeholder") })
	v.SetCompleter(func() error {
		v.SetField("name", types.String("real"))
		return nil
	})
	assert.Equal(t, types.String("real"), v.Get(types.String("name")))
}

// TestSetCompleterIsNoOpOnInputView documents the input-view branch:
// input views never lazily fetch anything, so wiring a completer on
// one is harmless.
func TestSetCompleterIsNoOpOnInputView(t *testing.T) {
	r := newTestRegistry(t)
	v, err := r.NewInputValue("google.mail.message", nil)
	require.NoError(t, err)
	v.SetCompleter(func() error { return errors.New("never runs") })
	// Reading the unset input field still errors as usual; no completer
	// is fired even though one was wired.
	res := v.Get(types.String("id"))
	_, isErr := res.(*types.Err)
	assert.True(t, isErr)
}

// TestValueLazyRecursive is the headline scenario: an output field whose
// value is another Value with its own completer. Walking the chain
// triggers exactly as many completions as steps taken.
func TestValueLazyRecursive(t *testing.T) {
	// Each level builds a child of the previous one until depth 0.
	completes := 0
	typ := &Type{
		FullName:     "n",
		OutputFields: []string{"name", "parent"},
	}
	var childAt func(depth int) *Value
	childAt = func(depth int) *Value {
		v := &Value{
			typ:      typ,
			view:     fullView,
			inputs:   map[string]ref.Val{},
			outputs:  map[string]ref.Val{},
			complete: &completion{},
			nameStr:  "n",
		}
		v.SetCompleter(func() error {
			completes++
			v.SetField("name", types.Int(int64(depth)))
			if depth > 0 {
				v.SetField("parent", childAt(depth-1))
			}
			return nil
		})
		return v
	}

	// Skip Registry — we're stress-testing Value directly.
	root := childAt(5)

	env, err := cel.NewEnv(cel.Variable("a", cel.DynType))
	require.NoError(t, err)
	ast, iss := env.Compile("a.parent.parent.name")
	require.NoError(t, iss.Err())
	prg, err := env.Program(ast)
	require.NoError(t, err)

	out, _, err := prg.Eval(map[string]any{"a": root})
	require.NoError(t, err)
	assert.Equal(t, int64(3), out.Value())
	// Three completions: root (5), then root.parent (4), then root.parent.parent (3).
	// `.name` on the depth-3 node returns from its already-set fields without running its completer again.
	assert.Equal(t, 3, completes)
}

// --- Providers -------------------------------------------------------------

func TestRequestProviderExposesInputViewOnly(t *testing.T) {
	r := newTestRegistry(t)
	mail, _ := r.Get("google.mail.message")
	p := NewRequestProvider(baseProvider{}, mail)

	_, ok := p.FindStructType("google.mail.message.__input__")
	assert.True(t, ok, "input view must be findable")

	_, ok = p.FindStructType("google.mail.message")
	assert.False(t, ok, "request provider must not expose the full view")

	_, ok = p.FindStructType("google.drive.file.__input__")
	assert.False(t, ok, "request provider must not expose other metas")
}

func TestRequestProviderFieldTypes(t *testing.T) {
	r := newTestRegistry(t)
	mail, _ := r.Get("google.mail.message")
	p := NewRequestProvider(baseProvider{}, mail)

	ft, ok := p.FindStructFieldType("google.mail.message.__input__", "id")
	require.True(t, ok)
	assert.Equal(t, types.DynType, ft.Type)

	_, ok = p.FindStructFieldType("google.mail.message.__input__", "sender")
	assert.False(t, ok, "output field must not be visible on the input view")
}

func TestFullProviderExposesBothViews(t *testing.T) {
	r := newTestRegistry(t)
	p := NewFullProvider(baseProvider{}, r)

	for _, name := range []string{
		"google.mail.message",
		"google.mail.message.__input__",
		"google.drive.file",
		"google.drive.file.__input__",
	} {
		_, ok := p.FindStructType(name)
		assert.True(t, ok, "FullProvider should expose %q", name)
	}
}

func TestFullProviderFieldTypes(t *testing.T) {
	r := newTestRegistry(t)
	p := NewFullProvider(baseProvider{}, r)

	// Full view: both input and output fields visible.
	for _, field := range []string{"id", "sender", "subject"} {
		ft, ok := p.FindStructFieldType("google.mail.message", field)
		require.Truef(t, ok, "field %q should be visible on full view", field)
		assert.Equal(t, types.DynType, ft.Type)
	}

	// Input view: only input fields.
	_, ok := p.FindStructFieldType("google.mail.message.__input__", "id")
	assert.True(t, ok)
	_, ok = p.FindStructFieldType("google.mail.message.__input__", "sender")
	assert.False(t, ok)
}

func TestFullProviderFieldNames(t *testing.T) {
	r := newTestRegistry(t)
	p := NewFullProvider(baseProvider{}, r)

	full, ok := p.FindStructFieldNames("google.mail.message")
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"id", "sender", "subject"}, full)

	inputOnly, ok := p.FindStructFieldNames("google.mail.message.__input__")
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"id"}, inputOnly)
}

func TestFullProviderNewValueBuildsFullView(t *testing.T) {
	r := newTestRegistry(t)
	p := NewFullProvider(baseProvider{}, r)

	val := p.NewValue("google.mail.message", map[string]ref.Val{
		"id": types.Int(42),
	})
	v, ok := val.(*Value)
	require.True(t, ok)
	assert.True(t, v.IsFullView())
	assert.Equal(t, types.Int(42), v.Get(types.String("id")))

	v.SetCompleter(func() error {
		v.SetField("sender", types.String("alice@example"))
		v.SetField("subject", types.String("hi"))
		return nil
	})
	assert.Equal(t, types.String("alice@example"), v.Get(types.String("sender")))
}

func TestFullProviderNewValueRejectsInputView(t *testing.T) {
	r := newTestRegistry(t)
	p := NewFullProvider(baseProvider{}, r)

	val := p.NewValue("google.mail.message.__input__", map[string]ref.Val{"id": types.Int(1)})
	_, isErr := val.(*types.Err)
	assert.True(t, isErr, "input view must not be constructible at runtime")
}

func TestFullProviderNewValueRejectsUnknownField(t *testing.T) {
	r := newTestRegistry(t)
	p := NewFullProvider(baseProvider{}, r)

	val := p.NewValue("google.mail.message", map[string]ref.Val{
		"bogus": types.Int(1),
	})
	_, isErr := val.(*types.Err)
	assert.True(t, isErr)
}

// TestFullProviderNewValueRejectsOutputField pins the policy-bypass fix:
// `Type{...}` literals must not accept output-field names. Without this
// check, `google.drive.file{id:"x", name:"shadow"}.name == "shadow"`
// would evaluate to true without ever calling the upstream, letting a
// hostile or buggy YAML author bypass any policy gating on output fields.
func TestFullProviderNewValueRejectsOutputField(t *testing.T) {
	r := newTestRegistry(t)
	p := NewFullProvider(baseProvider{}, r)

	val := p.NewValue("google.mail.message", map[string]ref.Val{
		"id":     types.Int(1),
		"sender": types.String("evil@example"),
	})
	e, isErr := val.(*types.Err)
	require.True(t, isErr, "Type{...} with an output-field literal must fail")
	assert.Contains(t, e.String(), `"sender"`)
	assert.Contains(t, e.String(), "output field")
}

// TestFullProviderEndToEndConstructAndAccess wires the FullProvider into a
// real cel-go env and exercises the Type{...} -> .field path that bind and
// policy expressions will use.
func TestFullProviderEndToEndConstructAndAccess(t *testing.T) {
	defaultReg, err := types.NewRegistry()
	require.NoError(t, err)

	r := NewRegistry()
	require.NoError(t, r.Register(&Type{
		FullName:     "google.drive.file",
		InputFields:  []string{"id"},
		OutputFields: []string{"name"},
	}))

	// Wrap the provider so each freshly-constructed full-view Value gets a
	// completer installed — this mirrors what the runtime layer will do at
	// evaluation time (phase 4+).
	provider := NewFullProvider(defaultReg, r)
	wrapped := &completerInstallingProvider{FullProvider: provider}

	env, err := cel.NewEnv(cel.CustomTypeProvider(wrapped))
	require.NoError(t, err)

	ast, iss := env.Compile(`google.drive.file{id: 7}.name`)
	require.NoError(t, iss.Err())
	prg, err := env.Program(ast)
	require.NoError(t, err)

	out, _, err := prg.Eval(map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "file-7", out.Value())
}

// completerInstallingProvider wraps a FullProvider and installs a
// stub completer on every constructed Value. Used in the end-to-end
// test above to demonstrate that lazy completion works through the
// provider path; production runtime code will install a richer
// completer that runs the meta's request/output programs.
type completerInstallingProvider struct {
	*FullProvider
}

func (p *completerInstallingProvider) NewValue(typeName string, fields map[string]ref.Val) ref.Val {
	val := p.FullProvider.NewValue(typeName, fields)
	v, ok := val.(*Value)
	if !ok {
		return val
	}
	v.SetCompleter(func() error {
		id := v.InputFields()["id"].(types.Int)
		v.SetField("name", types.String("file-"+id.ConvertToType(types.StringType).Value().(string)))
		return nil
	})
	return v
}
