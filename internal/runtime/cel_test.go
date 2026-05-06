package runtime

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLazyVariableProvider documents the cel-go activation pattern that the
// runtime relies on for meta resolution: a variable declared in the env can
// be provided as a `func() any`, in which case cel-go only invokes the
// closure the first time the variable is read during evaluation. This lets
// us defer the upstream HTTP call that fills a meta until a policy actually
// references it, and skip it entirely when short-circuit evaluation
// (`||`, `&&`, `?:`, optional unwrap) means the meta is never needed.
func TestLazyVariableProvider(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("a", cel.MapType(cel.StringType, cel.DynType)),
	)
	require.NoError(t, err)

	ast, iss := env.Compile("a.b + 2")
	require.NoError(t, iss.Err())
	program, err := env.Program(ast)
	require.NoError(t, err)

	called := 0
	activation, err := cel.NewActivation(map[string]any{
		"a": func() any {
			called++
			return map[string]any{"b": 3}
		},
	})
	require.NoError(t, err)

	res, _, err := program.Eval(activation)
	require.NoError(t, err)
	assert.Equal(t, int64(5), res.Value())
	assert.Equal(t, 1, called, "provider should run exactly once per Eval")
}

// TestLazyVariableProviderShortCircuits confirms the laziness is real,
// not just memoization: when the program short-circuits before touching
// `a`, the provider is never invoked.
func TestLazyVariableProviderShortCircuits(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("a", cel.MapType(cel.StringType, cel.DynType)),
	)
	require.NoError(t, err)

	ast, iss := env.Compile("true || a.b == 0")
	require.NoError(t, iss.Err())
	program, err := env.Program(ast)
	require.NoError(t, err)

	called := 0
	activation, err := cel.NewActivation(map[string]any{
		"a": func() any {
			called++
			return map[string]any{"b": 3}
		},
	})
	require.NoError(t, err)

	res, _, err := program.Eval(activation)
	require.NoError(t, err)
	assert.Equal(t, true, res.Value())
	assert.Equal(t, 0, called, "provider must not run when the value is unused")
}

// TestLazyRecursiveChain pushes the lazy pattern into a *recursive* shape:
// `a` exposes `name` and `parent`, where `parent` resolves to another value
// of the same shape. cel-go calls our `Get` once per `.parent` step, so
// `a.parent.parent.name` materializes only the nodes the expression
// actually walks — the chain can be arbitrarily deep (or infinite) without
// needing eager construction.
//
// Mechanism: declare `a` as `dyn`, bind a custom `ref.Val` that implements
// `traits.Indexer`. cel-go's qualifier dispatch for a select expression on
// a non-proto `ref.Val` calls `Indexer.Get(types.String(field))`, so each
// `.parent` step runs our closure and produces the next node on demand.
// This is the field-access analogue of the top-level `func() any` pattern
// the runtime uses for meta variables, and is the missing piece for the
// recursive-meta case skipped in `TestRecursiveMeta`.
func TestLazyRecursiveChain(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("a", cel.DynType))
	require.NoError(t, err)

	ast, iss := env.Compile("a.parent.parent.name")
	require.NoError(t, iss.Err())
	program, err := env.Program(ast)
	require.NoError(t, err)

	parentCalls := 0
	var nodeAt func(depth int) *chainNode
	nodeAt = func(depth int) *chainNode {
		return &chainNode{
			name: fmt.Sprintf("node-%d", depth),
			parent: func() *chainNode {
				parentCalls++
				if depth == 0 {
					return nil
				}
				return nodeAt(depth - 1)
			},
		}
	}

	activation, err := cel.NewActivation(map[string]any{"a": nodeAt(5)})
	require.NoError(t, err)

	res, _, err := program.Eval(activation)
	require.NoError(t, err)
	assert.Equal(t, "node-3", res.Value())
	// `a.parent` (5→4) and `.parent` (4→3) — exactly two parent walks; the
	// remaining nodes (2,1,0) are never constructed.
	assert.Equal(t, 2, parentCalls, "only the parents the expression walks should be constructed")
}

// TestLazyRecursiveChainTerminates verifies the null-parent terminator
// works: walking past the root yields `null`, and the program reports
// the no-such-key error rather than hanging.
func TestLazyRecursiveChainTerminates(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("a", cel.DynType))
	require.NoError(t, err)

	ast, iss := env.Compile("a.parent.parent")
	require.NoError(t, iss.Err())
	program, err := env.Program(ast)
	require.NoError(t, err)

	// Single-level chain: a.parent → root, root.parent → null.
	root := &chainNode{name: "root", parent: func() *chainNode { return nil }}
	a := &chainNode{name: "leaf", parent: func() *chainNode { return root }}

	activation, err := cel.NewActivation(map[string]any{"a": a})
	require.NoError(t, err)

	res, _, err := program.Eval(activation)
	require.NoError(t, err)
	assert.Equal(t, types.NullValue, res, "walking past the root should yield null")
}

// TestDottedTypeWithCustomGet wires up the third piece of the lazy-access
// story: making `google.drive.file{id: 123}.parent.parent.id` work as a
// complete CEL expression with no input variables.
//
// CEL parses `pkg.Type{...}` as message construction where `pkg.Type` is a
// *compile-time* identifier sequence (not a runtime select) — see
// TestDottedTypeConstruction in commit history for the basic proto path. To
// teach cel-go about a non-proto type we plug in a custom `types.Provider`:
//   - `FindStructType` — the checker calls this when it sees `google.drive.file`
//     as a type name and needs its meta-type
//   - `FindStructFieldType` — the checker calls this for each `.field` to
//     typecheck the chain (including the recursive `parent: google.drive.file`)
//   - `NewValue` — the runtime calls this for `Type{field: v}` to build the
//     instance
//
// Field reads at runtime then go through `traits.Indexer.Get` on the returned
// `*driveFile`, exactly like `chainNode` above. The provider just makes the
// type *constructible* via the dotted-name syntax.
func TestDottedTypeWithCustomGet(t *testing.T) {
	defaultReg, err := types.NewRegistry()
	require.NoError(t, err)

	env, err := cel.NewEnv(cel.CustomTypeProvider(&driveFileProvider{Provider: defaultReg}))
	require.NoError(t, err)

	ast, iss := env.Compile("google.drive.file{id: 123}.parent.parent.id")
	require.NoError(t, iss.Err())

	prog, err := env.Program(ast)
	require.NoError(t, err)

	res, _, err := prog.Eval(map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, int64(121), res.Value())
}

// driveFile is the runtime value behind `google.drive.file{id: int}`. The
// `parent` field is computed on demand as `id - 1`, demonstrating that
// arbitrarily long `.parent...` chains work without any eager construction.
type driveFile struct {
	id int64
}

const driveFileTypeName = "google.drive.file"

var driveFileType = cel.ObjectType(driveFileTypeName)

var (
	_ ref.Val        = (*driveFile)(nil)
	_ traits.Indexer = (*driveFile)(nil)
)

func (f *driveFile) Type() ref.Type { return driveFileType }
func (f *driveFile) Value() any     { return f }
func (f *driveFile) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("driveFile: native conversion not supported")
}
func (f *driveFile) ConvertToType(t ref.Type) ref.Val {
	if t == driveFileType {
		return f
	}
	return types.NewErr("cannot convert driveFile to %s", t)
}
func (f *driveFile) Equal(other ref.Val) ref.Val {
	o, ok := other.(*driveFile)
	if !ok {
		return types.False
	}
	return types.Bool(f.id == o.id)
}

func (f *driveFile) Get(key ref.Val) ref.Val {
	s, ok := key.(types.String)
	if !ok {
		return types.NewErr("driveFile: expected string key, got %T", key)
	}
	switch string(s) {
	case "id":
		return types.Int(f.id)
	case "parent":
		return &driveFile{id: f.id - 1}
	}
	return types.NewErr("driveFile: no field %q", string(s))
}

// driveFileProvider wraps a default registry to teach cel-go about
// `google.drive.file`. It intercepts only the methods that concern this one
// type; everything else flows through to the embedded provider so primitives
// and registered protos still work.
type driveFileProvider struct {
	types.Provider
}

// Compile-time assertion of the cel-go interface driveFileProvider satisfies.
var _ types.Provider = (*driveFileProvider)(nil)

func (p *driveFileProvider) FindStructType(name string) (*types.Type, bool) {
	if name == driveFileTypeName {
		return types.NewTypeTypeWithParam(driveFileType), true
	}
	return p.Provider.FindStructType(name)
}

func (p *driveFileProvider) FindStructFieldType(structType, field string) (*types.FieldType, bool) {
	if structType == driveFileTypeName {
		switch field {
		case "id":
			return &types.FieldType{Type: types.IntType}, true
		case "parent":
			return &types.FieldType{Type: driveFileType}, true
		}
		return nil, false
	}
	return p.Provider.FindStructFieldType(structType, field)
}

func (p *driveFileProvider) FindStructFieldNames(structType string) ([]string, bool) {
	if structType == driveFileTypeName {
		return []string{"id", "parent"}, true
	}
	return p.Provider.FindStructFieldNames(structType)
}

func (p *driveFileProvider) NewValue(typeName string, fields map[string]ref.Val) ref.Val {
	if typeName == driveFileTypeName {
		f := &driveFile{}
		if v, ok := fields["id"]; ok {
			i, ok := v.(types.Int)
			if !ok {
				return types.NewErr("driveFile.id: expected int, got %T", v)
			}
			f.id = int64(i)
		}
		return f
	}
	return p.Provider.NewValue(typeName, fields)
}

// chainNode is a minimal `ref.Val` that exposes `name` (string) and
// `parent` (lazy chainNode|null) via `traits.Indexer`. cel-go dispatches
// `.field` on a `dyn`-typed value to `Indexer.Get`, which is enough for
// select-style access; we don't need the full `traits.Mapper` surface.
type chainNode struct {
	name   string
	parent func() *chainNode
}

// Compile-time assertion of the cel-go interfaces chainNode satisfies.
var (
	_ ref.Val        = (*chainNode)(nil)
	_ traits.Indexer = (*chainNode)(nil)
)

var chainNodeType = cel.ObjectType("bouncer.test.ChainNode")

func (n *chainNode) Type() ref.Type { return chainNodeType }
func (n *chainNode) Value() any     { return n }
func (n *chainNode) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("chainNode: native conversion not supported")
}
func (n *chainNode) ConvertToType(t ref.Type) ref.Val {
	if t == chainNodeType {
		return n
	}
	return types.NewErr("cannot convert chainNode to %s", t)
}
func (n *chainNode) Equal(other ref.Val) ref.Val {
	o, ok := other.(*chainNode)
	if !ok {
		return types.False
	}
	return types.Bool(n.name == o.name)
}

// Get implements `traits.Indexer`. cel-go's qualifier walk turns each
// `.field` step in the program into a `Get(types.String("field"))` call.
func (n *chainNode) Get(key ref.Val) ref.Val {
	s, ok := key.(types.String)
	if !ok {
		return types.NewErr("chainNode: expected string key, got %T", key)
	}
	switch string(s) {
	case "name":
		return types.String(n.name)
	case "parent":
		if n.parent == nil {
			return types.NullValue
		}
		p := n.parent()
		if p == nil {
			return types.NullValue
		}
		return p
	}
	return types.NewErr("chainNode: no field %q", string(s))
}
