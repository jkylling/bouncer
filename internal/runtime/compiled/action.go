package compiled

import (
	"fmt"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Action is the compiled form of an `Action`. It owns:
//
//   - an optional path Template (`method:` + `path:`) that pre-matches
//     the request and captures named segments into a `match` map;
//   - an optional CEL Filter that runs after the template and may
//     reference the request and the captured `match`;
//   - one CompiledBind per declared bind expression, each tied back to
//     the Meta that produces its result type.
//
// Either Template or Filter must be present (or both); a bare action
// with neither is rejected at compile time.
type Action struct {
	Name     string
	Template *PathTemplate   // optional
	Filter   *CompiledFilter // optional
	Binds    []BoundVariable
}

// BoundVariable carries one bind expression plus the meta it produces.
type BoundVariable struct {
	MetaName string // meta full name, e.g. "gmail.message"
	Bind     *CompiledBind
	Meta     *Meta
}

// BoundValue is the runtime form of one resolved bind: the meta name
// and the *messages.Value the bind expression produced.
type BoundValue struct {
	Name  string
	Value *messages.Value
}

// NewAction compiles the path template (if any), the filter (if any),
// and the bind expressions. Bind output types are resolved against the
// supplied meta map (full-name keyed) so cross-API binds can find their
// target Meta.
func NewAction(action *models.Action, apiName string, reg *messages.Registry, metas map[string]*Meta) (*Action, error) {
	if action.Bind != "" && len(action.Binds) > 0 {
		return nil, fmt.Errorf("action %q: 'bind' and 'binds' are mutually exclusive", action.Name)
	}
	tpl, err := compileActionTemplate(action)
	if err != nil {
		return nil, err
	}
	filter, err := compileActionFilter(action)
	if err != nil {
		return nil, err
	}
	if tpl == nil && filter == nil {
		return nil, fmt.Errorf("action %q: must specify method+path, filter, or both", action.Name)
	}

	be, err := bindEnv(apiName, reg)
	if err != nil {
		return nil, fmt.Errorf("bind env %q: %w", action.Name, err)
	}
	var binds []BoundVariable
	seen := map[string]struct{}{}
	for _, expr := range action.AllBinds() {
		cb, err := NewBind(be, expr)
		if err != nil {
			return nil, fmt.Errorf("action %q: compile bind: %w", action.Name, err)
		}
		typeName := cb.OutputType().TypeName()
		meta, ok := metas[typeName]
		if !ok {
			return nil, fmt.Errorf("action %q: bind returns unknown meta type %q", action.Name, typeName)
		}
		// Two binds producing the same meta type would share the same
		// CEL variable name and clobber each other in the policy
		// environment — only the last-evaluated value would be visible
		// to policies, and which one "last" is would depend on slice
		// iteration order. Reject at compile time. If a policy needs
		// two values of the same meta, it can construct the second
		// inline with `Type{...}`.
		if _, dup := seen[meta.Type.FullName]; dup {
			return nil, fmt.Errorf("action %q: duplicate bind for meta %q", action.Name, meta.Type.FullName)
		}
		seen[meta.Type.FullName] = struct{}{}
		// Bind variables are declared under the meta's full name. With
		// the policy env's container set to the API name, a leaf
		// identifier in policy source (e.g. `message`) resolves via
		// ancestor search to the variable `<api>.message` rather than
		// being shadowed by the type of the same name. Cross-API
		// references work too — a policy on `google.gmail` can write
		// `google.drive.file` and CEL will find it as a variable.
		binds = append(binds, BoundVariable{
			MetaName: meta.Type.FullName,
			Bind:     cb,
			Meta:     meta,
		})
	}
	return &Action{Name: action.Name, Template: tpl, Filter: filter, Binds: binds}, nil
}

func compileActionTemplate(action *models.Action) (*PathTemplate, error) {
	switch {
	case action.Method == "" && action.Path == "":
		return nil, nil
	case action.Method == "":
		return nil, fmt.Errorf("action %q: path set but method missing", action.Name)
	case action.Path == "":
		return nil, fmt.Errorf("action %q: method set but path missing", action.Name)
	}
	tpl, err := ParsePathTemplate(action.Method, action.Path)
	if err != nil {
		return nil, fmt.Errorf("action %q: %w", action.Name, err)
	}
	return tpl, nil
}

func compileActionFilter(action *models.Action) (*CompiledFilter, error) {
	if action.Filter == "" {
		return nil, nil
	}
	env, err := filterEnv()
	if err != nil {
		return nil, fmt.Errorf("filter env %q: %w", action.Name, err)
	}
	f, err := NewFilter(env, action.Filter)
	if err != nil {
		return nil, fmt.Errorf("compile filter %q: %w", action.Name, err)
	}
	return f, nil
}

// Match runs the path template (if any) and then the filter (if any)
// against req. Returns the captured params and true on a successful
// match, or (nil, false) when the action does not fire. An error is
// returned only on a CEL evaluation failure inside the filter.
//
// The returned map is nil when the action has no path template; callers
// that pass it on to CEL evaluations should rely on
// `CompiledFilter.Eval`/`CompiledBind.Eval` to materialise an empty map
// — they're the lowest layer and protect every caller.
func (a *Action) Match(req *pb.Request) (map[string]string, bool, error) {
	// Defence-in-depth: NewAction rejects an Action that has neither
	// a template nor a filter, but the fields are exported and a
	// caller bypassing the constructor (a test helper, a future
	// deserialiser) could land here with both nil. Without this
	// guard, the function would fall through and return (nil, true,
	// nil) — a universal match that fires every policy on every
	// request.
	if a.Template == nil && a.Filter == nil {
		return nil, false, fmt.Errorf("action %q: no template or filter", a.Name)
	}
	var match map[string]string
	if a.Template != nil {
		m, ok := a.Template.Match(req)
		if !ok {
			return nil, false, nil
		}
		match = m
	}
	if a.Filter != nil {
		ok, err := a.Filter.Eval(req, match)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
	}
	return match, true, nil
}

// EvalBinds runs each bind expression against the request and the
// path-template captures, returning the resulting *messages.Value list.
// Completers are *not* installed here — the policy layer attaches them
// at the point where it has the PhysicalAPI in hand.
func (a *Action) EvalBinds(req *pb.Request, match map[string]string) ([]BoundValue, error) {
	out := make([]BoundValue, 0, len(a.Binds))
	for _, b := range a.Binds {
		v, err := b.Bind.Eval(req, match)
		if err != nil {
			return nil, fmt.Errorf("bind %q for %q: %w", b.MetaName, a.Name, err)
		}
		out = append(out, BoundValue{Name: b.MetaName, Value: v})
	}
	return out, nil
}
