package compiled

import (
	"context"
	"fmt"
	"time"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Meta is the compiled form of a `Metadata`. It owns the meta's CEL
// programs (request + per-output) plus a reference to the meta's Type
// entry in the shared messages.Registry.
//
// Construction is split into two phases so that all Types are
// registered before any output env (which uses FullProvider over the
// registry) is built — required for cross-meta references to resolve.
//
// APIName carries the API the meta belongs to so cross-API completers
// resolve through PhysicalAPIResolver to the *meta's* upstream rather
// than the routed-request upstream. It matches the apiName passed to
// RegisterMetaType / CompileMeta, which is also the prefix of
// Type.FullName.
type Meta struct {
	APIName string
	Type    *messages.Type
	Request *CompiledRequest
	Outputs []NamedOutput
}

// UsesRequestBody reports whether any output expression can observe
// the inbound request's body. The request expression sees only
// `input`, so outputs are the meta's only window onto the request.
func (m *Meta) UsesRequestBody() bool {
	for _, o := range m.Outputs {
		if o.Prog.UsesRequestBody() {
			return true
		}
	}
	return false
}

// NamedOutput is one output-field expression on a meta.
type NamedOutput struct {
	Name string
	Prog *CompiledOutput
}

// RegisterMetaType installs the meta's Type in reg and returns it. No
// programs are compiled in this phase; that happens in CompileMeta once
// every meta on the API is registered.
func RegisterMetaType(meta *models.Metadata, apiName string, reg *messages.Registry) (*messages.Type, error) {
	inputFields := make([]string, len(meta.Input))
	for i, f := range meta.Input {
		inputFields[i] = f.Name
	}
	outputFields := make([]string, len(meta.Output))
	for i, o := range meta.Output {
		outputFields[i] = o.Name
	}
	t := &messages.Type{
		FullName:     apiName + "." + meta.Name,
		InputFields:  inputFields,
		OutputFields: outputFields,
	}
	if err := reg.Register(t); err != nil {
		return nil, fmt.Errorf("register meta %q: %w", meta.Name, err)
	}
	return t, nil
}

// CompileMeta compiles the request and output expressions against the
// per-API celenv builders, producing a fully-functional Meta.
func CompileMeta(meta *models.Metadata, apiName string, t *messages.Type, reg *messages.Registry) (*Meta, error) {
	reqEnv, err := requestEnv(apiName, t)
	if err != nil {
		return nil, fmt.Errorf("meta %q: %w", meta.Name, err)
	}
	req, err := NewRequest(reqEnv, meta.Request)
	if err != nil {
		return nil, fmt.Errorf("meta %q request: %w", meta.Name, err)
	}

	outEnv, err := outputEnv(apiName, t, reg)
	if err != nil {
		return nil, fmt.Errorf("meta %q output env: %w", meta.Name, err)
	}
	outputs := make([]NamedOutput, 0, len(meta.Output))
	for _, o := range meta.Output {
		op, err := NewOutput(outEnv, o.Expr)
		if err != nil {
			return nil, fmt.Errorf("meta %q output %q: %w", meta.Name, o.Name, err)
		}
		outputs = append(outputs, NamedOutput{Name: o.Name, Prog: op})
	}

	return &Meta{APIName: apiName, Type: t, Request: req, Outputs: outputs}, nil
}

// CompleterFor returns a func() error that, when run, fetches the
// upstream payload for v and populates its output fields. Output
// expressions returning child *messages.Value (the recursion case)
// have their own completer installed pointing back through the same
// registry, so chained `.parent.parent...` walks materialise lazily.
//
// Self-referential metas (a meta whose output expression constructs
// the same meta — e.g. `file{parent: file{id: response.body.parent}}`)
// are supported by design: SetCompleter only *attaches* a completer to
// the child Value, it does not invoke one. Each `.parent` access
// triggers exactly one upstream call for the next link in the chain,
// terminating naturally when the policy stops walking. Eagerly
// expanding outputs would be the only way to loop, and the runtime
// never does that.
//
// The upstream is resolved through `resolve` keyed by the *meta's* own
// API (m.APIName), not the routed-request API. This is what makes
// cross-API binds and inline `Type{...}` literals work: a `gmail`
// policy reading `google.drive.file{id: ...}` resolves "google.drive"
// here and issues the GET against the Drive base URL.
//
// The closure captures ctx/resolve/req for this evaluation only —
// calling the returned function for a different request requires a new
// closure.
func (m *Meta) CompleterFor(ctx context.Context, v *messages.Value, reg *messages.Registry, metas map[string]*Meta, resolve PhysicalAPIResolver, req *pb.Request) func() error {
	return func() error {
		input, err := reg.NewInputValue(m.Type.FullName, v.InputFields())
		if err != nil {
			return err
		}
		mr, err := m.Request.Eval(input)
		if err != nil {
			return err
		}
		api, err := resolve(m.APIName)
		if err != nil {
			return fmt.Errorf("meta %q resolve api %q: %w", m.Type.FullName, m.APIName, err)
		}
		started := time.Now()
		resp, err := api.Call(ctx, mr)
		if obs := FetchObserverFrom(ctx); obs != nil {
			obs(m.Type.FullName, m.APIName, mr, resp, err, time.Since(started))
		}
		if err != nil {
			return fmt.Errorf("meta %q upstream: %w", m.Type.FullName, err)
		}
		if resp == nil {
			resp = &pb.Response{}
		}
		for _, op := range m.Outputs {
			out, err := op.Prog.Eval(input, req, resp)
			if err != nil {
				return fmt.Errorf("meta %q output %q: %w", m.Type.FullName, op.Name, err)
			}
			if child, ok := out.(*messages.Value); ok && child.IsFullView() {
				if childMeta, ok := metas[child.MetaType().FullName]; ok {
					child.SetCompleter(childMeta.CompleterFor(ctx, child, reg, metas, resolve, req))
				}
			}
			v.SetField(op.Name, out)
		}
		return nil
	}
}
