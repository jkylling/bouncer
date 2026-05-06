// Package propose builds a CEL policy whose condition matches a
// single recorded request — the AlertManager-style "silence this and
// everything like it" flow, where the user clicks an event and gets
// back a policy proposal. Given a traffic.Event and a per-field
// selection, it walks the recorded bind values, renders an equality
// clause per selected field, and produces a models.Policy validated
// against the live runtime.
//
// The package is HTTP-agnostic: the admin layer adapts it to a
// /propose-policy endpoint that either previews (no write) or hands
// the rendered policy to proposals.Service.
package propose

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// ListMatch controls how a list field's clause is rendered. The
// default `contains_all` is what an operator usually wants for "this
// label set" — the label set on the recorded message must be a
// superset of the original. Equality is stricter (every label in the
// same order); contains_any is loosest (any single overlap fires).
type ListMatch string

const (
	ListContainsAll ListMatch = "contains_all"
	ListEquals      ListMatch = "equals"
	ListContainsAny ListMatch = "contains_any"
)

// Field is one walked, addressable bind field with the value the
// proxy recorded and a "selected" flag the caller can flip. The path
// is dotted from the bind short name down (e.g. `message.labelIds`).
type Field struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Value    any    `json:"value"`
	Selected bool   `json:"selected"`
}

// Input is what the caller hands the engine. Empty Include means
// "use the default selection". Empty Result is treated as deny — the
// dominant case for the propose flow; the caller can override.
type Input struct {
	Result    models.PolicyResult  `json:"result"`
	Include   []string             `json:"include,omitempty"`
	ListMatch map[string]ListMatch `json:"list_match,omitempty"`
	Name      string               `json:"name,omitempty"`
}

// Result is what the engine returns. Both the rendered policy and
// the available_fields list are present on every call so the UI can
// render checkboxes without itself walking the proto.
type Result struct {
	Policy          models.Policy `json:"policy"`
	AvailableFields []Field       `json:"available_fields"`
	CompileOK       bool          `json:"compile_ok"`
	CompileError    string        `json:"compile_error,omitempty"`
}

// ErrNoAPI fires when the event didn't match any registered API.
// Without an API there is no policy namespace to attach the proposal
// to, so the engine can't render anything useful. The other two
// previously-fatal cases (no action, no binds) now fall back to
// literal request-shape clauses (request.method, request.path) so
// the reviewer always gets a starting draft.
var ErrNoAPI = errors.New("event did not match any registered API")

// Engine renders a policy from one Event. Construct one Engine per
// process and reuse — it keeps no per-call state and the runtime
// reference is the only dependency.
type Engine struct {
	rt *runtime.Runtime
}

// New constructs an Engine. rt must be non-nil.
func New(rt *runtime.Runtime) *Engine { return &Engine{rt: rt} }

// Propose walks ev's binds, applies in.Include (or default selection
// when Include is nil), and returns the rendered policy + the field
// list. The policy is always validated against the live runtime;
// CompileOK / CompileError surface the result so the UI can render
// inline feedback without intercepting non-2xx.
//
// Fallback shape: when ev has no action match (request matched the
// API by path prefix but no action's method/path template covered it)
// or no resolved binds, the engine still renders a draft that
// constrains on request.method and request.path. The reviewer can
// then either tighten the action by adding it to the API config, or
// approve the broader rule as-is.
func (e *Engine) Propose(ev traffic.Event, in Input) (Result, error) {
	if ev.API == "" {
		return Result{}, ErrNoAPI
	}
	bindFields, err := walkBinds(ev.API, ev.Binds)
	if err != nil {
		return Result{}, fmt.Errorf("walk binds: %w", err)
	}
	requestFields := requestShapeFields(ev)
	hasBinds := len(bindFields) > 0

	// Default selection: bind fields default-on when present, request
	// fields default-off (the operator usually wants the bind clauses
	// to do the gating). When there are no binds, request fields
	// default-on so the proposal still has clauses to check.
	for i := range requestFields {
		requestFields[i].Selected = !hasBinds
	}
	fields := append(bindFields, requestFields...)

	includeSet := selectionSet(fields, in.Include)
	for i := range fields {
		fields[i].Selected = includeSet[fields[i].Path]
	}

	listMatch := in.ListMatch
	if listMatch == nil {
		listMatch = map[string]ListMatch{}
	}
	condition := renderCondition(fields, listMatch)

	result := in.Result
	if result == "" {
		result = models.Deny
	}
	name := in.Name
	if name == "" {
		name = autoName(result, ev.Action, fields)
	}

	// Action predicate: scoped to the matched action when we have
	// one, otherwise `true` so the policy applies to any action this
	// API claims (or to a request that didn't match an action at
	// all, once one is added that does).
	actionPred := "true"
	if ev.Action != "" {
		actionPred = fmt.Sprintf("action.name == %q", ev.Action)
	}

	policy := models.Policy{
		API:       ev.API,
		Name:      name,
		Action:    actionPred,
		Condition: condition,
		Result:    result,
	}
	out := Result{
		Policy:          policy,
		AvailableFields: fields,
		CompileOK:       true,
	}
	if err := e.rt.ValidatePolicy(&policy); err != nil {
		out.CompileOK = false
		out.CompileError = err.Error()
	}
	return out, nil
}

// requestShapeFields builds the always-available request.method /
// request.path field pair from the recorded URL. The path component
// is the URL up to the first '?' so query strings don't leak into
// the literal-equality check (operators usually want a path-shaped
// rule, not "this exact query").
func requestShapeFields(ev traffic.Event) []Field {
	path := ev.URL
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	var fields []Field
	if ev.Method != "" {
		fields = append(fields, Field{
			Path:  "request.method",
			Type:  "string",
			Value: ev.Method,
		})
	}
	if path != "" {
		fields = append(fields, Field{
			Path:  "request.path",
			Type:  "string",
			Value: path,
		})
	}
	return fields
}

// selectionSet returns the set of paths that should be marked
// selected. Nil Include means "use each field's default"; an empty
// non-nil slice means "deselect everything" (the engine renders
// `condition: "true"`, which the validator rejects — the caller is
// expected to restore at least one selection before submitting).
//
// The default reflects the per-field Selected flag set by the
// producer: bind fields are always-on (the strategy doc's "include
// everything, reviewer prunes" rule), request.method/request.path
// are on only when there are no bind fields to gate on.
func selectionSet(fields []Field, include []string) map[string]bool {
	if include == nil {
		out := make(map[string]bool, len(fields))
		for _, f := range fields {
			out[f.Path] = f.Selected
		}
		return out
	}
	out := make(map[string]bool, len(include))
	for _, p := range include {
		out[p] = true
	}
	return out
}

// walkBinds enumerates every (path, value, type) triple a policy
// could constrain on. Paths are dotted from the bind short name; the
// short name is the last segment of the bind type when the bind
// belongs to ev.API, otherwise the full type name (so a cross-API
// bind keeps its qualifier).
func walkBinds(apiName string, binds []traffic.ResolvedBind) ([]Field, error) {
	var fields []Field
	for _, b := range binds {
		shape, err := decodeBindShape(b.Value)
		if err != nil {
			return nil, fmt.Errorf("bind %q: %w", b.Name, err)
		}
		short := bindShortName(apiName, shape.Type, b.Name)
		// Walk inputs first so they appear before outputs in the UI;
		// outputs are usually the more interesting set so they sort
		// to the bottom where the user looks last.
		for _, name := range sortedKeys(shape.Inputs) {
			fields = appendField(fields, short+"."+name, shape.Inputs[name])
		}
		for _, name := range sortedKeys(shape.Outputs) {
			fields = appendField(fields, short+"."+name, shape.Outputs[name])
		}
	}
	return fields, nil
}

// bindShape mirrors messages.Value's MarshalJSON output. Only the
// three keys we care about are decoded; any future siblings round-
// trip via json.RawMessage in a parent decode and never reach here.
type bindShape struct {
	Type    string         `json:"type"`
	Inputs  map[string]any `json:"inputs"`
	Outputs map[string]any `json:"outputs"`
}

func decodeBindShape(raw json.RawMessage) (bindShape, error) {
	var s bindShape
	if err := json.Unmarshal(raw, &s); err != nil {
		return bindShape{}, err
	}
	if s.Type == "" {
		return bindShape{}, errors.New("bind value missing 'type' key")
	}
	return s, nil
}

// bindShortName returns the name we'll use for this bind in the
// rendered policy condition. For a same-API bind (`gmail.message` on
// API `gmail`) we strip the API prefix so the policy reads
// `message.x` as it would in any hand-written gmail policy. For a
// cross-API bind we keep the qualifier — `drive.file.x` — because
// the policy's CEL container won't resolve `file` on its own.
//
// `metaFullName` is the value-side type tag; `bindName` is the
// recorder-side ResolvedBind.Name. They should agree, but if for
// some reason they don't (older recorder serialization, future
// schema drift) we prefer the value-side tag — that's what the JSON
// is shaped around.
func bindShortName(apiName, metaFullName, bindName string) string {
	t := metaFullName
	if t == "" {
		t = bindName
	}
	prefix := apiName + "."
	if strings.HasPrefix(t, prefix) {
		return t[len(prefix):]
	}
	return t
}

// appendField recurses into nested bind-shape values so a chained
// `parent.parent.parent.id` access surfaces as one path. Plain maps
// (not bind-shaped) are skipped — their semantics aren't
// constrainable in CEL without a value-equality dance the strategy
// doc explicitly defers to v2.
func appendField(fields []Field, path string, value any) []Field {
	switch v := value.(type) {
	case map[string]any:
		// Bind-shaped child? Recurse via the same walker.
		if t, ok := v["type"].(string); ok && t != "" {
			child := bindShape{
				Type:    t,
				Inputs:  asMap(v["inputs"]),
				Outputs: asMap(v["outputs"]),
			}
			for _, name := range sortedKeys(child.Inputs) {
				fields = appendField(fields, path+"."+name, child.Inputs[name])
			}
			for _, name := range sortedKeys(child.Outputs) {
				fields = appendField(fields, path+"."+name, child.Outputs[name])
			}
			return fields
		}
		// Plain object — opaque, skip. The strategy doc lists
		// whole-message equality as "out for v2" because proto
		// equality across versions is brittle.
		return fields
	case nil:
		return fields
	}
	return append(fields, Field{
		Path:     path,
		Type:     describeType(value),
		Value:    value,
		Selected: true, // bind fields default-on; reviewer prunes
	})
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// describeType produces a human-readable type tag for the UI. The
// JSON decoder gives us float64 for any number, but we tell int from
// double by checking whether the value has a fractional part — which
// is what the operator usually wants to see in the field list.
func describeType(v any) string {
	switch x := v.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case float64:
		if x == float64(int64(x)) {
			return "int"
		}
		return "double"
	case []any:
		if len(x) == 0 {
			return "list"
		}
		return "list<" + describeType(x[0]) + ">"
	}
	return fmt.Sprintf("%T", v)
}

// renderCondition concatenates the selected fields' equality clauses
// with `&&`. Each clause lands on its own line so the rendered
// condition is readable in both the preview pane and the YAML block
// scalar the UI emits. CEL is whitespace-insensitive outside literals
// so a multi-line condition compiles identically to a single-line one.
//
// Empty selection returns `"true"` — which the validator rejects, but
// lets the UI render a coherent preview ("you've deselected
// everything; pick at least one field to silence on").
func renderCondition(fields []Field, listMatch map[string]ListMatch) string {
	var parts []string
	for _, f := range fields {
		if !f.Selected {
			continue
		}
		clause := renderClause(f, listMatch[f.Path])
		if clause == "" {
			continue
		}
		parts = append(parts, clause)
	}
	if len(parts) == 0 {
		return "true"
	}
	return strings.Join(parts, " &&\n")
}

// renderClause produces the CEL fragment for one selected field.
// Lists pick the strategy doc's three modes; scalars are rendered as
// straight equality with a CEL literal.
func renderClause(f Field, lm ListMatch) string {
	switch f.Type {
	case "list<string>", "list<int>", "list<double>", "list<bool>":
		// Lists have a list_match selector; default contains_all.
		if lm == "" {
			lm = ListContainsAll
		}
		return renderListClause(f.Path, f.Value, lm)
	case "list":
		// Empty list at record time — comparing produces something
		// brittle ("path == []"), and contains_all over an empty
		// set is vacuously true. Skip rather than render an
		// always-true clause.
		return ""
	}
	lit := scalarLiteral(f.Value)
	if lit == "" {
		return ""
	}
	return f.Path + " == " + lit
}

// renderListClause picks one of:
//
//	contains_all → [a,b,c].all(x, x in path)         // path is a superset
//	equals       → path == [a,b,c]                   // path equals literal
//	contains_any → [a,b,c].exists(x, x in path)      // any overlap
//
// All three are stable CEL forms.
func renderListClause(path string, value any, lm ListMatch) string {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return ""
	}
	var literals []string
	for _, it := range items {
		l := scalarLiteral(it)
		if l == "" {
			// Mixed / nested element types aren't constrainable
			// here; skip the whole clause rather than emit a
			// half-rendered one.
			return ""
		}
		literals = append(literals, l)
	}
	listLit := "[" + strings.Join(literals, ", ") + "]"
	switch lm {
	case ListEquals:
		return path + " == " + listLit
	case ListContainsAny:
		return listLit + ".exists(x, x in " + path + ")"
	default: // ListContainsAll
		return listLit + ".all(x, x in " + path + ")"
	}
}

// scalarLiteral renders a Go value as a CEL literal. Strings are
// single-quoted with the minimum escapes CEL requires; numbers fall
// out of float64 with one decimal-point preserve for doubles.
// Anything we can't render returns "" so the caller skips the clause.
func scalarLiteral(v any) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

// autoName builds a starting policy name like
// `deny-delete_message-from-alice-example-com`, truncated to 40 chars.
// The strategy doc spec is `{result}-{action}-{topfield}-{topvalue}`;
// we use the first selected scalar field for {topfield}/{topvalue} so
// auto-generated names from different requests rarely collide.
func autoName(result models.PolicyResult, action string, fields []Field) string {
	base := string(result) + "-" + action
	for _, f := range fields {
		if !f.Selected {
			continue
		}
		if s, ok := f.Value.(string); ok {
			base += "-" + slug(f.Path[strings.LastIndex(f.Path, ".")+1:]) + "-" + slug(s)
			break
		}
	}
	if len(base) > 40 {
		base = base[:40]
	}
	return base
}

// slug lowercases and replaces non-[a-z0-9-] runs with `-`. The
// result is suitable for an identifier-shaped policy name; the
// validator will accept anything non-empty here, so the rule is for
// human readability rather than parse-correctness.
func slug(s string) string {
	var b strings.Builder
	prev := byte('-')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c = c + ('a' - 'A')
			b.WriteByte(c)
			prev = c
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
			prev = c
		default:
			if prev != '-' {
				b.WriteByte('-')
				prev = '-'
			}
		}
	}
	out := b.String()
	out = strings.Trim(out, "-")
	return out
}
