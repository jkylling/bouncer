// Package models defines the YAML-loaded API and policy schema, along with
// a directory loader that flattens multi-document YAML files in a directory.
package models

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// CelExpression is an unevaluated CEL source string. Kept as a named type
// for documentation; YAML decoding treats it as a plain string.
type CelExpression = string

// API is the top-level YAML document loaded from each *.yaml under
// an apis dir — a vendored bundle's apis/ subdir, an operator's
// --apis-dir, or the test fixtures in testdata/apis/.
//
// PathPrefixes is the routing key: each entry is a literal path prefix
// (e.g. "/drive/v3") that the multi-API runtime uses to dispatch
// incoming requests to this API. Matching is segment-aware ("/drive"
// matches "/drive/v3/..." but not "/drives/..."). An API may declare
// multiple disjoint prefixes (Drive serves both "/drive/v3" and
// "/upload/drive/v3"), but no prefix may be a segment-wise prefix of
// another across the whole runtime — that ambiguity is rejected at
// Build time. An API with no prefixes can never be routed to.
type API struct {
	Name         string     `yaml:"name"`
	BaseURL      string     `yaml:"base_url"`
	PathPrefixes []string   `yaml:"path_prefixes"`
	Meta         []Metadata `yaml:"meta"`
	Actions      []Action   `yaml:"actions"`

	// AccessDeniedStatus overrides the HTTP status the proxy returns
	// when it refuses to forward a request — both the 401 (auth fail)
	// and 403 (policy deny) paths use this value when set. Default
	// is the natural status for each path (401/403). Slack's Web API
	// returns 200 with `{"ok": false, "error": "..."}` for application-
	// level errors regardless of severity, and every official Slack
	// SDK branches on `body.ok`; so a Slack bundle sets this to 200
	// to make denials look like normal Slack-shaped errors.
	//
	// Only access-denial responses are remapped — 404 (no API claims
	// the path), 502 (upstream gateway), and 500 (internal eval bug)
	// still use their natural codes.
	AccessDeniedStatus int `yaml:"access_denied_status,omitempty"`

	// Auth controls whether requests to this API require a Bearer
	// JWT. Two values:
	//
	//   - "" / "required" (default): every request must carry a valid
	//     bouncer JWT; a missing/invalid Authorization header is a
	//     401 before policy eval runs.
	//   - "optional": requests without a Bearer are admitted as the
	//     anonymous principal (kind="anonymous", subject=""). Policy
	//     still runs and decides whether to permit. A Bearer that *is*
	//     present is verified normally — the API serves both
	//     authenticated and anonymous callers. Useful for upstreams
	//     whose schema endpoints (e.g. Google's discovery service)
	//     don't need credentials but should still be routed through
	//     the proxy.
	//
	// Forwarded requests on the anonymous path go upstream without
	// an Authorization header — the JWT had no embedded credential
	// to substitute. Upstreams that do require auth respond with
	// their own 401, which the proxy passes through.
	Auth string `yaml:"auth,omitempty"`
}

// AuthOptional reports whether the API admits anonymous (no-Bearer)
// requests. False means a missing/invalid Bearer is a hard 401.
func (a *API) AuthOptional() bool { return a.Auth == "optional" }

// Metadata describes a single named meta — a logical resource shape that
// the runtime can lazily fetch to back a policy variable.
type Metadata struct {
	Name    string        `yaml:"name"`
	Kind    string        `yaml:"kind"`
	Input   []InputField  `yaml:"input"`
	Request CelExpression `yaml:"request"`
	Output  []OutputField `yaml:"output"`
}

// InputField is a meta input variable; only its name matters at runtime
// because the dynamic proto field type is always google.protobuf.Any.
type InputField struct {
	Name string `yaml:"name"`
}

// OutputField is a meta output variable: a name and a CEL expression that
// is evaluated against the upstream Response to produce the field value.
type OutputField struct {
	Name string        `yaml:"name"`
	Expr CelExpression `yaml:"expr"`
}

// Action is one routable behaviour (e.g. "get_message") for an API. It is
// matched against an incoming request in two complementary ways:
//
//   - a path template (`method:` + `path:`) that uses `{name}` placeholders
//     to capture path-segment params into the `match` variable, e.g.
//     `path: /v1/users/{user_id}/messages/{message_id}`.
//   - a CEL `filter:` expression for anything the template can't express.
//
// Either side may be omitted, but at least one must be present. When both
// are present, both must match (template first; its captures are exposed
// to the filter as `match.<name>`). Bind expressions also see `match`.
type Action struct {
	Name string `yaml:"name"`

	// Method is the HTTP method (case-insensitive) the path template
	// matches on. Required iff Path is set.
	Method string `yaml:"method,omitempty"`

	// Path is the URI template, with `{name}` placeholders for captured
	// path-segment params. Required iff Method is set.
	Path string `yaml:"path,omitempty"`

	// Filter is an optional CEL predicate applied after the path template
	// (if any) succeeds. With no path template it acts alone.
	Filter CelExpression `yaml:"filter,omitempty"`

	Bind  CelExpression   `yaml:"bind,omitempty"`
	Binds []CelExpression `yaml:"binds,omitempty"`
}

// AllBinds returns the merged list of bind/binds expressions, preserving the
// Rust impl's order: singular `bind` first, then plural `binds`. An empty
// `bind:` field is treated as omitted.
func (a *Action) AllBinds() []CelExpression {
	out := make([]CelExpression, 0, len(a.Binds)+1)
	if a.Bind != "" {
		out = append(out, a.Bind)
	}
	out = append(out, a.Binds...)
	return out
}

// PolicyResult is one of permit/deny.
type PolicyResult string

const (
	Permit PolicyResult = "permit"
	Deny   PolicyResult = "deny"
)

// Validate reports whether r is one of the recognised PolicyResult
// values. Used at compile-load time so a typo (`result: dney`, or an
// omitted `result:` field) fails loudly rather than silently flipping a
// deny policy into a permit policy.
func (r PolicyResult) Validate() error {
	switch r {
	case Permit, Deny:
		return nil
	case "":
		return fmt.Errorf("policy result is required (permit|deny)")
	default:
		return fmt.Errorf("policy result %q is not one of permit|deny", string(r))
	}
}

// UnmarshalYAML rejects unknown PolicyResult values at YAML-load time
// with line/column context, instead of waiting for compile-time
// Validate to flag them at the policy boundary. Combined with the
// loader's KnownFields(true) this closes most of the "I
// configured X but the runtime did Y" surface — the operator sees
// "line 14: policy result \"dney\" is not one of permit|deny" rather
// than a generic build-time error indistinguishable from a structural
// problem.
func (r *PolicyResult) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	v := PolicyResult(s)
	if err := v.Validate(); err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	*r = v
	return nil
}

// Policy is a single conditional rule loaded from the operator's
// policies dir (typically /policies/*.yaml; the bundled config/
// ships API specs only). Many policies may target the same action;
// the runtime evaluates deny policies before permits.
//
// Action is a CEL bool predicate evaluated against `action.name`,
// `request`, and `match` (the path-template captures from the matched
// action). It decides which of the API's matched actions the policy
// applies to. An empty Action means "applies to every matched action"
// — handy for policies that gate by request shape alone. Examples:
//
//	action: action.name == "get_message"
//	action: action.name in ["get_message", "list_messages"]
//	action: match.user_id == 'me'
//	action:                                # match every matched action
//
// Pre-CEL configs that wrote a bare action name (`action: get_message`)
// must migrate to `action: action.name == "get_message"`; the bare
// form now compiles as a CEL identifier reference and fails loudly at
// load time.
type Policy struct {
	API  string `yaml:"api" json:"api"`
	Name string `yaml:"name" json:"name"`

	// Description is a free-form human-facing note: what the policy
	// is for, why it exists, who owns it. Optional and ignored by
	// the runtime.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Principal is an optional CEL bool predicate evaluated against the
	// caller identity (`principal`) and the originating request before
	// any per-action work. An empty Principal means "applies to every
	// caller" (compiled as the constant `true`). It runs first because
	// it is the cheapest filter — a policy that only fires for one kind
	// of caller short-circuits before the runtime walks matched
	// actions. Examples:
	//
	//	principal: principal.subject == "agent-1"
	//	principal: principal.kind == "user"
	//	principal: "admin" in principal.scopes
	Principal CelExpression `yaml:"principal,omitempty" json:"principal,omitempty"`

	Action    CelExpression `yaml:"action" json:"action"`
	Condition CelExpression `yaml:"condition" json:"condition"`
	Result    PolicyResult  `yaml:"result" json:"result"`
}
