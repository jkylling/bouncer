package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/proposals"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// tool is one MCP tool: schema for tools/list, executor for
// tools/call. Each tool also declares whether it requires the admin
// tier — read-only listings work for any authenticated caller, but
// anything that writes (propose / approve / reject) gates here.
type tool struct {
	Name        string
	Title       string
	Description string
	InputSchema map[string]any
	AdminOnly   bool
	Run         func(ctx context.Context, deps Deps, params json.RawMessage) (any, *Error)
}

// toolDescriptor is the wire shape for tools/list. Mirrors the MCP
// spec's Tool object.
type toolDescriptor struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

// content is one entry in the tools/call result envelope. We always
// emit a single text block carrying JSON; clients that want
// structured output decode the JSON, clients that pass it to a
// model see a readable transcript.
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// callToolResult is the spec's tools/call response shape.
type callToolResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// allTools is the in-process registry. New tools land here; the
// list is split into read-only and write halves below for clarity.
func allTools() []tool {
	return []tool{
		// ---- read-only ----------------------------------------
		{
			Name:        "list_apis",
			Title:       "List registered APIs",
			Description: "Returns every API the proxy knows about. The canonical schema discovery surface — equivalent to GET /_api/apis. APIs sourced from a vendored bundle carry a `readme_url` that points at the bundle README; agents can read it via `resources/read` with `bouncer://bundles/<bundle>/readme`.",
			InputSchema: schemaObject(nil, nil),
			Run:         runListAPIs,
		},
		{
			Name:        "list_policies",
			Title:       "List live policies",
			Description: "Returns every active policy. Optional `api` filter narrows by parent API. Equivalent to GET /_api/policies.",
			InputSchema: schemaObject(map[string]any{
				"api": map[string]any{"type": "string", "description": "Filter to one API by name."},
			}, nil),
			Run: runListPolicies,
		},
		{
			Name:        "get_policy",
			Title:       "Get a live policy",
			Description: "Fetch one policy by (api, name). Equivalent to GET /_api/policies/{api}/{name}.",
			InputSchema: schemaObject(map[string]any{
				"api":  map[string]any{"type": "string"},
				"name": map[string]any{"type": "string"},
			}, []string{"api", "name"}),
			Run: runGetPolicy,
		},
		{
			Name:        "dry_run_policy",
			Title:       "Validate a draft policy",
			Description: "Compile-check a policy body against the live runtime without persisting. Equivalent to POST /_api/policies:dryRun. Returns {ok:true} on success or {ok:false, error:<msg>}.",
			InputSchema: policyInputSchema(),
			Run:         runDryRunPolicy,
		},
		{
			Name:        "list_proposals",
			Title:       "List policy proposals",
			Description: "Returns proposals (drafts) the human reviewer queue. Optional filters: status (proposed|approved|rejected), api. Equivalent to GET /_api/proposals.",
			InputSchema: schemaObject(map[string]any{
				"status": map[string]any{"type": "string", "enum": []string{"proposed", "approved", "rejected"}},
				"api":    map[string]any{"type": "string"},
			}, nil),
			Run: runListProposals,
		},
		{
			Name:        "get_proposal",
			Title:       "Get one proposal",
			Description: "Fetch a proposal by id. Equivalent to GET /_api/proposals/{id}.",
			InputSchema: schemaObject(map[string]any{
				"id": map[string]any{"type": "string"},
			}, []string{"id"}),
			Run: runGetProposal,
		},
		{
			Name:        "list_traffic",
			Title:       "List recent requests",
			Description: "Returns recently-recorded requests for context. Optional filters: api, action, method, decision, path_prefix, pinned (bool), limit. Equivalent to GET /_api/traffic.",
			InputSchema: schemaObject(map[string]any{
				"api":         map[string]any{"type": "string"},
				"action":      map[string]any{"type": "string"},
				"method":      map[string]any{"type": "string"},
				"decision":    map[string]any{"type": "string", "enum": []string{"permit", "deny", "no_match", "error"}},
				"path_prefix": map[string]any{"type": "string"},
				"pinned":      map[string]any{"type": "boolean"},
				"limit":       map[string]any{"type": "integer", "minimum": 1},
			}, nil),
			Run: runListTraffic,
		},
		{
			Name:        "get_traffic_event",
			Title:       "Get one traffic event",
			Description: "Fetch the full recorded request by id. Equivalent to GET /_api/traffic/{id}.",
			InputSchema: schemaObject(map[string]any{
				"id": map[string]any{"type": "string"},
			}, []string{"id"}),
			Run: runGetTrafficEvent,
		},
		// ---- write --------------------------------------------
		{
			Name:        "propose_policy",
			Title:       "Submit a policy draft for review",
			Description: "Creates a proposal in the human-review queue. Equivalent to POST /_api/proposals. With kind=apply (default) the proposal asks the reviewer to add or replace the policy at (api, name); with kind=delete it asks the reviewer to remove the live policy at that key (only api + name read from the policy object). The runtime validates the apply path against the live runtime before persisting.",
			InputSchema: schemaObject(map[string]any{
				"kind":      map[string]any{"type": "string", "enum": []string{"apply", "delete"}, "default": "apply"},
				"policy":    policyInputSchema(),
				"rationale": map[string]any{"type": "string", "description": "Free-form note explaining why the policy is needed."},
			}, []string{"policy"}),
			Run: runProposePolicy,
		},
		{
			Name:        "propose_policy_deletion",
			Title:       "Submit a removal proposal for review",
			Description: "Convenience wrapper around propose_policy with kind=delete. Equivalent to POST /_api/proposals with the same kind. Approving the resulting proposal removes the live policy at (api, name).",
			InputSchema: schemaObject(map[string]any{
				"api":       map[string]any{"type": "string"},
				"name":      map[string]any{"type": "string"},
				"rationale": map[string]any{"type": "string"},
			}, []string{"api", "name"}),
			Run: runProposePolicyDeletion,
		},
		{
			Name:        "approve_proposal",
			Title:       "Approve a proposal (admin)",
			Description: "Promotes the proposal's policy into the live runtime. Equivalent to POST /_api/proposals/{id}/approve. Requires admin.",
			InputSchema: schemaObject(map[string]any{
				"id":        map[string]any{"type": "string"},
				"overwrite": map[string]any{"type": "boolean", "description": "Overwrite an existing live policy on (api, name) collision."},
			}, []string{"id"}),
			AdminOnly: true,
			Run:       runApproveProposal,
		},
		{
			Name:        "reject_proposal",
			Title:       "Reject a proposal (admin)",
			Description: "Marks the proposal rejected. Equivalent to POST /_api/proposals/{id}/reject. Requires admin.",
			InputSchema: schemaObject(map[string]any{
				"id":     map[string]any{"type": "string"},
				"reason": map[string]any{"type": "string"},
			}, []string{"id"}),
			AdminOnly: true,
			Run:       runRejectProposal,
		},
	}
}

// schemaObject builds a JSON-Schema object with `type:"object"` and
// optional properties / required slots. A nil properties map yields
// the empty `{type:"object"}` schema (zero-arg tool).
func schemaObject(props map[string]any, required []string) map[string]any {
	out := map[string]any{"type": "object"}
	if len(props) > 0 {
		out["properties"] = props
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

// policyInputSchema is the shared sub-schema for a policy body. Used
// by dry_run_policy and by the `policy` field of propose_policy.
func policyInputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"api":         map[string]any{"type": "string"},
			"name":        map[string]any{"type": "string"},
			"description": map[string]any{"type": "string"},
			"principal":   map[string]any{"type": "string"},
			"action":      map[string]any{"type": "string"},
			"condition":   map[string]any{"type": "string"},
			"result":      map[string]any{"type": "string", "enum": []string{"permit", "deny"}},
		},
		"required": []string{"api", "name", "action", "condition", "result"},
	}
}

// listToolsResult is the spec's tools/list response shape.
type listToolsResult struct {
	Tools []toolDescriptor `json:"tools"`
}

func (s *Server) handleToolsList(_ *http.Request, _ json.RawMessage) (any, *Error) {
	tools := allTools()
	out := make([]toolDescriptor, 0, len(tools))
	for _, t := range tools {
		out = append(out, toolDescriptor{
			Name:        t.Name,
			Title:       t.Title,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return listToolsResult{Tools: out}, nil
}

// callToolParams is the inbound shape of tools/call. arguments is
// the per-tool params object (validated by the tool itself).
type callToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (s *Server) handleToolsCall(r *http.Request, params json.RawMessage) (any, *Error) {
	var p callToolParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, invalidParams("could not decode params: %v", err)
	}
	if p.Name == "" {
		return nil, invalidParams(`"name" is required`)
	}
	for _, t := range allTools() {
		if t.Name != p.Name {
			continue
		}
		if t.AdminOnly {
			c := auth.CallerFromContext(r.Context())
			if c.Role != auth.RoleAdmin {
				return nil, &Error{
					Code:    codeInvalidRequest,
					Message: "tool " + p.Name + " requires the admin role",
				}
			}
		}
		// Default to an empty object so tools that take no
		// arguments don't have to special-case nil.
		args := p.Arguments
		if len(args) == 0 {
			args = json.RawMessage(`{}`)
		}
		result, rpcErr := t.Run(r.Context(), s.deps, args)
		if rpcErr != nil {
			// Tool-level errors come back as a successful
			// JSON-RPC envelope with isError:true so the client
			// model can read the message rather than handle a
			// transport failure. Spec §Tools/Errors.
			return callToolResult{
				Content: []content{{Type: "text", Text: rpcErr.Message}},
				IsError: true,
			}, nil
		}
		text, err := encodeText(result)
		if err != nil {
			slog.ErrorContext(r.Context(), "mcp: encode tool result", "tool", p.Name, "err", err)
			return nil, internalError("could not encode tool result")
		}
		return callToolResult{Content: []content{{Type: "text", Text: text}}}, nil
	}
	return nil, &Error{
		Code:    codeMethodNotFound,
		Message: "tool not found: " + p.Name,
	}
}

func encodeText(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// requireService is the shared "this surface isn't wired" guard. A
// deployment that disables traffic recording or proposal review
// keeps the MCP endpoint mounted but the dependent tools refuse
// with a clear message rather than a confusing nil-deref.
func requireService(present bool, what string) *Error {
	if present {
		return nil
	}
	return &Error{
		Code:    codeMethodNotFound,
		Message: "this deployment has no " + what + " configured",
	}
}

// ---- read-only tool runners ----------------------------------------

func runListAPIs(_ context.Context, deps Deps, _ json.RawMessage) (any, *Error) {
	specs := deps.Runtime.APISpecs()
	out := make([]apiSummary, 0, len(specs))
	for _, s := range specs {
		row := apiSummary{API: s}
		if bundle, ok := deps.APIBundle[s.Name]; ok {
			row.Bundle = bundle
			if _, has := deps.BundleReadmes[bundle]; has {
				row.ReadmeURI = BundleReadmeURI(bundle)
			}
		}
		out = append(out, row)
	}
	return map[string]any{"apis": out}, nil
}

// apiSummary embeds the raw API spec and adds the bundle pointers so
// an MCP client sees the same fields as `/_api/apis` without us
// duplicating the `models.API` projection. Embedding rather than a
// hand-rolled mirror means new schema fields surface automatically.
type apiSummary struct {
	*models.API
	Bundle    string `json:"bundle,omitempty"`
	ReadmeURI string `json:"readme_uri,omitempty"`
}

type listPoliciesArgs struct {
	API string `json:"api,omitempty"`
}

func runListPolicies(_ context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.PolicyService != nil, "policy service"); e != nil {
		return nil, e
	}
	var args listPoliciesArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	all := deps.PolicyService.List()
	if args.API == "" {
		return map[string]any{"policies": all}, nil
	}
	out := make([]models.Policy, 0, len(all))
	for _, p := range all {
		if p.API == args.API {
			out = append(out, p)
		}
	}
	return map[string]any{"policies": out}, nil
}

type policyKeyArgs struct {
	API  string `json:"api"`
	Name string `json:"name"`
}

func runGetPolicy(_ context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.PolicyService != nil, "policy service"); e != nil {
		return nil, e
	}
	var args policyKeyArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	if args.API == "" || args.Name == "" {
		return nil, invalidParams("api and name are required")
	}
	p, err := deps.PolicyService.Get(args.API, args.Name)
	if err != nil {
		return nil, mapPolicyError(err)
	}
	return p, nil
}

type dryRunResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func runDryRunPolicy(_ context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.PolicyService != nil, "policy service"); e != nil {
		return nil, e
	}
	var p models.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalidParams("decode policy: %v", err)
	}
	if err := deps.PolicyService.Validate(&p); err != nil {
		return dryRunResult{OK: false, Error: err.Error()}, nil
	}
	return dryRunResult{OK: true}, nil
}

type listProposalsArgs struct {
	Status string `json:"status,omitempty"`
	API    string `json:"api,omitempty"`
}

func runListProposals(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.ProposalService != nil, "proposal service"); e != nil {
		return nil, e
	}
	var args listProposalsArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	out, err := deps.ProposalService.List(ctx, proposals.ListOpts{
		Status: proposals.Status(args.Status),
		API:    args.API,
	})
	if err != nil {
		return nil, internalError("list proposals: " + err.Error())
	}
	return map[string]any{"proposals": out}, nil
}

type proposalIDArgs struct {
	ID string `json:"id"`
}

func runGetProposal(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.ProposalService != nil, "proposal service"); e != nil {
		return nil, e
	}
	var args proposalIDArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	if args.ID == "" {
		return nil, invalidParams("id is required")
	}
	p, err := deps.ProposalService.Get(ctx, proposals.ProposalID(args.ID))
	if err != nil {
		return nil, mapProposalError(err)
	}
	return p, nil
}

type listTrafficArgs struct {
	API        string `json:"api,omitempty"`
	Action     string `json:"action,omitempty"`
	Method     string `json:"method,omitempty"`
	Decision   string `json:"decision,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
	Pinned     bool   `json:"pinned,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

func runListTraffic(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.TrafficStore != nil, "traffic store"); e != nil {
		return nil, e
	}
	var args listTrafficArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	rows, _, err := deps.TrafficStore.List(ctx, traffic.ListOpts{
		API:        args.API,
		Action:     args.Action,
		Method:     args.Method,
		Decision:   traffic.Decision(args.Decision),
		PathPrefix: args.PathPrefix,
		PinnedOnly: args.Pinned,
		Limit:      args.Limit,
	})
	if err != nil {
		return nil, internalError("list traffic: " + err.Error())
	}
	return map[string]any{"rows": rows}, nil
}

type trafficIDArgs struct {
	ID string `json:"id"`
}

func runGetTrafficEvent(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.TrafficStore != nil, "traffic store"); e != nil {
		return nil, e
	}
	var args trafficIDArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	if args.ID == "" {
		return nil, invalidParams("id is required")
	}
	ev, err := deps.TrafficStore.Get(ctx, traffic.EventID(args.ID))
	if err != nil {
		return nil, mapTrafficError(err)
	}
	return ev, nil
}

// ---- write tool runners --------------------------------------------

type proposePolicyArgs struct {
	Kind      proposals.Kind `json:"kind,omitempty"`
	Policy    models.Policy  `json:"policy"`
	Rationale string         `json:"rationale,omitempty"`
}

func runProposePolicy(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.ProposalService != nil, "proposal service"); e != nil {
		return nil, e
	}
	var args proposePolicyArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	caller := auth.CallerFromContext(ctx)
	created, err := deps.ProposalService.Create(ctx, proposals.CreateInput{
		Kind:      args.Kind,
		Policy:    args.Policy,
		Author:    caller.Subject,
		Rationale: args.Rationale,
		Origin:    proposals.Origin{Kind: proposals.OriginAgent, Agent: caller.Subject},
	})
	if err != nil {
		return nil, mapProposalError(err)
	}
	return created, nil
}

type proposePolicyDeletionArgs struct {
	API       string `json:"api"`
	Name      string `json:"name"`
	Rationale string `json:"rationale,omitempty"`
}

// runProposePolicyDeletion is the shorthand: only api+name+rationale,
// kind is hardcoded to delete. Cuts boilerplate for the common case
// where the agent already knows the (api, name) of a policy it wants
// gone — no need to package an empty `policy` body around it.
func runProposePolicyDeletion(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.ProposalService != nil, "proposal service"); e != nil {
		return nil, e
	}
	var args proposePolicyDeletionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	if args.API == "" || args.Name == "" {
		return nil, invalidParams("api and name are required")
	}
	caller := auth.CallerFromContext(ctx)
	created, err := deps.ProposalService.Create(ctx, proposals.CreateInput{
		Kind:      proposals.KindDelete,
		Policy:    models.Policy{API: args.API, Name: args.Name},
		Author:    caller.Subject,
		Rationale: args.Rationale,
		Origin:    proposals.Origin{Kind: proposals.OriginAgent, Agent: caller.Subject},
	})
	if err != nil {
		return nil, mapProposalError(err)
	}
	return created, nil
}

type approveProposalArgs struct {
	ID        string `json:"id"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

func runApproveProposal(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.ProposalService != nil, "proposal service"); e != nil {
		return nil, e
	}
	var args approveProposalArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	if args.ID == "" {
		return nil, invalidParams("id is required")
	}
	caller := auth.CallerFromContext(ctx)
	got, err := deps.ProposalService.Approve(ctx, proposals.ProposalID(args.ID), caller.Subject, args.Overwrite)
	if err != nil {
		return nil, mapProposalError(err)
	}
	return got, nil
}

type rejectProposalArgs struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

func runRejectProposal(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.ProposalService != nil, "proposal service"); e != nil {
		return nil, e
	}
	var args rejectProposalArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	if args.ID == "" {
		return nil, invalidParams("id is required")
	}
	caller := auth.CallerFromContext(ctx)
	got, err := deps.ProposalService.Reject(ctx, proposals.ProposalID(args.ID), caller.Subject, args.Reason)
	if err != nil {
		return nil, mapProposalError(err)
	}
	return got, nil
}

// ---- error mapping --------------------------------------------------

func mapPolicyError(err error) *Error {
	switch {
	case errors.Is(err, policies.ErrNotFound):
		return &Error{Code: codeInvalidParams, Message: "policy not found"}
	case errors.Is(err, policies.ErrInvalid), errors.Is(err, policies.ErrAPIPath):
		return &Error{Code: codeInvalidParams, Message: err.Error()}
	case errors.Is(err, policies.ErrConflict):
		return &Error{Code: codeInvalidParams, Message: err.Error()}
	case errors.Is(err, policies.ErrReadOnly):
		return &Error{Code: codeInvalidRequest, Message: err.Error()}
	default:
		return internalError(err.Error())
	}
}

func mapProposalError(err error) *Error {
	switch {
	case errors.Is(err, proposals.ErrNotFound):
		return &Error{Code: codeInvalidParams, Message: "proposal not found"}
	case errors.Is(err, proposals.ErrInvalid),
		errors.Is(err, proposals.ErrBadTransition):
		return &Error{Code: codeInvalidParams, Message: err.Error()}
	case errors.Is(err, proposals.ErrPolicyConflict):
		return &Error{Code: codeInvalidParams, Message: err.Error()}
	default:
		return internalError(err.Error())
	}
}

func mapTrafficError(err error) *Error {
	switch {
	case errors.Is(err, traffic.ErrNotFound):
		return &Error{Code: codeInvalidParams, Message: "traffic event not found"}
	default:
		return internalError(err.Error())
	}
}
