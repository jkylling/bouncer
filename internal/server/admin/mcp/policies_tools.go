package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/proposals"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// policiesTools is the policies-family slice contributed to the
// registry. The first three are read-only; propose_policy is the
// write path the agent uses to recover from a 403 — admin callers
// see it land in the live runtime, non-admin callers get the
// validated draft back to surface to a human operator.
func policiesTools() []tool {
	return []tool{
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
			Name:        "propose_policy",
			Title:       "Propose a new policy",
			Description: "Validate a draft policy and, when the caller is admin, create it in the live runtime. Non-admin callers receive the validated policy back with applied=false so the agent can surface it to the operator. Conflict on (api, name) is reported with applied=false for both roles.",
			InputSchema: policyInputSchema(),
			Run:         runProposePolicy,
		},
	}
}

// policyInputSchema is the shared sub-schema for a policy body. Used
// by dry_run_policy and by propose_policy.
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

// proposePolicyResult is the response for propose_policy. `ok` mirrors
// dry_run_policy (compile success); `applied` says whether the policy
// landed in the live runtime (admin path); `proposal_id` is populated
// when the draft was enqueued on the proposals queue for human review.
type proposePolicyResult struct {
	OK         bool           `json:"ok"`
	Applied    bool           `json:"applied"`
	ProposalID string         `json:"proposal_id,omitempty"`
	Policy     *models.Policy `json:"policy,omitempty"`
	Message    string         `json:"message,omitempty"`
	Error      string         `json:"error,omitempty"`
}

func runProposePolicy(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.PolicyService != nil, "policy service"); e != nil {
		return nil, e
	}
	var p models.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalidParams("decode policy: %v", err)
	}
	if err := deps.PolicyService.Validate(&p); err != nil {
		return proposePolicyResult{OK: false, Error: err.Error()}, nil
	}
	// Conflict check runs for both roles so admin and non-admin paths
	// surface the same name-already-taken response shape.
	if _, err := deps.PolicyService.Get(p.API, p.Name); err == nil {
		return proposePolicyResult{
			OK:      true,
			Applied: false,
			Policy:  &p,
			Message: "Policy is valid but (api, name) already exists. Pick a different name or ask the operator to replace the existing policy.",
		}, nil
	}
	caller := auth.CallerFromContext(ctx)
	if !caller.IsAdmin() {
		// Non-admin: enqueue onto the proposals queue so an operator
		// can review at /_admin/proposals. nil ProposalService is the
		// legacy "just return the draft" behaviour.
		if deps.ProposalService == nil {
			return proposePolicyResult{
				OK:      true,
				Applied: false,
				Policy:  &p,
				Message: "Policy compiled cleanly. Surface this draft to the user; an operator with admin role must apply it.",
			}, nil
		}
		prop, err := deps.ProposalService.Create(ctx, proposals.CreateInput{
			Policy: p,
			Origin: proposals.Origin{Kind: proposals.OriginAgent, Agent: caller.Subject},
			Author: caller.Subject,
		})
		if err != nil {
			return nil, internalError(err.Error())
		}
		return proposePolicyResult{
			OK:         true,
			Applied:    false,
			ProposalID: prop.ID.String(),
			Policy:     &p,
			Message:    "Draft enqueued for review at /_admin/proposals (id " + prop.ID.String() + ").",
		}, nil
	}
	if err := deps.PolicyService.Create(ctx, &p); err != nil {
		return nil, mapPolicyError(err)
	}
	return proposePolicyResult{
		OK:      true,
		Applied: true,
		Policy:  &p,
		Message: "Policy created and applied to the live runtime.",
	}, nil
}

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
