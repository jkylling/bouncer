package admin

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/proposals"
)

// Proposal endpoint paths. Approve/reject are sub-resources rather
// than the Google-style `:verb` suffix because chi splits routes on
// `/` and a literal-after-param segment is more readable than a
// regex-constrained parameter would be.
const (
	ProposalsPath       = "/_api/proposals"
	ProposalItemPath    = "/_api/proposals/{id}"
	ProposalApprovePath = "/_api/proposals/{id}/approve"
	ProposalRejectPath  = "/_api/proposals/{id}/reject"
	ProposalsUIPath     = "/_admin/proposals"
)

// MaxProposalBodyBytes caps the JSON body the proposal endpoints
// accept. A proposal carries one policy + a few text fields; the same
// 64 KiB cap as the policy endpoints is plenty.
const MaxProposalBodyBytes int64 = 1 << 16

// MountProposals attaches the proposal endpoints to r, backed by svc.
// Same pattern as MountPolicies: the parent server constructs the
// dependency and calls this only when proposals are wanted.
//
// Per-route access tiers live in the embedded internal-policy set
// (proposals_create / proposals_approve / ...). Subject scoping
// (a non-admin caller only sees their own proposals) still happens
// inside the handlers via the Caller in ctx.
func MountProposals(r chi.Router, svc *proposals.Service) {
	r.Get(ProposalsPath, listProposalsHandler(svc))
	r.Post(ProposalsPath, createProposalHandler(svc))
	r.Get(ProposalItemPath, getProposalHandler(svc))
	r.Patch(ProposalItemPath, updateProposalHandler(svc))
	r.Delete(ProposalItemPath, deleteProposalHandler(svc))
	r.Post(ProposalApprovePath, approveProposalHandler(svc))
	r.Post(ProposalRejectPath, rejectProposalHandler(svc))
	mountUIPage(r, ProposalsUIPath, "proposals")
}

// proposalsListResponse wraps the list so a future field
// (pagination, version) can be added without breaking clients that
// decoded a bare array.
type proposalsListResponse struct {
	Proposals []proposals.Proposal `json:"proposals"`
}

// listProposalsHandler scopes the listing to the caller's subject
// for non-admin callers — a reviewer sees the full set, an agent
// sees only its own drafts. Status / API filters compose with the
// scope.
func listProposalsHandler(svc *proposals.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := auth.CallerFromContext(r.Context())
		opts := proposals.ListOpts{
			Status: proposals.Status(r.URL.Query().Get("status")),
			API:    r.URL.Query().Get("api"),
		}
		out, err := svc.List(r.Context(), opts)
		if err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		if !caller.IsAdmin() {
			out = filterProposalsBySubject(out, caller.Subject)
		}
		writeJSON(w, proposalsListResponse{Proposals: out})
	}
}

// getProposalHandler 404s a non-admin caller asking about another
// subject's proposal — same shape as TrafficGet's cross-subject
// guard. 404 (not 403) so an agent can't probe id namespaces.
func getProposalHandler(svc *proposals.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := auth.CallerFromContext(r.Context())
		p, err := svc.Get(r.Context(), proposals.ProposalID(chi.URLParam(r, "id")))
		if err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		if !callerCanSeeProposal(caller, p) {
			writeProposalError(r.Context(), w, proposals.ErrNotFound)
			return
		}
		writeJSON(w, p)
	}
}

// createProposalHandler stamps the JWT subject onto the created
// proposal's Author field so a non-admin caller can't masquerade as
// someone else. Admins keep the body's Author (so an operator
// re-importing drafts on behalf of another agent still works).
func createProposalHandler(svc *proposals.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in proposals.CreateInput
		if err := decodeJSONBody(w, r, MaxProposalBodyBytes, &in); err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		caller := auth.CallerFromContext(r.Context())
		if !caller.IsAdmin() {
			in.Author = caller.Subject
		}
		p, err := svc.Create(r.Context(), in)
		if err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		writeJSONStatus(w, http.StatusCreated, ProposalsPath+"/"+p.ID.String(), p)
	}
}

func updateProposalHandler(svc *proposals.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in proposals.UpdateInput
		if err := decodeJSONBody(w, r, MaxProposalBodyBytes, &in); err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		id := proposals.ProposalID(chi.URLParam(r, "id"))
		if err := ensureCallerCanModify(r.Context(), svc, id); err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		p, err := svc.Update(r.Context(), id, in)
		if err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		writeJSON(w, p)
	}
}

func deleteProposalHandler(svc *proposals.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := proposals.ProposalID(chi.URLParam(r, "id"))
		if err := ensureCallerCanModify(r.Context(), svc, id); err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		if err := svc.Delete(r.Context(), id); err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ensureCallerCanModify implements the non-admin scope guard the
// update + delete paths share. Admins skip the check; everyone else
// must own the proposal. A row the caller cannot see surfaces as
// ErrNotFound — same shape as a real miss, so a non-admin can't
// distinguish "missing" from "not yours" via probe.
//
// There is still a small TOCTOU window between this Get and the
// caller's mutation; pushing the scope into proposals.Service would
// close it but requires a service-surface change.
func ensureCallerCanModify(ctx context.Context, svc *proposals.Service, id proposals.ProposalID) error {
	caller := auth.CallerFromContext(ctx)
	if caller.IsAdmin() {
		return nil
	}
	cur, err := svc.Get(ctx, id)
	if err != nil {
		return proposals.ErrNotFound
	}
	if !callerCanSeeProposal(caller, cur) {
		return proposals.ErrNotFound
	}
	return nil
}

// callerCanSeeProposal reports whether the caller is allowed to
// read or mutate the proposal. Admins see everything; everyone
// else sees only their own.
func callerCanSeeProposal(c auth.Caller, p proposals.Proposal) bool {
	if c.IsAdmin() {
		return true
	}
	return c.Subject != "" && p.Author == c.Subject
}

// filterProposalsBySubject returns only the entries whose Author
// matches subject. Empty subject (anonymous) returns the empty
// slice — the route gate already rejected anonymous so this is
// belt-and-suspenders.
func filterProposalsBySubject(in []proposals.Proposal, subject string) []proposals.Proposal {
	if subject == "" {
		return nil
	}
	out := make([]proposals.Proposal, 0, len(in))
	for _, p := range in {
		if p.Author == subject {
			out = append(out, p)
		}
	}
	return out
}

// approveBody is the POST .../approve payload.
type approveBody struct {
	By        string `json:"by"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

// rejectBody is the POST .../reject payload.
type rejectBody struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
}

func approveProposalHandler(svc *proposals.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body approveBody
		if err := decodeJSONBody(w, r, MaxProposalBodyBytes, &body); err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		// Approver identity is the JWT subject by default; the body's
		// `by` is only honoured when the caller explicitly overrides
		// (so an operator scripting bulk approvals on behalf of a
		// reviewer can still set it). Avoids the UI prompting for a
		// name the server already knows.
		if body.By == "" {
			body.By = auth.CallerFromContext(r.Context()).Subject
		}
		p, err := svc.Approve(r.Context(), proposals.ProposalID(chi.URLParam(r, "id")), body.By, body.Overwrite)
		if err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		writeJSON(w, p)
	}
}

func rejectProposalHandler(svc *proposals.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body rejectBody
		if err := decodeJSONBody(w, r, MaxProposalBodyBytes, &body); err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		if body.By == "" {
			body.By = auth.CallerFromContext(r.Context()).Subject
		}
		p, err := svc.Reject(r.Context(), proposals.ProposalID(chi.URLParam(r, "id")), body.By, body.Reason)
		if err != nil {
			writeProposalError(r.Context(), w, err)
			return
		}
		writeJSON(w, p)
	}
}

// The underlying policies layer's sentinels (ErrInvalid, ErrAPIPath,
// ErrReadOnly) reach here when an approve promotes a policy.
func writeProposalError(ctx context.Context, w http.ResponseWriter, err error) {
	writeMappedError(ctx, w, "proposals", err, []errMap{
		{sentinel: proposals.ErrInvalid, status: http.StatusBadRequest},
		{sentinel: policies.ErrInvalid, status: http.StatusBadRequest},
		{sentinel: policies.ErrAPIPath, status: http.StatusBadRequest},
		{sentinel: proposals.ErrNotFound, status: http.StatusNotFound, msg: "not found"},
		{sentinel: proposals.ErrBadTransition, status: http.StatusConflict},
		{sentinel: proposals.ErrPolicyConflict, status: http.StatusConflict},
		{sentinel: policies.ErrReadOnly, status: http.StatusForbidden},
	})
}
