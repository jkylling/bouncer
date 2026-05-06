package admin

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/proposals"
	"github.com/jkylling/bouncer/internal/control/propose"
	"github.com/jkylling/bouncer/internal/control/traffic"
)

// ProposePolicyPath is the per-event sub-resource for the
// "render a policy from this request" flow. A sub-resource (rather
// than a Google-style `:proposePolicy` colon suffix) keeps chi's
// path matching straightforward.
const ProposePolicyPath = "/_api/traffic/{id}/propose-policy"

// MaxProposeBodyBytes caps the JSON body the propose handler reads.
// The body is small (a list of paths + a few flags); 16 KiB is more
// than enough.
const MaxProposeBodyBytes int64 = 1 << 14

// MountPropose attaches the propose-policy endpoint. proposalSvc is
// optional — when nil the endpoint still serves previews but submit=
// true returns 501. The traffic store is required (we need the
// recorded Event to render against).
//
// Tier wiring: any authenticated caller may propose. The handler
// reads the recorded event, which already lives behind the
// admin-tier traffic reads — so a non-admin's only way to reach an
// event id today is to know it (e.g. from a denial body). Subject
// scoping (only your own request) is layered in phase 5.
func MountPropose(r chi.Router, store traffic.Store, engine *propose.Engine, proposalSvc *proposals.Service) {
	r.Post(ProposePolicyPath, RequireAuthenticated(proposePolicyHandler(store, engine, proposalSvc)))
}

// proposeResponse is what the handler returns. It always carries the
// rendered policy + field list (engine.Result); on `?submit=true` it
// also carries the persisted Proposal so the UI can navigate to the
// review tab without a follow-up GET.
type proposeResponse struct {
	propose.Result
	Proposal *proposals.Proposal `json:"proposal,omitempty"`
}

func proposePolicyHandler(store traffic.Store, engine *propose.Engine, proposalSvc *proposals.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Look up the recorded event first so a typo'd id 404s
		// before we waste a body decode.
		ev, err := store.Get(r.Context(), traffic.EventID(chi.URLParam(r, "id")))
		if err != nil {
			writeProposeError(r.Context(), w, err)
			return
		}

		// Subject scoping: an authenticated non-admin caller may
		// only propose against their own recorded requests. 404 (not
		// 403) so an agent can't probe for other subjects' event ids.
		caller := auth.CallerFromContext(r.Context())
		if !caller.IsAdmin() && (caller.Subject == "" || caller.Subject != ev.Subject) {
			writeProposeError(r.Context(), w, traffic.ErrNotFound)
			return
		}

		var in propose.Input
		if err := decodeJSONBody(w, r, MaxProposeBodyBytes, &in); err != nil {
			writeProposeError(r.Context(), w, err)
			return
		}

		out, err := engine.Propose(ev, in)
		if err != nil {
			writeProposeError(r.Context(), w, err)
			return
		}

		// Preview: 200 + the rendered policy / field list. The
		// submit branch returns early so this fall-through only
		// fires when ?submit=true was not asked for.
		if r.URL.Query().Get("submit") != "true" {
			writeJSONStatus(w, http.StatusOK, "", proposeResponse{Result: out})
			return
		}

		// Submit: validate prerequisites, persist via the proposal
		// service, return 201 + Location pointing at the new
		// review record. Submitting a known-bad policy is exactly
		// the foot-gun the strategy doc forbids ("we don't write
		// a non-compiling proposal even when called with
		// submit=true").
		if proposalSvc == nil {
			writeJSONError(w, "submit not configured (no proposal service)", http.StatusNotImplemented)
			return
		}
		if !out.CompileOK {
			writeJSONError(w, "refusing to submit: "+out.CompileError, http.StatusBadRequest)
			return
		}
		created, err := proposalSvc.Create(r.Context(), proposals.CreateInput{
			Policy: out.Policy,
			Origin: proposals.Origin{
				Kind:      proposals.OriginFromRequest,
				RequestID: ev.ID,
			},
			// Author left empty — the control plane is
			// unauthenticated for now (per the README/0.x trust
			// model). Once the JWT-with-admin scope gate lands,
			// plumb the subject through here.
			Rationale: "Generated from request " + ev.ID.String(),
		})
		if err != nil {
			writeProposeError(r.Context(), w, err)
			return
		}
		writeJSONStatus(w, http.StatusCreated, ProposalsPath+"/"+created.ID.String(),
			proposeResponse{Result: out, Proposal: &created})
	}
}

func writeProposeError(ctx context.Context, w http.ResponseWriter, err error) {
	writeMappedError(ctx, w, "propose", err, []errMap{
		{sentinel: traffic.ErrNotFound, status: http.StatusNotFound, msg: "not found"},
		{sentinel: propose.ErrNoAPI, status: http.StatusUnprocessableEntity},
		{sentinel: proposals.ErrInvalid, status: http.StatusBadRequest},
	})
}
