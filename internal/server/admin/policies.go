package admin

import (
	"context"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Policy endpoint paths. The collection lives at `/_api/policies`,
// items at `/_api/policies/{api}/{name}`, `:dryRun` is a literal
// sub-resource (Google-style) for compile-without-persist, and
// `:capabilities` reports whether the underlying store accepts writes.
const (
	PoliciesPath             = "/_api/policies"
	PolicyItemPath           = "/_api/policies/{api}/{name}"
	PoliciesDryRunPath       = "/_api/policies:dryRun"
	PoliciesCapabilitiesPath = "/_api/policies:capabilities"
	PoliciesUIPath           = "/_admin/policies"
)

// MaxPolicyBodyBytes caps the JSON body the policy endpoints read.
// One policy is a few hundred bytes; 64 KiB is generous and still
// shields the proxy from a hostile body that's just trying to OOM.
const MaxPolicyBodyBytes int64 = 1 << 16

// MountPolicies attaches the policy CRUD endpoints to r, backed by
// svc. Following the MountTraffic pattern: the parent server
// constructs the dependency and calls this only when policy CRUD is
// wanted (it's a no-op otherwise).
//
// Tier wiring:
//   - :capabilities is open so the UI can decide whether to render
//     edit affordances before the operator logs in.
//   - List, Get, dryRun require any authenticated caller — policies
//     are the rules being applied to them, so non-admins can read.
//   - Create / Replace / Delete require admin — only operators
//     change the rule set.
//   - The HTML shell is open so the login JS can render.
func MountPolicies(r chi.Router, svc *policies.Service) {
	r.Get(PoliciesCapabilitiesPath, capabilitiesHandler(svc))
	r.Get(PoliciesPath, RequireAuthenticated(listPoliciesHandler(svc)))
	r.Get(PolicyItemPath, RequireAuthenticated(getPolicyHandler(svc)))
	r.Post(PoliciesDryRunPath, RequireAuthenticated(dryRunPolicyHandler(svc)))
	r.Post(PoliciesPath, RequireAdmin(createPolicyHandler(svc)))
	r.Put(PolicyItemPath, RequireAdmin(replacePolicyHandler(svc)))
	r.Delete(PolicyItemPath, RequireAdmin(deletePolicyHandler(svc)))
	mountUIPage(r, PoliciesUIPath, "policies")
}

// capabilitiesResponse is the GET /_api/policies:capabilities body.
// `writeable` drives whether the UI exposes create/edit/delete
// affordances; a future field (e.g. backend kind) can be added without
// breaking clients that only read this one.
type capabilitiesResponse struct {
	Writeable bool `json:"writeable"`
}

func capabilitiesHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, capabilitiesResponse{Writeable: svc.Writeable()})
	}
}

// policiesListResponse is the GET /_api/policies body. Wrapped in an
// object so a future field (pagination, version) can be added without
// breaking clients that decoded a bare array.
type policiesListResponse struct {
	Policies []models.Policy `json:"policies"`
}

func listPoliciesHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("api")
		all := svc.List()
		if filter != "" {
			// Build a fresh slice rather than filter in place: even
			// though Service.List returns a fresh snapshot today, a
			// future copy-on-write or interned-slice optimisation
			// would silently turn this into shared-state mutation.
			out := make([]models.Policy, 0, len(all))
			for _, p := range all {
				if p.API == filter {
					out = append(out, p)
				}
			}
			all = out
		}
		writeJSON(w, policiesListResponse{Policies: all})
	}
}

func getPolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api := chi.URLParam(r, "api")
		name := chi.URLParam(r, "name")
		p, err := svc.Get(api, name)
		if err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		writeJSON(w, p)
	}
}

func createPolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p models.Policy
		if err := decodeJSONBody(w, r, MaxPolicyBodyBytes, &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		if err := svc.Create(r.Context(), &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		// URL-escape both segments: p.API and p.Name come from the
		// caller's JSON body. validAPIName / validPolicyName reject
		// CRLF and other unsafe characters at validate time, but
		// path-escaping defends against a future schema relaxation
		// silently re-opening response-header injection.
		writeJSONStatus(w, http.StatusCreated,
			PoliciesPath+"/"+url.PathEscape(p.API)+"/"+url.PathEscape(p.Name), p)
	}
}

func replacePolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api := chi.URLParam(r, "api")
		name := chi.URLParam(r, "name")
		var p models.Policy
		if err := decodeJSONBody(w, r, MaxPolicyBodyBytes, &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		if err := svc.Replace(r.Context(), api, name, &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		writeJSON(w, p)
	}
}

func deletePolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api := chi.URLParam(r, "api")
		name := chi.URLParam(r, "name")
		if err := svc.Delete(r.Context(), api, name); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// dryRunPolicyHandler validates a policy against the live runtime
// without persisting or applying it. UIs call this on every keystroke
// for live feedback, so the response is JSON-shaped (a structured
// error rather than a bare 400 body) on the *compile* path.
// "Couldn't decode the request at all" — body too large, malformed
// JSON, unknown field — surfaces as the same 4xx the Create / Replace
// paths return, so a future shared HTTP client that retries on 4xx
// vs. 200 doesn't retry-storm against a malformed payload.
func dryRunPolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p models.Policy
		if err := decodeJSONBody(w, r, MaxPolicyBodyBytes, &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		if err := svc.Validate(&p); err != nil {
			writeJSON(w, dryRunResponse{OK: false, Error: err.Error()})
			return
		}
		writeJSON(w, dryRunResponse{OK: true})
	}
}

// dryRunResponse is the JSON shape POST /_api/policies:dryRun returns.
// `ok=false` always carries a human-readable error message; `ok=true`
// has neither.
type dryRunResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func writePolicyError(ctx context.Context, w http.ResponseWriter, err error) {
	writeMappedError(ctx, w, "policies", err, []errMap{
		{sentinel: policies.ErrInvalid, status: http.StatusBadRequest},
		{sentinel: policies.ErrAPIPath, status: http.StatusBadRequest},
		{sentinel: policies.ErrConflict, status: http.StatusConflict},
		{sentinel: policies.ErrNotFound, status: http.StatusNotFound, msg: "not found"},
		{sentinel: policies.ErrReadOnly, status: http.StatusForbidden},
	})
}
