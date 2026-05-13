// Package admin owns the bouncer control-plane HTTP routes — the
// human-facing UI under `/_admin/...` and the JSON API families under
// `/_api/...`. Each surface has its own Mount* entry point (login,
// whoami, apis, docs, traffic, policies, proposals, propose) so the
// parent server composes them piecemeal.
package admin

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/tokens"
)

// Path constants are exported so the parent server (and tests) can
// refer to them without re-stating the strings — and so a future
// rename can be made in one place.
const (
	UIPath = "/_admin"

	// IssuePath is the access-JWT issue endpoint POSTed to from both
	// the embedded UI and external curl/CLI flows.
	IssuePath = "/_api/issue/tokens"

	// IssueRefreshPath wraps an upstream refresh token in a refresh
	// JWT — the bootstrap-side primitive that the credentials-file
	// path of `bouncer issue-token --credentials-file ...` builds on
	// (this endpoint is just the JWT-issue step, no credentials.json
	// bundling).
	IssueRefreshPath = "/_api/issue/refresh"
)

// maxIssueBodyBytes caps the JSON body the issue handler reads. The
// payload is one Spec — a few hundred bytes in practice — so 64 KiB
// is generous.
const maxIssueBodyBytes int64 = 1 << 16

// MountOn attaches the issue endpoints. Other admin surfaces
// (login, whoami, apis, docs, traffic, policies) have their own Mount*
// entry points. Redirects /_admin/ to /_admin/agents as the default
// dashboard entry point.
//
// Issuing an arbitrary access or refresh JWT is a
// privilege-escalation primitive; the admin gate now lives in the
// embedded internal-policy set rather than per-route wrappers, so
// every Mount* site is plain `r.Method(path, handler)` and gating
// happens uniformly via InternalPolicyMiddleware.
func MountOn(r chi.Router, keys *auth.ServerKeys) {
	r.Get(UIPath, http.RedirectHandler("/_admin/agents", http.StatusSeeOther).ServeHTTP)
	r.Get(UIPath+"/", http.RedirectHandler("/_admin/agents", http.StatusSeeOther).ServeHTTP)
	r.Post(IssuePath, issueHandler(keys))
	r.Post(IssueRefreshPath, issueRefreshHandler(keys))
}

// issueHandler returns the handler for POST /_api/issue/tokens. It
// decodes a `tokens.Spec` (the same struct cmd/issue-token reads
// from --credentials-file, so a payload from one source replays
// cleanly through the other), validates, and signs. Admin gating
// is enforced upstream by InternalPolicyMiddleware against the
// `tokens_issue` action.
func issueHandler(keys *auth.ServerKeys) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var spec tokens.Spec
		if err := decodeJSONBody(w, r, maxIssueBodyBytes, &spec); err != nil {
			respondIssueError(w, r, err)
			return
		}
		res, err := tokens.Issue(r.Context(), keys, &spec)
		if err != nil {
			respondIssueError(w, r, err)
			return
		}
		writeJSON(w, IssueResponse{
			Token:     res.Token,
			ExpiresAt: res.ExpiresAt,
		})
	}
}

// issueRefreshHandler is the refresh-JWT counterpart to issueHandler.
// Wraps an upstream refresh token in a refresh JWT — same shape on
// the wire, ttl_seconds=0 yields a non-expiring token (in which case
// expires_at is omitted from the response).
func issueRefreshHandler(keys *auth.ServerKeys) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var spec tokens.RefreshSpec
		if err := decodeJSONBody(w, r, maxIssueBodyBytes, &spec); err != nil {
			respondIssueError(w, r, err)
			return
		}
		res, err := tokens.IssueRefresh(r.Context(), keys, &spec)
		if err != nil {
			respondIssueError(w, r, err)
			return
		}
		out := IssueRefreshResponse{Token: res.Token}
		if !res.ExpiresAt.IsZero() {
			out.ExpiresAt = &res.ExpiresAt
		}
		writeJSON(w, out)
	}
}

// Internal errors surface as generic 500 (logged) so an
// unauthenticated caller can't probe HKDF/AEAD details.
func respondIssueError(w http.ResponseWriter, r *http.Request, err error) {
	writeMappedError(r.Context(), w, "issue", err, []errMap{
		{sentinel: tokens.ErrInvalidSpec, status: http.StatusBadRequest},
	})
}

// IssueResponse is the JSON shape POST /_api/issue/tokens returns on
// success. Exported so external callers (and the integration test
// living in the parent package) can decode without restating the
// shape.
type IssueResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssueRefreshResponse is the JSON shape POST /_api/issue/refresh
// returns. ExpiresAt is a pointer so a non-expiring refresh JWT
// omits the field on the wire (rather than carrying a misleading
// 0001-01-01 timestamp).
type IssueRefreshResponse struct {
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}
