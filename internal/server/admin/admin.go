// Package admin owns the bouncer control-plane HTTP routes — the
// human-facing UI under `/_admin/...` and the JSON API families under
// `/_api/...`. Each surface has its own Mount* entry point (login,
// whoami, apis, docs, traffic, policies, services, tokens) so the
// parent server composes them piecemeal.
package admin

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Path constants are exported so the parent server (and tests) can
// refer to them without re-stating the strings — and so a future
// rename can be made in one place.
const (
	UIPath = "/_admin"
)

// MountOn wires the dashboard entry redirects. The JWT issue
// endpoints live with the tokens page (MountTokensPage:
// /_api/tokens/issue + /_api/tokens/issue/refresh); other admin
// surfaces (login, whoami, apis, docs, traffic, policies) have their
// own Mount* entry points. Admin gating happens uniformly via
// InternalPolicyMiddleware, so every Mount* site is plain
// `r.Method(path, handler)`.
func MountOn(r chi.Router) {
	r.Get(UIPath, http.RedirectHandler("/_admin/services", http.StatusSeeOther).ServeHTTP)
	r.Get(UIPath+"/", http.RedirectHandler("/_admin/services", http.StatusSeeOther).ServeHTTP)
}
