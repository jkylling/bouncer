package admin

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
)

// WhoamiPath is the open endpoint that returns the caller principal
// as JSON. An anonymous caller gets all-zero fields, so the browser
// UI can ask "am I admin?" without forcing a 401 probe against an
// admin-only endpoint.
const WhoamiPath = "/_api/whoami"

// MountWhoami attaches the whoami endpoint. Open by design — there
// is nothing privileged to leak: the response only mirrors what the
// caller's own JWT already says.
func MountWhoami(r chi.Router) {
	r.Get(WhoamiPath, whoamiHandler())
}

// whoamiResponse is the JSON shape /_api/whoami returns. Stable
// fields: an absent JWT renders all three at their zero value.
type whoamiResponse struct {
	Subject       string `json:"subject"`
	Admin         bool   `json:"admin"`
	Authenticated bool   `json:"authenticated"`
}

func whoamiHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := auth.CallerFromContext(r.Context())
		writeJSON(w, whoamiResponse{
			Subject:       c.Subject,
			Admin:         c.IsAdmin(),
			Authenticated: c.IsAuthenticated(),
		})
	}
}
