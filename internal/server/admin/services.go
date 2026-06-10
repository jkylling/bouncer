package admin

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/control/services"
)

// Service-surface paths. Read-only — the tokens screen issues stateless
// JWTs via /_api/tokens/issue / /_api/tokens/issue/refresh; no per-service
// state is kept on the server.
const (
	ServicesPath    = "/_api/services"
	ServiceItemPath = "/_api/services/{slug}"

	// UI shells. Both shells read /_api/services in the browser, so
	// they need no per-request server-side data.
	ServicesUIPath      = "/_admin/services"
	ServiceDetailUIPath = "/_admin/services/{slug}"
)

// MountServices wires the /_api/services* endpoints + UI shells.
func MountServices(r chi.Router, svc *services.Registry) {
	r.Get(ServicesPath, listServicesHandler(svc))
	r.Get(ServiceItemPath, getServiceHandler(svc))

	mountUIPage(r, ServicesUIPath, "services")

	// Service detail bakes the resolved Descriptor into the rendered
	// HTML (no client-side fetch + Loading… placeholder) so the page
	// shows up populated on first paint.
	r.Get(ServiceDetailUIPath, serviceDetailUIHandler(svc))
	r.Get(ServiceDetailUIPath+"/", serviceDetailUIHandler(svc))
}

// serviceDetailUIExtra is the per-request bundle the service-detail
// template reads as `.Extra`.
type serviceDetailUIExtra struct {
	*services.Descriptor
	InitialLetter string
}

func serviceDetailUIHandler(svc *services.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		if svc == nil {
			http.NotFound(w, r)
			return
		}
		d, err := svc.Get(slug)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		initial := "?"
		for _, ch := range d.Title {
			initial = strings.ToUpper(string(ch))
			break
		}
		renderPageWith(w, "service_detail", serviceDetailUIExtra{
			Descriptor:    &d,
			InitialLetter: initial,
		})
	}
}

type listServicesResponse struct {
	Services []services.Descriptor `json:"services"`
}

func listServicesHandler(svc *services.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if svc == nil {
			writeJSON(w, listServicesResponse{Services: []services.Descriptor{}})
			return
		}
		writeJSON(w, listServicesResponse{Services: svc.List()})
	}
}

func getServiceHandler(svc *services.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			respondServiceError(w, r, services.ErrUnknown)
			return
		}
		d, err := svc.Get(chi.URLParam(r, "slug"))
		if err != nil {
			respondServiceError(w, r, err)
			return
		}
		writeJSON(w, d)
	}
}

func respondServiceError(w http.ResponseWriter, r *http.Request, err error) {
	writeMappedError(r.Context(), w, "services", err, []errMap{
		{sentinel: services.ErrUnknown, status: http.StatusNotFound},
	})
}
