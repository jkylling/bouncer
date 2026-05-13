package admin

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/control/connections"
)

// Connection endpoint paths. Providers is read-only and reports
// per-provider connect-mode availability so the wizard's two-tab
// panel knows whether to grey out "Use your own OAuth client."
const (
	ConnectionsPath          = "/_api/connections"
	ConnectionItemPath       = "/_api/connections/{provider}"
	ConnectionsProvidersPath = "/_api/connections/providers"
)

// MaxConnectionBodyBytes caps the JSON the create endpoint reads.
// A credentials triple is a few hundred bytes; 16 KiB is generous.
const MaxConnectionBodyBytes int64 = 1 << 14

// MountConnections attaches the connections endpoints to r, backed
// by svc. Providers reports availability derived from the env map
// the caller passed at construction time (so request-time env
// changes don't flicker the UI mid-session).
func MountConnections(r chi.Router, svc *connections.Store, providersInfo map[string]connections.ProviderInfo) {
	r.Get(ConnectionsProvidersPath, listProvidersHandler(providersInfo))
	r.Get(ConnectionsPath, listConnectionsHandler(svc))
	r.Post(ConnectionItemPath, putConnectionHandler(svc))
	r.Delete(ConnectionItemPath, deleteConnectionHandler(svc))
}

type providersResponse struct {
	Providers map[string]connections.ProviderInfo `json:"providers"`
}

func listProvidersHandler(info map[string]connections.ProviderInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, providersResponse{Providers: info})
	}
}

type connectionsListResponse struct {
	Connections []connections.Connection `json:"connections"`
}

func listConnectionsHandler(svc *connections.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := svc.List()
		if err != nil {
			respondConnectionError(w, r, err)
			return
		}
		writeJSON(w, connectionsListResponse{Connections: list})
	}
}

// putConnectionRequest accepts a flat credentials triple, the shape
// `bouncer issue-token --credentials-file` reads. Operators paste
// that JSON directly from the GCP / Slack console into the wizard.
type putConnectionRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	TokenURL     string `json:"token_url,omitempty"`
}

func putConnectionHandler(svc *connections.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body putConnectionRequest
		if err := decodeJSONBody(w, r, MaxConnectionBodyBytes, &body); err != nil {
			respondConnectionError(w, r, err)
			return
		}
		creds := connections.Credentials{
			ClientID:     body.ClientID,
			ClientSecret: body.ClientSecret,
			RefreshToken: body.RefreshToken,
			TokenURL:     body.TokenURL,
		}
		provider := chi.URLParam(r, "provider")
		rec, err := svc.Put(provider, creds)
		if err != nil {
			respondConnectionError(w, r, err)
			return
		}
		writeJSONStatus(w, http.StatusCreated, "", rec)
	}
}

func deleteConnectionHandler(svc *connections.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Delete(chi.URLParam(r, "provider")); err != nil {
			respondConnectionError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func respondConnectionError(w http.ResponseWriter, r *http.Request, err error) {
	writeMappedError(r.Context(), w, "connections", err, []errMap{
		{sentinel: connections.ErrUnknown, status: http.StatusBadRequest},
		{sentinel: connections.ErrInvalid, status: http.StatusBadRequest},
		{sentinel: connections.ErrNotFound, status: http.StatusNotFound},
	})
}
