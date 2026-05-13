package admin

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/control/agents"
)

// Agent endpoint paths. Register is the one anonymous entry point
// (any client that can reach the server can ask for a slot); the
// rest are admin-only via the internal-policy set.
const (
	AgentsPath        = "/_api/agents"
	AgentRegisterPath = "/_api/agents/register"
	AgentItemPath     = "/_api/agents/{id}"
	AgentApprovePath  = "/_api/agents/{id}/approve"
	AgentRejectPath   = "/_api/agents/{id}/reject"

	// UI shells. The new connect-agent + list-agents page lives at
	// /_admin/agents (and /_admin/agents/new for the wizard step).
	// /_admin/ still serves the legacy tokens.tmpl.html for now.
	AgentsUIPath    = "/_admin/agents"
	AgentsNewUIPath = "/_admin/agents/new"
)

// MaxAgentBodyBytes caps the registration body. Harness + fingerprint
// are short strings; 4 KiB is plenty.
const MaxAgentBodyBytes int64 = 1 << 12

// MountAgents wires the agent endpoints to r. Approve / reject /
// list are admin-only via the internal-policy actions; register is
// open so an agent can post without holding any credential yet.
func MountAgents(r chi.Router, svc *agents.Store) {
	r.Post(AgentRegisterPath, registerAgentHandler(svc))
	r.Get(AgentsPath, listAgentsHandler(svc))
	r.Get(AgentItemPath, getAgentHandler(svc))
	r.Post(AgentApprovePath, approveAgentHandler(svc))
	r.Post(AgentRejectPath, rejectAgentHandler(svc))

	mountUIPage(r, AgentsUIPath, "agents")
	mountUIPage(r, AgentsNewUIPath, "agents")
}

type registerAgentRequest struct {
	Harness     string   `json:"harness"`
	Fingerprint string   `json:"fingerprint"`
	Name        string   `json:"name,omitempty"`
	Services    []string `json:"services,omitempty"`
}

func registerAgentHandler(svc *agents.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body registerAgentRequest
		if err := decodeJSONBody(w, r, MaxAgentBodyBytes, &body); err != nil {
			respondAgentError(w, r, err)
			return
		}
		rec, err := svc.RegisterWith(body.Harness, body.Fingerprint, agents.RegisterOpts{
			Name:     body.Name,
			Services: body.Services,
		})
		if err != nil {
			respondAgentError(w, r, err)
			return
		}
		writeJSONStatus(w, http.StatusCreated, "", rec)
	}
}

type listAgentsResponse struct {
	Agents []agents.Agent `json:"agents"`
}

func listAgentsHandler(svc *agents.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := svc.List()
		if err != nil {
			respondAgentError(w, r, err)
			return
		}
		writeJSON(w, listAgentsResponse{Agents: list})
	}
}

func getAgentHandler(svc *agents.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, err := svc.Get(chi.URLParam(r, "id"))
		if err != nil {
			respondAgentError(w, r, err)
			return
		}
		writeJSON(w, rec)
	}
}

func approveAgentHandler(svc *agents.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, err := svc.Approve(chi.URLParam(r, "id"))
		if err != nil {
			respondAgentError(w, r, err)
			return
		}
		writeJSON(w, rec)
	}
}

func rejectAgentHandler(svc *agents.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, err := svc.Reject(chi.URLParam(r, "id"))
		if err != nil {
			respondAgentError(w, r, err)
			return
		}
		writeJSON(w, rec)
	}
}

func respondAgentError(w http.ResponseWriter, r *http.Request, err error) {
	writeMappedError(r.Context(), w, "agents", err, []errMap{
		{sentinel: agents.ErrInvalid, status: http.StatusBadRequest},
		{sentinel: agents.ErrNotFound, status: http.StatusNotFound},
		{sentinel: agents.ErrNotPending, status: http.StatusConflict},
	})
}
