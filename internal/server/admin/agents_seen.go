package admin

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/control/agentseen"
)

// AgentsSeenPath returns the in-memory roll-up of every Bearer-
// authenticated MCP caller the server has seen since boot. The
// dashboard's "Connected agents" card reads from this — the older
// `/_api/traffic/subjects` only sees subjects that made an upstream
// proxied call, so MCP-only agents never appeared there.
const AgentsSeenPath = "/_api/agents/seen"

// seenResponse mirrors the SubjectSummary wire shape so the
// dashboard's renderAgents() can swap fetch URLs without reshaping
// the JS.
type seenResponse struct {
	Subjects []agentseen.Sighting `json:"subjects"`
}

// MountAgentsSeen registers GET AgentsSeenPath against tracker.
// Internal policy gates the route as admin-readable; mounting is
// unconditional once a tracker exists.
func MountAgentsSeen(r chi.Router, tracker *agentseen.Tracker) {
	r.Get(AgentsSeenPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, seenResponse{Subjects: tracker.List()})
	})
}
