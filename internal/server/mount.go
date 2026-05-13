package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/server/admin"
	"github.com/jkylling/bouncer/internal/server/admin/mcp"
	"github.com/jkylling/bouncer/internal/server/oauth"
)

// mountControlPlane wires every /_admin, /_api, and /.well-known
// route onto r. Each surface is gated on the dependency it needs:
// nil store / service leaves the matching routes unmounted, so a
// stripped-down deployment doesn't expose stubs that 503.
//
// Admin / MCP / OAuth all sit here together because they are the
// operator and agent control surfaces — the data-plane proxy
// catchall is mounted separately by mountDataPlane.
func (s *Server) mountControlPlane(r chi.Router) {
	admin.MountStatic(r)
	admin.MountOn(r, s.keys)
	admin.MountLogin(r, s.keys, s.adminPasswordHash)
	admin.MountWhoami(r)
	admin.MountAPIs(r, s.runtime, s.bundleData)
	admin.MountDocs(r)
	admin.MountCA(r, s.mitmCAPath)
	admin.MountInstall(r, s.mitmCAPath)
	admin.MountSettings(r)
	admin.MountOnboarding(r)
	admin.MountRecipes(r, s.policyService)
	if s.connectionStore != nil {
		admin.MountConnections(r, s.connectionStore, s.providersInfo)
	}
	if s.agentStore != nil {
		admin.MountAgents(r, s.agentStore)
	}
	// /_api/services is the surface the new Services UI consumes.
	// Always mounted — when the registry is nil it returns an empty
	// list rather than 404ing the route.
	admin.MountServices(r, s.servicesRegistry, s.connectionStore, s.policyService)
	if s.trafficStore != nil {
		admin.MountTraffic(r, s.trafficStore, admin.AnonymousPrincipal)
	}
	if s.policyService != nil {
		admin.MountPolicies(r, s.policyService)
	}
	// MCP server sits at /_api/mcp and re-projects the surfaces
	// above as JSON-RPC tools + resources. RequireAuthenticated /
	// admin gating happens inside the tool runners (mirroring the
	// HTTP-side discipline) so the bare endpoint stays accessible
	// for tools/list discovery.
	agentMD, policyMD, apiMD := admin.DocsBytes()
	mcp.New(mcp.Deps{
		Runtime:         s.runtime,
		PolicyService:   s.policyService,
		TrafficStore:    s.trafficStore,
		BundleReadmes:   s.bundleData.Readmes,
		APIBundle:       s.bundleData.APIBundle,
		TokenBundles:    s.bundleData.TokenBundles,
		ConnectionStore: s.connectionStore,
		Keys:            s.keys,
		SeenTracker:     s.seenTracker,
		Docs: mcp.Docs{
			AgentGuide:      agentMD,
			PolicyAuthoring: policyMD,
			APIAuthoring:    apiMD,
		},
	}).Mount(r)
	if s.seenTracker != nil {
		admin.MountAgentsSeen(r, s.seenTracker)
	}
	// MCP-aware harnesses probe OAuth metadata + DCR before falling
	// back to a configured Bearer; intercept the probe paths so they
	// return a clean signal instead of being eaten by the data-plane
	// catchall and showing up as confusing "missing JWT" log lines.
	mcp.MountWellKnown(r)
	r.Method(http.MethodPost, oauth.Path, s.oauthHandler)
}
