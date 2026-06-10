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
func (s *Server) mountControlPlane(r chi.Router) {
	admin.MountStatic(r)
	admin.MountOn(r)
	admin.MountLogin(r, s.keys, s.adminPasswordHash)
	admin.MountWhoami(r)
	admin.MountAPIs(r, s.runtime, s.bundleData)
	admin.MountDocs(r)
	admin.MountCA(r, s.mitmCAPath)
	admin.MountSettings(r)
	admin.MountServices(r, s.servicesRegistry)
	admin.MountTokensPage(r, s.keys, s.servicesRegistry)
	if s.trafficStore != nil {
		admin.MountTraffic(r, s.trafficStore, admin.AnonymousPrincipal)
	}
	if s.policyService != nil {
		admin.MountPolicies(r, s.policyService)
	}
	if s.proposalService != nil {
		admin.MountProposals(r, s.proposalService)
	}
	agentMD, policyMD, apiMD := admin.DocsBytes()
	mcp.New(mcp.Deps{
		Runtime:         s.runtime,
		PolicyService:   s.policyService,
		ProposalService: s.proposalService,
		TrafficStore:    s.trafficStore,
		BundleReadmes:   s.bundleData.Readmes,
		APIBundle:       s.bundleData.APIBundle,
		Docs: mcp.Docs{
			AgentGuide:      agentMD,
			PolicyAuthoring: policyMD,
			APIAuthoring:    apiMD,
		},
	}).Mount(r)
	// MCP-aware harnesses probe OAuth metadata + DCR before falling
	// back to a configured Bearer; intercept the probe paths so they
	// return a clean signal instead of being eaten by the data-plane
	// catchall and showing up as confusing "missing JWT" log lines.
	mcp.MountWellKnown(r)
	r.Method(http.MethodPost, oauth.Path, s.oauthHandler)
}
