package admin

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Onboarding UI paths. The wizard re-skins the regular dashboard
// pages by passing ?onboarding=1 — the templates check the flag and
// surface a banner + a "continue" affordance pointing at the next
// step. Keeping the wizard's URL space distinct lets a deep link
// (from a CLI prompt, README, or MCP tool docstring) jump directly
// into a wizard-shaped flow without the operator first having to
// hunt for the right query param.
const (
	OnboardingPath         = "/_admin/onboarding"
	OnboardingConnectPath  = "/_admin/onboarding/connect"
	OnboardingPoliciesPath = "/_admin/onboarding/policies"
	OnboardingAgentPath    = "/_admin/onboarding/agent"
)

// MountOnboarding wires the wizard redirects. Each path forwards to
// the matching dashboard surface with ?onboarding=1; the page
// templates render an onboarding banner + an inline "continue" link
// when that flag is set.
func MountOnboarding(r chi.Router) {
	r.Get(OnboardingPath, redirectTo("/_admin/services?onboarding=1"))
	r.Get(OnboardingPath+"/", redirectTo("/_admin/services?onboarding=1"))
	// "connect" historically meant step-1 (pick a service); now we
	// just send the operator to the services list with the wizard
	// flag set, where they pick a card and land on the detail page.
	r.Get(OnboardingConnectPath, redirectTo("/_admin/services?onboarding=1"))
	r.Get(OnboardingConnectPath+"/", redirectTo("/_admin/services?onboarding=1"))
	// "policies" — the per-service policies tab. Without a slug we
	// route back to the service picker, which advances the operator
	// into the detail page (which renders the Policies tab when the
	// onboarding flag is set and the service is already connected).
	r.Get(OnboardingPoliciesPath, redirectTo("/_admin/services?onboarding=1"))
	r.Get(OnboardingPoliciesPath+"/", redirectTo("/_admin/services?onboarding=1"))
	// "agent" — connect-an-agent step.
	r.Get(OnboardingAgentPath, redirectTo("/_admin/agents/new?onboarding=1"))
	r.Get(OnboardingAgentPath+"/", redirectTo("/_admin/agents/new?onboarding=1"))
}

// redirectTo returns a handler that 303s to dest.
func redirectTo(dest string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest, http.StatusSeeOther)
	}
}
