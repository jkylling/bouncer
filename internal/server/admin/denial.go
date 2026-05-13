package admin

import (
	"net/http"
)

// DenialResponse is the structured body emitted on access errors
// from the data plane (401/403/404). The shape is JSON so an
// agent can parse it programmatically; the `message` carries the
// human-readable summary, and `next_steps` points at the
// admin/control-plane endpoints the agent would want to consult to
// understand the rejection or change the rules.
type DenialResponse struct {
	// Ok is always false on a denial. Slack's API convention is
	// `{ok: bool, error: string}` and every official Slack SDK
	// branches on `body.ok`. Including it here lets a Slack-aware
	// client see a denial as a normal Slack-shaped error rather
	// than an unparseable response — a small affordance with no
	// cost on other consumers.
	Ok bool `json:"ok"`

	// Error mirrors http.StatusText for the status — present so a
	// generic JSON consumer can branch on it without parsing the
	// status line of the wrapping HTTP response.
	Error string `json:"error"`

	// Message is the human-readable explanation.
	Message string `json:"message"`

	// API is the registered API whose path-prefix claimed the
	// request. Populated on policy-deny (403) so an agent reading
	// the body knows where to author its proposal — empty on the
	// other denial paths (401, 404 no_match) where there is no
	// matched API to name.
	API string `json:"api,omitempty"`

	// MatchedActions are the action names whose match logic fired
	// on the request. On a policy-deny this is the set the agent
	// would draft a policy against. Empty otherwise (and elided on
	// the wire via omitempty).
	MatchedActions []string `json:"matched_actions,omitempty"`

	// NextSteps lists the admin endpoints the operator/agent can
	// hit to understand the proxy's surface and change the rules.
	NextSteps DenialNextSteps `json:"next_steps"`
}

// DenialNextSteps is the canonical "where do I go from here?"
// block. Every field is a relative URL on the same proxy origin —
// agents prefix the proxy's address themselves.
type DenialNextSteps struct {
	// SupportedAPIs lists every registered API + its actions.
	SupportedAPIs string `json:"supported_apis"`

	// Policies lists the live policy set.
	Policies string `json:"policies"`

	// Docs is the agent guide describing how to use the proxy.
	Docs string `json:"docs"`

	// DocsPolicies is the policy-authoring guide. An agent staring
	// at a 403 wants to draft a permitting policy; this is the
	// document with the schema, CEL primer, and worked examples.
	DocsPolicies string `json:"docs_policies"`
}

// WriteDenial emits a structured 401/403/404 body with `next_steps`
// pointing at the four discovery endpoints. Every field is filled
// in from the package's path constants so the response stays
// self-consistent if a path is renamed. The wire status doubles as
// the semantic label (so a 401 carries `error: "Unauthorized"`).
func WriteDenial(w http.ResponseWriter, status int, message string) {
	writeDenial(w, status, status, message, "", nil)
}

// WriteDenialDetail is the richer variant used by the data plane's
// policy-deny site: in addition to the standard fields, it
// surfaces the API the path routed to and the action names whose
// match logic fired on the request. An agent reading the body sees
// "your request matched these actions on API <X>; write or propose
// a policy that gates one of them" and has everything it needs to
// draft the fix without a follow-up GET /_api/apis.
//
// Pass api="" / matchedActions=nil and this collapses to the same
// body as WriteDenial — handy for the 401/404 sites where neither
// detail applies.
func WriteDenialDetail(w http.ResponseWriter, status int, message, api string, matchedActions []string) {
	writeDenial(w, status, status, message, api, matchedActions)
}

// WriteDenialRemapped is the variant used by the data plane when an
// API's `access_denied_status` override decouples the wire status
// from the semantic one. wireStatus drives the HTTP response line;
// semanticStatus drives the `error` label inside the body — so a
// Slack-shaped 200 still carries `error: "Forbidden"` (matching the
// natural deny) rather than the contradictory "OK" you'd get from
// http.StatusText(200).
func WriteDenialRemapped(w http.ResponseWriter, wireStatus, semanticStatus int, message, api string, matchedActions []string) {
	writeDenial(w, wireStatus, semanticStatus, message, api, matchedActions)
}

// writeDenial is the shared body-build path. Splitting wire and
// semantic statuses lets per-API access_denied_status overrides
// remap the response code without lying about *what kind of
// denial* it was — operators reading logs and clients reading the
// body see the same denial vocabulary regardless of wire framing.
func writeDenial(w http.ResponseWriter, wireStatus, semanticStatus int, message, api string, matchedActions []string) {
	body := DenialResponse{
		Error:          http.StatusText(semanticStatus),
		Message:        message,
		API:            api,
		MatchedActions: matchedActions,
		NextSteps: DenialNextSteps{
			SupportedAPIs: APIsPath,
			Policies:      PoliciesPath,
			Docs:          DocsPath,
			DocsPolicies:  DocsPoliciesPath,
		},
	}
	writeJSONStatus(w, wireStatus, "", body)
}

// StructuredErrorCredentialsNotStaged is the discriminator string an
// agent reads to know it should run the matching /{service}-token
// prompt. Stable wire constant.
const StructuredErrorCredentialsNotStaged = "credentials_not_staged"

// StructuredErrorServiceNotConnected is the discriminator string an
// agent reads to know it should surface the connect_url to the user.
// Stable wire constant.
const StructuredErrorServiceNotConnected = "service_not_connected"

// StructuredCredentialsNotStaged is the body emitted with HTTP 401
// when the proxy's upstream call returns 401 and the request routed
// to an API whose bundle declares a `token:` block. The agent reads
// `error` for the discriminator and re-runs the named prompt to
// re-stage. The shape is documented in
// plans/bouncer_service_token_prompts.md.
type StructuredCredentialsNotStaged struct {
	Error        string `json:"error"`
	Service      string `json:"service"`
	StagePrompt  string `json:"stage_prompt"`
	Message      string `json:"message,omitempty"`
	UpstreamBody string `json:"upstream_body,omitempty"`
}

// WriteCredentialsNotStaged emits a 401 with the structured body. The
// upstream's response body (if any) is preserved as `upstream_body`
// so operators tracing through bouncer can still see what the
// upstream returned.
func WriteCredentialsNotStaged(w http.ResponseWriter, service string, upstreamBody []byte) {
	body := StructuredCredentialsNotStaged{
		Error:       StructuredErrorCredentialsNotStaged,
		Service:     service,
		StagePrompt: "/" + service + "-token",
		Message:     "Re-run /" + service + "-token to refresh the stored " + service + " credential.",
	}
	if len(upstreamBody) > 0 && len(upstreamBody) <= 4096 {
		body.UpstreamBody = string(upstreamBody)
	}
	writeJSONStatus(w, http.StatusUnauthorized, "", body)
}

// StructuredServiceNotConnected is the body emitted when the proxy
// knows the tenant has not authorized the service at all (no stored
// connection). The MCP `get_{service}_token` tool surfaces the same
// shape in its tool-call error data field.
type StructuredServiceNotConnected struct {
	Error      string `json:"error"`
	Service    string `json:"service"`
	ConnectURL string `json:"connect_url,omitempty"`
	Message    string `json:"message,omitempty"`
}

// WriteServiceNotConnected emits a 401 with the structured body.
// connectURL may be empty when bouncer has no opinion about where to
// send the user — the agent will fall back to telling the user to
// authorize the service in the dashboard.
func WriteServiceNotConnected(w http.ResponseWriter, service, connectURL string) {
	writeJSONStatus(w, http.StatusUnauthorized, "", StructuredServiceNotConnected{
		Error:      StructuredErrorServiceNotConnected,
		Service:    service,
		ConnectURL: connectURL,
		Message:    "Connect " + service + " to bouncer to use this tool.",
	})
}
