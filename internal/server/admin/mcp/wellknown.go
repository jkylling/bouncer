package mcp

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// MCP-aware harnesses (Claude Code, Cursor, …) probe several
// well-known OAuth metadata paths and the dynamic-client-registration
// (DCR) endpoint as part of the spec's authorization flow:
//
//	GET  /.well-known/oauth-authorization-server
//	GET  /.well-known/openid-configuration
//	GET  /.well-known/oauth-protected-resource
//	GET  /.well-known/oauth-protected-resource/_api/mcp
//	POST /register
//
// Bouncer doesn't implement OAuth code-grant flow — its MCP endpoint
// uses pre-issued Bearer JWTs (the same ones the proxy already
// issues for the data plane). Without explicit handlers these paths
// fall through to the proxy data-plane catchall, which 401s with a
// "missing or invalid Authorization header — present a Bearer JWT
// issued by this proxy" message. Confusing for an OAuth-aware MCP
// client and noisy in the access log.
//
// MountWellKnown registers the probe paths with a clean 404 + a
// JSON body pointing at /_api/docs#mcp-integration. The MCP client
// gets an unambiguous "this resource isn't OAuth-discoverable; go
// configure a pre-issued Bearer" signal and the operator's logs
// stay readable.
func MountWellKnown(r chi.Router) {
	r.Get("/.well-known/oauth-authorization-server", handlerNotOAuth())
	r.Get("/.well-known/oauth-authorization-server/*", handlerNotOAuth())
	r.Get("/.well-known/openid-configuration", handlerNotOAuth())
	r.Get("/.well-known/oauth-protected-resource", handlerNotOAuth())
	r.Get("/.well-known/oauth-protected-resource/*", handlerNotOAuth())
	// Dynamic Client Registration (RFC 7591) — POST /register. We
	// intercept regardless of method so a probe with the wrong verb
	// also gets the clean signal.
	r.HandleFunc("/register", handlerNotOAuth())
}

// notOAuthBody is the response shape probes get back. The
// `auth_method` field is the load-bearing signal — an MCP client
// reading this knows to fall back to its static-bearer config rather
// than retry the OAuth code-grant flow.
type notOAuthBody struct {
	Error          string `json:"error"`
	Message        string `json:"message"`
	AuthMethod     string `json:"auth_method"`
	BearerConfig   string `json:"bearer_config"`
	IssueTokenHint string `json:"issue_token_hint"`
	Docs           string `json:"docs"`
}

func handlerNotOAuth() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(notOAuthBody{
			Error:          "Not Found",
			Message:        "bouncer's MCP endpoint does not implement OAuth code-grant flow; configure your client with a pre-issued Bearer JWT.",
			AuthMethod:     "pre_issued_bearer",
			BearerConfig:   "Authorization: Bearer <jwt>",
			IssueTokenHint: "bouncer issue-token --subject <name> --access-token <upstream-token> --admin",
			Docs:           "/_api/docs",
		})
	}
}
