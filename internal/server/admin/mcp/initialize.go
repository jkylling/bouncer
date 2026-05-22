package mcp

import (
	"encoding/json"
	"net/http"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime"
)

// ProtocolVersion is the MCP spec revision the server speaks. Bumped
// when the server's behaviour migrates to a newer spec; the client's
// `initialize.params.protocolVersion` is recorded but the server's
// reply always advertises this value.
const ProtocolVersion = "2025-06-18"

// ServerName / ServerTitle / ServerVersion show up in
// `initialize.result.serverInfo`. A future bump only changes
// `ServerVersion`; clients keying on `serverInfo.name` to identify
// bouncer must not see it move. `ServerTitle` is the human-readable
// display name some clients render in their UI.
const (
	ServerName    = "bouncer"
	ServerTitle   = "Bouncer"
	ServerVersion = "0.1.0"
)

// Deps bundles every backing service the MCP tools and resources
// reach for. Caller-supplied (server.go composes them and hands the
// bundle to mcp.New) so this package never imports the parent
// server's wiring directly. Optional fields stay nil when the
// corresponding /_api/* surface is also disabled — tools that need
// them surface a clean MethodNotFound rather than panicking.
type Deps struct {
	// Runtime is the live API+policy engine. Required — list_apis
	// and the docs-resource catalogue both depend on it.
	Runtime *runtime.Runtime

	// PolicyService backs the policy CRUD tools. Optional; when
	// nil, the policy tools refuse with a clear error.
	PolicyService *policies.Service

	// TrafficStore backs the traffic-list / get tools. Optional.
	TrafficStore traffic.Store

	// BundleReadmes maps each vendored-bundle manifest name to the
	// bytes of its README.md. The resources surface lists one
	// `bouncer://bundles/<name>/readme` per entry.
	BundleReadmes map[string][]byte

	// APIBundle maps each registered API name to the bundle that
	// owns it. Used so list_apis can stamp a resource pointer onto
	// each API rather than the agent rebuilding the link itself.
	APIBundle map[string]string

	// Docs are the embedded markdown blobs the resources surface
	// serves.
	Docs Docs
}

// Docs carries the markdown bodies for the doc resources. Same
// fields as the docs.go file in the admin package; passed through
// so this package doesn't reach into admin's go:embed directly.
type Docs struct {
	AgentGuide      []byte
	PolicyAuthoring []byte
	APIAuthoring    []byte
}

// initializeParams is the inbound shape the spec requires at handshake
// time. We accept and ignore the client's protocolVersion / clientInfo
// — the version negotiation is "server's value wins"; logging the
// client metadata is a future enhancement.
type initializeParams struct {
	ProtocolVersion string          `json:"protocolVersion,omitempty"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
	ClientInfo      json.RawMessage `json:"clientInfo,omitempty"`
}

// initializeResult is the server's handshake reply.
type initializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    serverCapabilities `json:"capabilities"`
	ServerInfo      serverInfo         `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

type serverCapabilities struct {
	Tools     *capability `json:"tools,omitempty"`
	Resources *capability `json:"resources,omitempty"`
	Prompts   *capability `json:"prompts,omitempty"`
}

// capability is the empty marker object the spec uses to mean "this
// family is supported".
type capability struct{}

type serverInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

func (s *Server) handleInitialize(_ *http.Request, params json.RawMessage) (any, *Error) {
	if len(params) > 0 {
		var p initializeParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, invalidParams("could not decode params: %v", err)
		}
	}
	return initializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: serverCapabilities{
			Tools:     &capability{},
			Resources: &capability{},
			Prompts:   &capability{},
		},
		ServerInfo: serverInfo{
			Name:    ServerName,
			Title:   ServerTitle,
			Version: ServerVersion,
		},
		Instructions: instructions,
	}, nil
}

// instructions is the static "how to use bouncer" guidance the server
// returns at handshake. Stateless — issued JWTs are minted on the
// /_admin/tokens page; agents present them as Bearer headers.
const instructions = `Bouncer is a policy-enforcing proxy in front of upstream APIs. It
issues encrypted bearer tokens that look like ordinary API keys, so
CLIs like gws, gcloud, gh, and curl work transparently through it.

# How to use
- The operator issues a bouncer JWT on the /_admin/tokens page (or
  via the issue-token CLI / /_api/tokens/issue endpoint) and pastes
  it into the agent's configuration.
- The agent uses the JWT as a Bearer credential against the proxy.

# Common errors
- 403 Forbidden — bouncer denied by policy. The response body
  explains which action was blocked (matched_actions + api). Draft
  a permitting policy and call propose_policy: an admin bearer
  applies it; a non-admin gets the validated draft back to surface.

# Where to learn more
Tools: list_apis, list_policies, get_policy, dry_run_policy,
propose_policy, list_traffic, get_traffic_event.
Docs: bouncer://docs/agent.md, bouncer://docs/policies.md.
`
