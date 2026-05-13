package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/agentseen"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/connections"
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
	// `bouncer://bundles/<name>/readme` per entry. Empty / nil for
	// deployments with no vendored bundles.
	BundleReadmes map[string][]byte

	// APIBundle maps each registered API name to the bundle that
	// owns it. Used so list_apis can stamp a resource pointer onto
	// each API rather than the agent rebuilding the link itself.
	APIBundle map[string]string

	// Docs are the embedded markdown blobs the resources surface
	// serves. The admin package owns the raw bytes and passes them
	// in here so this package stays I/O-free.
	Docs Docs

	// TokenBundles is the per-bundle token-staging metadata the MCP
	// layer registers `/{service}-token` prompts and
	// `get_{service}_token` tools from. Empty / nil for deployments
	// with no bundles that declare a `token:` block.
	TokenBundles []*bundles.BundleToken

	// ConnectionStore reads the per-service upstream credentials the
	// `get_{service}_token` tools wrap into bouncer JWTs. nil makes
	// the tools return service_not_connected unconditionally — useful
	// for tests + deployments where connections aren't wired.
	ConnectionStore *connections.Store

	// Keys is the server's signing/encryption key bundle. Required
	// when ConnectionStore is set; `get_{service}_token` calls
	// tokens.IssueRefresh with it to wrap the stored upstream
	// refresh-token triple into a refresh JWT the proxy can exchange
	// on the data plane.
	Keys *auth.ServerKeys

	// SeenTracker records every Bearer-authenticated JSON-RPC call so
	// the dashboard's "Connected agents" card can show MCP-only
	// clients that haven't yet made an upstream proxied request.
	// Optional; nil disables the per-request bookkeeping.
	SeenTracker *agentseen.Tracker
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

// initializeResult is the server's handshake reply. `capabilities`
// declares what method families this server supports; the client
// uses it to decide which subsequent calls (tools/list,
// resources/list, …) make sense. `instructions` is guidance the
// client may surface to the LLM as system-prompt-like context —
// what bouncer is, how to set it up, common errors and their
// responses.
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
// family is supported". Future fields (listChanged, subscribe) add
// here without breaking clients that expect the bare object.
type capability struct{}

type serverInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

func (s *Server) handleInitialize(_ *http.Request, params json.RawMessage) (any, *Error) {
	// Decode for side-effect (rejecting malformed bodies); the
	// returned values are not used today but keep the slot open
	// for future logging.
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
		Instructions: buildInstructions(s.deps),
	}, nil
}

// buildInstructions renders the guidance string the server returns at
// handshake. The dynamic bit is the list of services the operator
// has wired up; everything else is static "how to use bouncer" text
// the client passes to the LLM as system-prompt-like context.
func buildInstructions(deps Deps) string {
	var b strings.Builder
	b.WriteString(`Bouncer is a policy-enforcing proxy in front of upstream APIs. It
issues encrypted bearer tokens that look like ordinary API keys, so
CLIs like gws, gcloud, gh, and curl work transparently through it.

# How to use
1. First time on a machine: run the ` + "`setup`" + ` prompt. It installs
   ` + "`bouncer-wrap`" + ` and the CA cert.
2. First time using a service: run the matching ` + "`<service>-token`" + `
   prompt (e.g. ` + "`google-token`, `slack-token`" + `). It stages local
   credentials.
3. Make API calls by prefixing with ` + "`bouncer-wrap`" + `:
       bouncer-wrap gws drive list
       bouncer-wrap curl https://slack.com/api/conversations.list

Do not bypass ` + "`bouncer-wrap`" + ` by unsetting HTTPS_PROXY, passing
--no-proxy, or calling the upstream directly.
`)
	if svcs := serviceSummary(deps.TokenBundles); svcs != "" {
		b.WriteString("\n# Available services\n")
		b.WriteString(svcs)
	}
	b.WriteString(`
# Common errors
- ` + "`service_not_connected`" + ` — the operator hasn't connected the
  upstream to bouncer yet. Surface ` + "`connect_url`" + ` from the response
  and wait.
- ` + "`credentials_not_staged`" + ` — run the matching ` + "`<service>-token`" + `
  prompt and retry.
- 403 Forbidden — bouncer denied by policy. The response body explains
  which action was blocked (` + "`matched_actions`" + ` + ` + "`api`" + `). Draft a
  permitting policy and call ` + "`propose_policy`" + `: an admin bearer applies
  it; a non-admin bearer gets the validated draft back to surface to
  the operator.

# Where to learn more
Tools: ` + "`list_apis`, `list_policies`, `get_policy`, `dry_run_policy`," + `
` + "`propose_policy`, `list_traffic`, `get_traffic_event`, `connections`," + `
` + "`credentials_staged`, `get_<service>_token`" + `.
Docs: ` + "`bouncer://docs/agent.md`, `bouncer://docs/policies.md`" + `.
`)
	return b.String()
}

// serviceSummary returns a "- slug — description" bullet list for
// every token-bundle service, sorted by slug. Empty string when no
// bundles declare a service block.
func serviceSummary(tbs []*bundles.BundleToken) string {
	type row struct{ slug, title, desc string }
	rows := make([]row, 0, len(tbs))
	for _, tb := range tbs {
		if tb.Spec == nil {
			continue
		}
		rows = append(rows, row{
			slug:  tb.Spec.Slug,
			title: tb.Spec.Title,
			desc:  strings.TrimSpace(tb.Spec.Description),
		})
	}
	if len(rows) == 0 {
		return ""
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].slug < rows[j].slug })
	var b strings.Builder
	for _, r := range rows {
		label := r.title
		if label == "" {
			label = r.slug
		}
		fmt.Fprintf(&b, "- `%s` — %s", r.slug, label)
		if r.desc != "" {
			fmt.Fprintf(&b, ": %s", firstLine(r.desc))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// firstLine returns s up to the first newline, trimmed. Service
// descriptions are usually multi-line; the summary line in the
// instructions only wants the opening sentence.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
