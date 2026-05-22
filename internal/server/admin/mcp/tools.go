package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jkylling/bouncer/internal/auth"
)

// tool is one MCP tool: schema for tools/list, executor for
// tools/call. Each tool also declares whether it requires the admin
// tier — read-only listings work for any authenticated caller, but
// anything that writes (propose / approve / reject) gates here.
type tool struct {
	Name        string
	Title       string
	Description string
	InputSchema map[string]any
	AdminOnly   bool
	Run         func(ctx context.Context, deps Deps, params json.RawMessage) (any, *Error)
}

// toolDescriptor is the wire shape for tools/list. Mirrors the MCP
// spec's Tool object.
type toolDescriptor struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

// content is one entry in the tools/call result envelope. We always
// emit a single text block carrying JSON; clients that want
// structured output decode the JSON, clients that pass it to a
// model see a readable transcript.
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// callToolResult is the spec's tools/call response shape.
type callToolResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// allTools is the in-process registry. Each family contributes its
// own slice from a sibling file (apis_tools.go, policies_tools.go,
// traffic_tools.go). New tools land in the family they belong to,
// not here.
func allTools() []tool {
	out := make([]tool, 0, 16)
	out = append(out, apisTools()...)
	out = append(out, policiesTools()...)
	out = append(out, trafficTools()...)
	return out
}

// schemaObject builds a JSON-Schema object with `type:"object"` and
// optional properties / required slots. A nil properties map yields
// the empty `{type:"object"}` schema (zero-arg tool).
func schemaObject(props map[string]any, required []string) map[string]any {
	out := map[string]any{"type": "object"}
	if len(props) > 0 {
		out["properties"] = props
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

// listToolsResult is the spec's tools/list response shape.
type listToolsResult struct {
	Tools []toolDescriptor `json:"tools"`
}

func (s *Server) handleToolsList(r *http.Request, _ json.RawMessage) (any, *Error) {
	isAdmin := auth.CallerFromContext(r.Context()).IsAdmin()
	tools := allTools()
	out := make([]toolDescriptor, 0, len(tools))
	for _, t := range tools {
		// Hide admin-only tools from non-admin callers so the agent's
		// tool list is the set it can actually invoke. The call path
		// still gates by role; this just prevents the listing from
		// dangling tools the caller would only ever get refused on.
		if t.AdminOnly && !isAdmin {
			continue
		}
		out = append(out, toolDescriptor{
			Name:        t.Name,
			Title:       t.Title,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return listToolsResult{Tools: out}, nil
}

// callToolParams is the inbound shape of tools/call. arguments is
// the per-tool params object (validated by the tool itself).
type callToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (s *Server) handleToolsCall(r *http.Request, params json.RawMessage) (any, *Error) {
	var p callToolParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, invalidParams("could not decode params: %v", err)
	}
	if p.Name == "" {
		return nil, invalidParams(`"name" is required`)
	}
	for _, t := range allTools() {
		if t.Name != p.Name {
			continue
		}
		if t.AdminOnly {
			c := auth.CallerFromContext(r.Context())
			if c.Role != auth.RoleAdmin {
				return nil, &Error{
					Code:    codeInvalidRequest,
					Message: "tool " + p.Name + " requires the admin role",
				}
			}
		}
		// Default to an empty object so tools that take no
		// arguments don't have to special-case nil.
		args := p.Arguments
		if len(args) == 0 {
			args = json.RawMessage(`{}`)
		}
		result, rpcErr := t.Run(r.Context(), s.deps, args)
		if rpcErr != nil {
			// Tool-level errors come back as a successful
			// JSON-RPC envelope with isError:true so the client
			// model can read the message rather than handle a
			// transport failure. Spec §Tools/Errors.
			return callToolResult{
				Content: []content{{Type: "text", Text: rpcErr.Message}},
				IsError: true,
			}, nil
		}
		text, err := encodeText(result)
		if err != nil {
			slog.ErrorContext(r.Context(), "mcp: encode tool result", "tool", p.Name, "err", err)
			return nil, internalError("could not encode tool result")
		}
		return callToolResult{Content: []content{{Type: "text", Text: text}}}, nil
	}
	return nil, &Error{
		Code:    codeMethodNotFound,
		Message: "tool not found: " + p.Name,
	}
}

func encodeText(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// requireService is the shared "this surface isn't wired" guard. A
// deployment that disables traffic recording or proposal review
// keeps the MCP endpoint mounted but the dependent tools refuse
// with a clear message rather than a confusing nil-deref.
func requireService(present bool, what string) *Error {
	if present {
		return nil
	}
	return &Error{
		Code:    codeMethodNotFound,
		Message: "this deployment has no " + what + " configured",
	}
}
