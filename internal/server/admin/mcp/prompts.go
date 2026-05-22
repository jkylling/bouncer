package mcp

import (
	"encoding/json"
	"net/http"
)

// promptDescriptor is the wire shape for prompts/list. Matches the
// MCP spec's Prompt object.
type promptDescriptor struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

type listPromptsResult struct {
	Prompts []promptDescriptor `json:"prompts"`
}

func (s *Server) handlePromptsList(_ *http.Request, _ json.RawMessage) (any, *Error) {
	// No built-in prompts after the onboarding flow was removed.
	// Bouncer JWTs are now issued from the /_admin/tokens page; the
	// agent presents them as Bearer headers directly.
	return listPromptsResult{Prompts: []promptDescriptor{}}, nil
}

// getPromptParams matches the spec's prompts/get inbound shape.
type getPromptParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (s *Server) handlePromptsGet(_ *http.Request, params json.RawMessage) (any, *Error) {
	var p getPromptParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, invalidParams("could not decode params: %v", err)
	}
	return nil, &Error{Code: codeInvalidParams, Message: "unknown prompt: " + p.Name}
}
