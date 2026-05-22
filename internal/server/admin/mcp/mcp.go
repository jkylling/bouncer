// Package mcp implements a Model Context Protocol server at
// /_api/mcp. The MCP catalogue (resources + tools) is a thin
// projection of bouncer's existing /_api/* surface, but speaking a
// standard JSON-RPC protocol agent harnesses (Claude Desktop,
// Cursor, Continue, …) already know how to drive.
//
// Transport: JSON-RPC over HTTP POST. The server never pushes
// notifications, so SSE/streaming is not needed; a plain
// `application/json` response covers every method.
//
// Auth: the parent admin/AuthMiddleware runs before this handler,
// so by the time a method dispatches the caller is already verified
// and on the request context. Tool implementations re-check the
// admin tier where they would mutate live state, mirroring the
// HTTP-side RequireAdmin discipline.
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Path is the canonical mount path. Same prefix as the rest of the
// admin JSON API — agent harnesses configure their MCP client at
// `<bouncer>/_api/mcp`.
const Path = "/_api/mcp"

// MaxBodyBytes caps the JSON-RPC body the handler reads. MCP method
// payloads are small (a few hundred bytes for tools/call); 1 MiB is
// generous and shields the proxy from a hostile client.
const MaxBodyBytes int64 = 1 << 20

// JSON-RPC error codes the spec defines. Values come straight from
// JSON-RPC 2.0 §5.1; the MCP spec uses these unchanged.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// Request is one inbound JSON-RPC request. `id` may be a string,
// number, or null — keep it as json.RawMessage so the response can
// echo it byte-for-byte without a re-marshal round-trip.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is the JSON-RPC response envelope. Exactly one of Result
// / Error is set on a normal reply; both are nil only when the
// request was a notification (no `id`) and the dispatcher chose to
// emit nothing.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is the JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// methodHandler handles one JSON-RPC method, returning either a
// concrete result type or a JSON-RPC Error (parse / not-found
// errors are produced by the dispatcher; handlers surface
// app-level failures via Error).
type methodHandler func(r *http.Request, params json.RawMessage) (any, *Error)

// Server is the configured MCP dispatcher: a method registry plus
// the dependencies tools and resources reach for.
type Server struct {
	deps    Deps
	methods map[string]methodHandler
}

// New builds a Server with all built-in methods registered.
func New(deps Deps) *Server {
	s := &Server{deps: deps, methods: map[string]methodHandler{}}
	s.register("initialize", s.handleInitialize)
	s.register("tools/list", s.handleToolsList)
	s.register("tools/call", s.handleToolsCall)
	s.register("resources/list", s.handleResourcesList)
	s.register("resources/read", s.handleResourcesRead)
	s.register("prompts/list", s.handlePromptsList)
	s.register("prompts/get", s.handlePromptsGet)
	// `notifications/initialized` is a no-op acknowledgement the
	// client sends after `initialize`. Register it explicitly so the
	// server returns success rather than method-not-found.
	s.register("notifications/initialized", func(*http.Request, json.RawMessage) (any, *Error) {
		return struct{}{}, nil
	})
	// `ping` is the spec's keep-alive primitive. Returning {} is
	// the canonical empty response.
	s.register("ping", func(*http.Request, json.RawMessage) (any, *Error) {
		return struct{}{}, nil
	})
	return s
}

// register attaches m to the method registry. Panics on a duplicate
// registration so a typo in a server build fails loud at boot.
func (s *Server) register(name string, h methodHandler) {
	if _, exists := s.methods[name]; exists {
		panic("mcp: duplicate registration of method " + name)
	}
	s.methods[name] = h
}

// Mount wires Path to s.ServeHTTP. The auth middleware on the
// parent router runs first, so the dispatcher already sees the
// verified caller on r.Context().
func (s *Server) Mount(r chi.Router) {
	r.Post(Path, s.ServeHTTP)
}

// ServeHTTP is the JSON-RPC entry point. Decodes one request (the
// MCP HTTP transport does not require batch support — the spec
// allows it but most clients send single requests, and we can add
// batching later without an API break).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeRPC(w, makeError(nil, codeInvalidRequest, "request body too large", nil))
			return
		}
		writeRPC(w, makeError(nil, codeInvalidRequest, "could not read body", nil))
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, makeError(nil, codeParseError, "invalid JSON: "+err.Error(), nil))
		return
	}
	if req.JSONRPC != "2.0" {
		writeRPC(w, makeError(req.ID, codeInvalidRequest, `"jsonrpc" must be "2.0"`, nil))
		return
	}
	if req.Method == "" {
		writeRPC(w, makeError(req.ID, codeInvalidRequest, `"method" is required`, nil))
		return
	}

	h, ok := s.methods[req.Method]
	if !ok {
		writeRPC(w, makeError(req.ID, codeMethodNotFound, "method not found: "+req.Method, nil))
		return
	}

	result, rpcErr := h(r, req.Params)
	if rpcErr != nil {
		writeRPC(w, makeError(req.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data))
		return
	}
	// Notification: client sent no `id`, so the spec says emit
	// nothing. Use 204 so a client that did expect a body can tell
	// the difference between "I posted a notification" and "the
	// server ate my request".
	if len(req.ID) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeRPC(w, Response{JSONRPC: "2.0", ID: req.ID, Result: result})
}

// makeError is a tiny constructor so the dispatcher's error paths
// stay readable.
func makeError(id json.RawMessage, code int, message string, data any) Response {
	return Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &Error{Code: code, Message: message, Data: data},
	}
}

// writeRPC marshals resp to JSON and writes it with the right
// content type and a no-store cache header — JSON-RPC responses
// are session-scoped and never cacheable.
func writeRPC(w http.ResponseWriter, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// The connection is likely already torn; logging is the
		// only useful action.
		slog.Error("mcp: encode response", "err", err)
	}
}

// invalidParams is a small helper for handlers that decode params
// then need to short-circuit with the canonical -32602 code.
func invalidParams(format string, args ...any) *Error {
	return &Error{Code: codeInvalidParams, Message: fmt.Sprintf(format, args...)}
}

// internalError wraps an unexpected server-side failure. The
// underlying error goes to slog (via the caller); the JSON-RPC
// payload only carries the user-facing message so HKDF/AEAD details
// don't leak the way they wouldn't through writeJSONError on the
// HTTP side.
func internalError(message string) *Error {
	return &Error{Code: codeInternalError, Message: message}
}
