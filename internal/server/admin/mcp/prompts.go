package mcp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"text/template"
)

// Prompt names are stable strings. Renaming one breaks every agent
// harness that has the prompt pinned in its slash-command muscle
// memory.
const (
	PromptBouncerSetup = "setup"
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
	out := []promptDescriptor{
		{
			Name:        PromptBouncerSetup,
			Title:       "Bouncer setup",
			Description: "Install the bouncer-wrap script + CA cert on this machine and append a project-level instruction fragment.",
		},
	}
	// Per-service prompts come from bundles with a Token block. Sort
	// so the slash-command list is stable across boots.
	tokens := s.deps.tokenBundles()
	names := make([]string, 0, len(tokens))
	for name := range tokens {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, svc := range names {
		out = append(out, promptDescriptor{
			Name:        svc + "-token",
			Title:       "Stage " + svc + " credentials",
			Description: "Fetch a bouncer-issued bearer for " + svc + " and write it to the file the matching CLI reads.",
		})
	}
	return listPromptsResult{Prompts: out}, nil
}

// getPromptParams matches the spec's prompts/get inbound shape. No
// prompt this server exposes takes arguments today; the field exists
// only so a future arg-taking prompt round-trips cleanly.
type getPromptParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type promptMessage struct {
	Role    string        `json:"role"`
	Content promptContent `json:"content"`
}

type promptContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type getPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []promptMessage `json:"messages"`
}

func (s *Server) handlePromptsGet(r *http.Request, params json.RawMessage) (any, *Error) {
	var p getPromptParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, invalidParams("could not decode params: %v", err)
	}
	if p.Name == "" {
		return nil, invalidParams(`"name" is required`)
	}
	if p.Name == PromptBouncerSetup {
		body, err := renderBouncerSetup(bouncerSetupVars(r, s.deps))
		if err != nil {
			slog.ErrorContext(r.Context(), "mcp: render setup", "err", err)
			return nil, internalError("render setup")
		}
		return getPromptResult{
			Description: "Walk the user through installing bouncer-wrap on this machine.",
			Messages:    []promptMessage{userMessage(body)},
		}, nil
	}
	if svc, ok := strings.CutSuffix(p.Name, "-token"); ok {
		b, ok := s.deps.tokenBundles()[svc]
		if !ok {
			return nil, &Error{Code: codeInvalidParams, Message: "unknown prompt: " + p.Name}
		}
		body, err := renderTokenPrompt(b, tokenPromptVars(r, b))
		if err != nil {
			slog.ErrorContext(r.Context(), "mcp: render token prompt", "service", svc, "err", err)
			return nil, internalError("render token prompt")
		}
		return getPromptResult{
			Description: "Stage " + svc + " credentials so the matching CLI works through bouncer-wrap.",
			Messages:    []promptMessage{userMessage(body)},
		}, nil
	}
	return nil, &Error{Code: codeInvalidParams, Message: "unknown prompt: " + p.Name}
}

func userMessage(text string) promptMessage {
	return promptMessage{
		Role:    "user",
		Content: promptContent{Type: "text", Text: text},
	}
}

// ServiceInfo pairs a service's slug and description for template rendering.
type ServiceInfo struct {
	Slug        string
	Title       string
	Description string
}

// bouncerSetupVars derives the template inputs for the
// setup body from the inbound prompts/get request. Same
// rules as install.externalURL: TLS / X-Forwarded-Proto for scheme,
// r.Host / X-Forwarded-Host for host.
func bouncerSetupVars(r *http.Request, deps Deps) bouncerSetupTmpl {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = v
	}
	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		host = v
	}
	base := scheme + "://" + host

	// Extract service information from token bundles.
	services := make([]ServiceInfo, 0, len(deps.TokenBundles))
	for _, tb := range deps.TokenBundles {
		if tb.Spec == nil {
			continue
		}
		services = append(services, ServiceInfo{
			Slug:        tb.Spec.Slug,
			Title:       tb.Spec.Title,
			Description: tb.Spec.Description,
		})
	}

	return bouncerSetupTmpl{
		InstallWrapperURL: base + "/install/bouncer-wrap",
		InstallCAURL:      base + "/install/ca.pem",
		BearerToken:       bearerFromRequest(r),
		Services:          services,
	}
}

func bearerFromRequest(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "<tenant-token>"
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "<tenant-token>"
	}
	return strings.TrimSpace(h[len(prefix):])
}

type bouncerSetupTmpl struct {
	InstallWrapperURL string
	InstallCAURL      string
	BearerToken       string
	Services          []ServiceInfo
}

// bouncerSetupTemplate is the prompt body the agent walks through.
// It includes service descriptions from connected bundles so the user
// understands upfront what services are available and which CLIs they
// enable.
const bouncerSetupTemplate = `Bouncer is an HTTP proxy that sits between AI agents and upstream
APIs. It enforces per-request access control via CEL policies and issues
encrypted bearer tokens that look like ordinary API keys to CLIs — so existing clients work transparently through it.

This bouncer proxy has the following services available:
{{- range .Services }}

**{{ .Title }}** (` + "`/{{ .Slug }}-token`" + `)
{{ .Description }}
{{- end }}

This prompt wires bouncer up on the current machine. It installs a
small wrapper script ` + "`bouncer-wrap`" + ` (which sets HTTPS_PROXY and the
CA cert env vars) and writes a project-level instruction fragment so
future agent sessions know to use bouncer.
If any step below fails, stop and report the error.

# 1. Create install directories
Run:
    mkdir -p ~/.local/bin ~/.config/bouncer

# 2. Download the personalized wrapper script
Run:
    curl -fsSL -H "Authorization: Bearer {{ .BearerToken }}" {{ .InstallWrapperURL }} -o ~/.local/bin/bouncer-wrap && chmod 755 ~/.local/bin/bouncer-wrap

# 3. Download the CA cert
Run:
    curl -fsSL -H "Authorization: Bearer {{ .BearerToken }}" {{ .InstallCAURL }} -o ~/.config/bouncer/ca.pem && chmod 644 ~/.config/bouncer/ca.pem

# 4. Append the bouncer instruction fragment
Append the FRAGMENT below to whichever instruction file the current
harness reads for this project. If the target file already contains "## bouncer", update if the fragment is different.

FRAGMENT (append exactly):

    ## bouncer

    For any upstream API call that bouncer manages, prefix the
    command with ` + "`bouncer-wrap`. Examples:" + `

      - bouncer-wrap gws drive list
      - bouncer-wrap curl https://slack.com/api/conversations.list

    Do not bypass ` + "`bouncer-wrap`" + ` by unsetting HTTPS_PROXY, passing
    --no-proxy, or calling the upstream directly.

    If a tool needs access tokens or api keys, use the corresponding
    ` + "`get_<service>_token`" + ` tool of the bouncer mcp to obtain a token.

    If a call is denied, either:
    - Follow the instructions in the denied response.
    - Or use the ` + "`list_traffic`" + ` tool of the bouncer mcp to list recent
      requests and understand why the request was denied.

    Denial reasons are one of:
    - Invalid bouncer token — use the ` + "`get_<service>_token`" + ` bouncer mcp
      tool to obtain a fresh token.
    - Policy denial — propose a new bouncer policy with the
      ` + "`propose_policy`" + ` bouncer mcp tool.
    - Policy error — propose an update to the failing policy with the
      ` + "`propose_policy`" + ` bouncer mcp tool.
    - Other — surface the error to the user.

    See ` + "`bouncer://docs/policies`" + ` (via the bouncer mcp ` + "`resources/read`" + `)
    for how to write bouncer policies.


# 5. PATH check
Run:
    echo "$PATH" | tr ':' '\n' | grep -qx "$HOME/.local/bin"

If exit code != 0, tell the user how to add ~/.local/bin to PATH
(append ` + "`export PATH=$HOME/.local/bin:$PATH`" + ` to ~/.bashrc / ~/.zshrc,
or ` + "`fish_add_path $HOME/.local/bin`)." + `

# 6. Done
Tell the user:
    "Bouncer is wired up and ready for use."
`

func renderBouncerSetup(v bouncerSetupTmpl) (string, error) {
	tmpl, err := template.New("setup").Parse(bouncerSetupTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}
