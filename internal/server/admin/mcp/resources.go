package mcp

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strings"
)

// Resource URIs the server exposes. Stable strings — clients store
// the URI in their resource cache and a rename would break their
// link to a previously-seen entry.
const (
	URIDocsAgent    = "bouncer://docs/agent"
	URIDocsPolicies = "bouncer://docs/policies"
	URIDocsAPIs     = "bouncer://docs/apis"
	URIAPIs         = "bouncer://apis"

	// URIBundleReadmePrefix is the per-bundle README URI scheme.
	// The full URI is `bouncer://bundles/<bundle>/readme`; clients
	// follow it from list_apis or resources/list.
	URIBundleReadmePrefix = "bouncer://bundles/"
	uriBundleReadmeSuffix = "/readme"
)

// BundleReadmeURI builds the URI for a bundle README. Mirrors the
// HTTP `readmeURLFor` so a rename of the scheme stays in sync.
func BundleReadmeURI(bundle string) string {
	return URIBundleReadmePrefix + bundle + uriBundleReadmeSuffix
}

// resourceDescriptor is the wire shape for resources/list. Mirrors
// the MCP spec's Resource object.
type resourceDescriptor struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

type listResourcesResult struct {
	Resources []resourceDescriptor `json:"resources"`
}

func (s *Server) handleResourcesList(_ *http.Request, _ json.RawMessage) (any, *Error) {
	out := []resourceDescriptor{
		{
			URI:         URIDocsAgent,
			Name:        "agent_guide",
			Title:       "Bouncer agent guide",
			Description: "Orientation for an agent calling through bouncer: auth tiers, request shape, denial recovery.",
			MIMEType:    "text/markdown",
		},
		{
			URI:         URIDocsPolicies,
			Name:        "policy_authoring",
			Title:       "Policy authoring guide",
			Description: "How to write a CEL policy plus a self-contained CEL primer. Read after a 403 denial.",
			MIMEType:    "text/markdown",
		},
		{
			URI:         URIDocsAPIs,
			Name:        "api_authoring",
			Title:       "API integration spec",
			Description: "How to describe a new upstream API to bouncer (resources, fetch URLs, actions).",
			MIMEType:    "text/markdown",
		},
		{
			URI:         URIAPIs,
			Name:        "registered_apis",
			Title:       "Registered APIs (live catalogue)",
			Description: "JSON snapshot of every API the proxy knows about. Same payload as GET /_api/apis.",
			MIMEType:    "application/json",
		},
	}
	bundles := make([]string, 0, len(s.deps.BundleReadmes))
	for name := range s.deps.BundleReadmes {
		bundles = append(bundles, name)
	}
	sort.Strings(bundles)
	for _, name := range bundles {
		out = append(out, resourceDescriptor{
			URI:         BundleReadmeURI(name),
			Name:        "bundle_readme_" + name,
			Title:       "README — " + name,
			Description: "Operator-facing notes shipped with the " + name + " bundle.",
			MIMEType:    "text/markdown",
		})
	}
	return listResourcesResult{Resources: out}, nil
}

// readResourceParams is the inbound shape of resources/read.
type readResourceParams struct {
	URI string `json:"uri"`
}

// resourceContent is one entry in the resources/read result. Either
// `text` or `blob` carries the body — we always emit text since
// every exposed resource is markdown or JSON.
type resourceContent struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
}

type readResourcesResult struct {
	Contents []resourceContent `json:"contents"`
}

func (s *Server) handleResourcesRead(r *http.Request, params json.RawMessage) (any, *Error) {
	var p readResourceParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, invalidParams("could not decode params: %v", err)
	}
	if p.URI == "" {
		return nil, invalidParams(`"uri" is required`)
	}
	switch p.URI {
	case URIDocsAgent:
		return mdResource(p.URI, s.deps.Docs.AgentGuide), nil
	case URIDocsPolicies:
		return mdResource(p.URI, s.deps.Docs.PolicyAuthoring), nil
	case URIDocsAPIs:
		return mdResource(p.URI, s.deps.Docs.APIAuthoring), nil
	case URIAPIs:
		body, err := json.MarshalIndent(map[string]any{"apis": s.deps.Runtime.APISpecs()}, "", "  ")
		if err != nil {
			slog.ErrorContext(r.Context(), "mcp: marshal apis", "err", err)
			return nil, internalError("marshal apis")
		}
		return readResourcesResult{
			Contents: []resourceContent{{
				URI:      p.URI,
				MIMEType: "application/json",
				Text:     string(body),
			}},
		}, nil
	}
	if name, ok := bundleFromReadmeURI(p.URI); ok {
		body, ok := s.deps.BundleReadmes[name]
		if !ok || len(body) == 0 {
			return nil, &Error{Code: codeInvalidParams, Message: "unknown bundle: " + name}
		}
		return mdResource(p.URI, body), nil
	}
	return nil, &Error{Code: codeInvalidParams, Message: "unknown resource uri: " + p.URI}
}

// bundleFromReadmeURI parses `bouncer://bundles/<name>/readme` and
// returns the bundle name. The two-step strip (prefix then suffix)
// rejects malformed URIs that share the prefix but lack the
// terminal `/readme`.
func bundleFromReadmeURI(uri string) (string, bool) {
	rest, ok := strings.CutPrefix(uri, URIBundleReadmePrefix)
	if !ok {
		return "", false
	}
	name, ok := strings.CutSuffix(rest, uriBundleReadmeSuffix)
	if !ok || name == "" || strings.Contains(name, "/") {
		return "", false
	}
	return name, true
}

func mdResource(uri string, body []byte) readResourcesResult {
	return readResourcesResult{
		Contents: []resourceContent{{
			URI:      uri,
			MIMEType: "text/markdown",
			Text:     string(body),
		}},
	}
}
