package admin

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/docs"
)

// DocsPath is the canonical mount path for the agent-facing
// documentation. The body is Markdown — the same source an
// operator reads in this repo's `docs/agent.md`. An agent's
// fetch-and-feed-to-an-LLM workflow handles markdown trivially;
// browsers that hit the path directly will render text/plain
// (which is fine — Markdown degrades gracefully) unless the
// operator has a markdown-aware browser extension.
const DocsPath = "/_api/docs"

// DocsPoliciesPath serves the policy-authoring guide. Linked from
// the parent docs orientation page and from denial responses, so
// an agent landing on a 403 can fetch the guide it needs without
// guessing.
const DocsPoliciesPath = "/_api/docs/policies"

// DocsAPIsPath serves the API-integration authoring guide. Not
// referenced from denial responses — denial is a runtime event,
// not an authoring one. Reachable via the parent docs page.
const DocsAPIsPath = "/_api/docs/apis"

// MountDocs attaches the GET handlers for the three doc paths. The
// docs are static so no runtime dependency is wired through.
func MountDocs(r chi.Router) {
	r.Get(DocsPath, markdownHandler(docs.Agent))
	r.Get(DocsPoliciesPath, markdownHandler(docs.Policies))
	r.Get(DocsAPIsPath, markdownHandler(docs.APIs))
}

// DocsBytes returns the raw markdown blobs the docs handlers serve.
// Sibling packages (the MCP server's resources surface) read the
// same bodies so an agent fetching `bouncer://docs/agent` over MCP
// sees byte-for-byte what an HTTP fetch of `/_api/docs` would
// return.
func DocsBytes() (agent, policies, apisGuide []byte) {
	return docs.Agent, docs.Policies, docs.APIs
}

func markdownHandler(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// `text/markdown` is the IANA-registered media type
		// (RFC 7763); agents and operators get a clear signal
		// that the body is structured Markdown rather than
		// arbitrary text.
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}
}
