// Package docs holds the canonical agent- and operator-facing
// documentation. The Markdown sources are the ground truth — the
// admin HTTP handlers (`/_api/docs/*`) and the MCP `resources/list`
// surface both read from here. Edits to the .md files ship as the
// docs.
package docs

import _ "embed"

// Agent is the orientation guide an agent or operator-script reads
// first: auth, request shape, MCP wiring, troubleshooting.
//
//go:embed agent.md
var Agent []byte

// Policies is the CEL policy authoring guide, including the CEL
// primer. Linked from denial responses so an agent landing on a 403
// can fetch it directly.
//
//go:embed policies.md
var Policies []byte

// APIs is the API-integration authoring guide: the YAML schema for
// a new upstream and the process for enumerating its actions and
// metas.
//
//go:embed apis.md
var APIs []byte
