package mcp

import (
	"context"
	"encoding/json"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// apisTools is the apis-family slice contributed to the registry.
func apisTools() []tool {
	return []tool{
		{
			Name:        "list_apis",
			Title:       "List registered APIs",
			Description: "Returns every API the proxy knows about. The canonical schema discovery surface — equivalent to GET /_api/apis. APIs sourced from a vendored bundle carry a `readme_url` that points at the bundle README; agents can read it via `resources/read` with `bouncer://bundles/<bundle>/readme`.",
			InputSchema: schemaObject(nil, nil),
			Run:         runListAPIs,
		},
	}
}

// apiSummary embeds the raw API spec and adds the bundle pointers so
// an MCP client sees the same fields as `/_api/apis` without us
// duplicating the `models.API` projection. Embedding rather than a
// hand-rolled mirror means new schema fields surface automatically.
type apiSummary struct {
	*models.API
	Bundle    string `json:"bundle,omitempty"`
	ReadmeURI string `json:"readme_uri,omitempty"`
}

func runListAPIs(_ context.Context, deps Deps, _ json.RawMessage) (any, *Error) {
	specs := deps.Runtime.APISpecs()
	out := make([]apiSummary, 0, len(specs))
	for _, s := range specs {
		row := apiSummary{API: s}
		if bundle, ok := deps.APIBundle[s.Name]; ok {
			row.Bundle = bundle
			if _, has := deps.BundleReadmes[bundle]; has {
				row.ReadmeURI = BundleReadmeURI(bundle)
			}
		}
		out = append(out, row)
	}
	return map[string]any{"apis": out}, nil
}
