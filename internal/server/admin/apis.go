package admin

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Path constants for the supported-APIs surface: a JSON listing
// agents discover schema from, and an HTML viewer for humans.
const (
	APIsPath       = "/_api/apis"
	APIsReadmePath = "/_api/apis/{bundle}/readme"
)

// APIsListResponse is the GET /_api/apis body. Wrapped in an object
// so a future field (catalog version, generation hash) can be added
// without breaking clients that decoded a bare array.
type APIsListResponse struct {
	APIs []APIDescriptor `json:"apis"`
}

// APIDescriptor is one registered API, projected to a JSON-friendly
// shape. The projection lets the JSON shape evolve independently of
// the YAML loader struct.
type APIDescriptor struct {
	Name         string             `json:"name"`
	BaseURL      string             `json:"base_url"`
	PathPrefixes []string           `json:"path_prefixes,omitempty"`
	Actions      []ActionDescriptor `json:"actions,omitempty"`
	Meta         []MetaDescriptor   `json:"meta,omitempty"`

	// AccessDeniedStatus is the operator-configured status the
	// proxy returns on auth-fail / policy-deny. Omitted (and the
	// natural 401/403 applies) unless the spec sets a non-zero
	// value — Slack bundles typically pin this to 200.
	AccessDeniedStatus int `json:"access_denied_status,omitempty"`

	// ReadmeURL points at the bundle README served from
	// `/_api/apis/{bundle}/readme`. Empty for APIs not sourced
	// from a vendored bundle, or for bundles without a README.
	ReadmeURL string `json:"readme_url,omitempty"`
}

// ActionDescriptor surfaces one action: name + match criteria
// (method, path template, filter) + bind expressions.
type ActionDescriptor struct {
	Name   string   `json:"name"`
	Method string   `json:"method,omitempty"`
	Path   string   `json:"path,omitempty"`
	Filter string   `json:"filter,omitempty"`
	Binds  []string `json:"binds,omitempty"`
}

// MetaDescriptor surfaces one named meta type: input fields a
// policy can constrain on, output fields a policy can read after
// the meta is fetched.
type MetaDescriptor struct {
	Name   string             `json:"name"`
	Kind   string             `json:"kind,omitempty"`
	Input  []string           `json:"input,omitempty"`
	Output []OutputDescriptor `json:"output,omitempty"`
}

// OutputDescriptor is one field a meta exposes to policy code.
type OutputDescriptor struct {
	Name string `json:"name"`
	Expr string `json:"expr,omitempty"`
}

// BundleData carries the per-bundle metadata MountAPIs needs to
// surface READMEs and per-API readme links, plus the token-staging
// metadata the MCP layer needs to register per-service prompts and
// tools. All fields may be empty for a deployment with no vendored
// bundles.
type BundleData struct {
	// Readmes maps a bundle's manifest name to its README bytes.
	Readmes map[string][]byte

	// APIBundle maps an API name to the bundle name it came from.
	// Locally-loaded APIs are absent.
	APIBundle map[string]string

	// TokenBundles is the per-bundle token-staging blocks the MCP
	// prompts/tools layer reads. Empty for deployments where no
	// bundle declares MCP staging metadata.
	TokenBundles []*bundles.BundleToken

	// Services is the per-bundle service block + OAuth + token
	// variants + suggested policies the /_api/services surface and
	// the new Service Detail UI read. Empty for deployments whose
	// bundles don't declare a `service:` block.
	Services []bundles.LoadedService
}

// MountAPIs attaches the GET /_api/apis listing onto r, backed by
// rt's registered API specs. Read-only — no Put/Delete since the
// API surface is frozen at boot. Plus a per-bundle README endpoint
// at /_api/apis/{bundle}/readme used by the per-service Docs tab on
// /_admin/services/{slug}.
func MountAPIs(r chi.Router, rt *runtime.Runtime, bd BundleData) {
	r.Get(APIsPath, listAPIsHandler(rt, bd))
	r.Get(APIsReadmePath, readmeHandler(bd.Readmes))
}

func listAPIsHandler(rt *runtime.Runtime, bd BundleData) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		specs := rt.APISpecs()
		out := make([]APIDescriptor, 0, len(specs))
		for _, s := range specs {
			out = append(out, describeAPI(s, bd))
		}
		writeJSON(w, APIsListResponse{APIs: out})
	}
}

// readmeHandler serves the bundle README as text/markdown. A
// missing bundle (or one without a README) 404s; we don't fall back
// to an empty body so a typo in the URL is loud rather than silent.
func readmeHandler(readmes map[string][]byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bundle := chi.URLParam(r, "bundle")
		body, ok := readmes[bundle]
		if !ok || len(body) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write(body)
	}
}

func describeAPI(api *models.API, bd BundleData) APIDescriptor {
	d := APIDescriptor{
		Name:               api.Name,
		BaseURL:            api.BaseURL,
		PathPrefixes:       api.PathPrefixes,
		AccessDeniedStatus: api.AccessDeniedStatus,
	}
	if bundle, ok := bd.APIBundle[api.Name]; ok {
		if _, hasReadme := bd.Readmes[bundle]; hasReadme {
			d.ReadmeURL = readmeURLFor(bundle)
		}
	}
	for _, a := range api.Actions {
		ad := ActionDescriptor{
			Name:   a.Name,
			Method: a.Method,
			Path:   a.Path,
			Filter: string(a.Filter),
		}
		for _, b := range a.AllBinds() {
			ad.Binds = append(ad.Binds, string(b))
		}
		d.Actions = append(d.Actions, ad)
	}
	for _, m := range api.Meta {
		md := MetaDescriptor{Name: m.Name, Kind: m.Kind}
		for _, in := range m.Input {
			md.Input = append(md.Input, in.Name)
		}
		for _, out := range m.Output {
			md.Output = append(md.Output, OutputDescriptor{
				Name: out.Name,
				Expr: string(out.Expr),
			})
		}
		d.Meta = append(d.Meta, md)
	}
	return d
}

// readmeURLFor builds the public path for a bundle README. Mirrors
// chi's literal path so a rename of APIsReadmePath stays in sync
// without requiring a router lookup at request time.
func readmeURLFor(bundle string) string {
	return strings.Replace(APIsReadmePath, "{bundle}", bundle, 1)
}
