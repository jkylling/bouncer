package admin

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// tmplFuncs are the template helpers every page is parsed with.
//
//   - json marshals any value to JSON and returns it as template.JS
//     so callers can embed it inline as a JS literal: `const x =
//     {{ json .Extra }};`. Saves a follow-up fetch when the server
//     already has the data the page needs.
var tmplFuncs = template.FuncMap{
	"json": func(v any) (template.JS, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return template.JS(b), nil
	},
}

// Static files include common.css (shared utilities) and pages.css (page-specific styles).
//
//go:embed admin_ui/layout.tmpl.html admin_ui/*.tmpl.html admin_ui/partials/*.tmpl.html admin_ui/static/js/*.js admin_ui/static/css/*.css admin_ui/static/favicon.svg
var adminTemplatesFS embed.FS

// partialGlob is the wildcard ParseFS uses to pull in shared template
// fragments — currently the policies_list / traffic_list components
// reused by both their full-page hosts (/_admin/policies, /_admin/
// traffic) and the per-service tabs on /_admin/services/{slug}.
const partialGlob = "admin_ui/partials/*.tmpl.html"

// pageData is the value every layout-routed page receives. Title
// goes into <title>; Current is the nav identifier (one of
// "services" / "tokens" / "policies" / "traffic" / "settings") so
// the matching nav link gets aria-current. ContainerClass adds an
// extra class to the .container wrapper — pages with table-heavy
// content pass "wide" to widen the layout.
type pageData struct {
	Title          string
	Current        string
	ContainerClass string
	// Extra is per-request data resolved by a custom handler (e.g.
	// the service-detail page bakes the resolved services.Descriptor
	// here so the template can render every field server-side). Nil
	// for pages that go through the default pageHandler.
	Extra any
}

// pages maps a page identifier to the full set of template files
// the renderer needs to parse for that page (layout + per-page
// body). One template tree per page so each page has its own
// `body` block bound to its file.
var pages = map[string]string{
	"traffic":        "admin_ui/traffic.tmpl.html",
	"policies":       "admin_ui/policies.tmpl.html",
	"proposals":      "admin_ui/proposals.tmpl.html",
	"settings":       "admin_ui/settings.tmpl.html",
	"services":       "admin_ui/services.tmpl.html",
	"service_detail": "admin_ui/service_detail.tmpl.html",
	"tokens":         "admin_ui/tokens.tmpl.html",
}

// pageMeta is the static {Title, Current, ContainerClass} for each
// page. Centralised so a new page or a title change lands in one
// place. ContainerClass widens the .container wrapper for table-
// heavy pages.
var pageMeta = map[string]pageData{
	"traffic":        {Title: "traffic", Current: "traffic", ContainerClass: "wide"},
	"policies":       {Title: "policies", Current: "policies", ContainerClass: "wide"},
	"proposals":      {Title: "proposals", Current: "proposals", ContainerClass: "wide"},
	"settings":       {Title: "settings", Current: "settings", ContainerClass: "wide"},
	"services":       {Title: "services", Current: "services", ContainerClass: "wide"},
	"service_detail": {Title: "service", Current: "services", ContainerClass: "wide"},
	"tokens":         {Title: "tokens", Current: "tokens", ContainerClass: "wide"},
}

// pageTemplates is parsed once at package init and re-used per
// request. html/template's parsed Template is safe for concurrent
// Execute calls.
var pageTemplates = func() map[string]*template.Template {
	out := make(map[string]*template.Template, len(pages))
	for name, body := range pages {
		// Parse the layout + page body together with every shared
		// partial so {{template "policies_list_body" .}} et al.
		// resolve at render time. Partials are pulled by glob so
		// adding a new fragment in admin_ui/partials/ is zero-config.
		t := template.New(name).Funcs(tmplFuncs)
		t, err := t.ParseFS(adminTemplatesFS, "admin_ui/layout.tmpl.html", body, partialGlob)
		if err != nil {
			panic(fmt.Sprintf("admin: parse %s: %v", body, err))
		}
		out[name] = t
	}
	return out
}()

// renderPage executes the named page through the shared layout
// with the static pageMeta as the template data.
func renderPage(w http.ResponseWriter, name string) {
	renderPageWith(w, name, nil)
}

// renderPageWith is renderPage plus per-request extra data that the
// template reads as `.Extra`. Use when a page needs server-resolved
// state (e.g. the service-detail page bakes the resolved
// services.Descriptor here so the template can render every field
// without an asynchronous fetch + Loading… placeholder).
func renderPageWith(w http.ResponseWriter, name string, extra any) {
	t, ok := pageTemplates[name]
	if !ok {
		slog.Error("admin: no template", "page", name)
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}
	meta, ok := pageMeta[name]
	if !ok {
		slog.Error("admin: no meta", "page", name)
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}
	meta.Extra = extra
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := t.ExecuteTemplate(w, "layout", meta); err != nil {
		slog.Error("admin: render", "page", name, "err", err)
		// Best-effort: by the time ExecuteTemplate fails, the
		// response may have started — there's nothing useful to
		// send back.
	}
}

// pageHandler is the handler factory each MountX wires up. UI-shell
// access (anonymous → 303 to login, authenticated → render) is now
// enforced upstream by InternalPolicyMiddleware against the matching
// `ui_*` action; the handler itself just renders.
func pageHandler(name string) http.HandlerFunc {
	// Resolve at construction time so a typo'd name fails at boot
	// (panic) rather than 500-ing per request.
	if _, ok := pages[name]; !ok {
		panic("admin: pageHandler: unknown page " + name)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		renderPage(w, name)
	}
}

// mountUIPage registers uiPath and uiPath+"/" — chi treats them as
// distinct routes. The internal-policy middleware handles the
// anonymous-redirect-to-login dance via the matching `ui_*` action.
func mountUIPage(r chi.Router, uiPath, page string) {
	h := pageHandler(page)
	r.Get(uiPath, h)
	r.Get(uiPath+"/", h)
}

// serveStaticHandler serves static files (JS, CSS) from the embedded FS.
// Files are cached for 30 days since they're part of the binary.
func serveStaticHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the path after /_admin/static/
	path := strings.TrimPrefix(r.URL.Path, "/_admin/static/")
	if path == r.URL.Path || path == "" {
		http.NotFound(w, r)
		return
	}

	// Read the file from embedded FS
	data, err := fs.ReadFile(adminTemplatesFS, "admin_ui/static/"+path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Determine content type based on extension
	contentType := "application/octet-stream"
	if strings.HasSuffix(path, ".js") {
		contentType = "application/javascript; charset=utf-8"
	} else if strings.HasSuffix(path, ".css") {
		contentType = "text/css; charset=utf-8"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// MountStatic serves static files (JS, CSS) under /_admin/static/.
// Call this from the parent server router setup.
func MountStatic(r chi.Router) {
	r.Get("/_admin/static/*", serveStaticHandler)
}

// FaviconHandler serves admin_ui/static/favicon.svg as image/svg+xml.
// Exposed so the data-plane router can register /favicon.ico without
// duplicating the embedded SVG.
func FaviconHandler(w http.ResponseWriter, _ *http.Request) {
	data, err := fs.ReadFile(adminTemplatesFS, "admin_ui/static/favicon.svg")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}
