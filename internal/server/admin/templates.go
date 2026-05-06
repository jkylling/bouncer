package admin

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

//go:embed admin_ui/layout.tmpl.html admin_ui/*.tmpl.html
var adminTemplatesFS embed.FS

// pageData is the value every layout-routed page receives. Title
// goes into <title>; Current is the nav identifier (one of
// "tokens" / "traffic" / "policies" / "proposals" / "apis") so the
// matching nav link gets aria-current. ContainerClass adds an
// extra class to the .container wrapper — pages with table-heavy
// content pass "wide" to widen the layout.
type pageData struct {
	Title          string
	Current        string
	ContainerClass string
}

// pages maps a page identifier to the full set of template files
// the renderer needs to parse for that page (layout + per-page
// body). One template tree per page so each page has its own
// `body` block bound to its file.
var pages = map[string]string{
	"tokens":    "admin_ui/tokens.tmpl.html",
	"traffic":   "admin_ui/traffic.tmpl.html",
	"policies":  "admin_ui/policies.tmpl.html",
	"proposals": "admin_ui/proposals.tmpl.html",
	"apis":      "admin_ui/apis.tmpl.html",
	// traffic_propose is reached from the traffic detail view, not
	// the nav. Treated like a regular page for layout purposes; the
	// nav highlights traffic since that's where the operator came
	// from.
	"traffic_propose": "admin_ui/traffic_propose.tmpl.html",
}

// pageMeta is the static {Title, Current, ContainerClass} for each
// page. Centralised so a new page or a title change lands in one
// place. ContainerClass widens the .container wrapper for table-
// heavy pages.
var pageMeta = map[string]pageData{
	"tokens":          {Title: "issue token", Current: "tokens"},
	"traffic":         {Title: "traffic viewer", Current: "traffic", ContainerClass: "wide"},
	"policies":        {Title: "policies", Current: "policies", ContainerClass: "wide"},
	"proposals":       {Title: "proposals", Current: "proposals", ContainerClass: "wide"},
	"apis":            {Title: "registered APIs", Current: "apis", ContainerClass: "wide"},
	"traffic_propose": {Title: "propose policy", Current: "traffic"},
}

// pageTemplates is parsed once at package init and re-used per
// request. html/template's parsed Template is safe for concurrent
// Execute calls.
var pageTemplates = func() map[string]*template.Template {
	out := make(map[string]*template.Template, len(pages))
	for name, body := range pages {
		t, err := template.ParseFS(adminTemplatesFS,
			"admin_ui/layout.tmpl.html", body)
		if err != nil {
			panic(fmt.Sprintf("admin: parse %s: %v", body, err))
		}
		out[name] = t
	}
	return out
}()

// renderPage executes the named page through the shared layout.
// Renders into a buffer first so a template-execute failure
// produces a 500 rather than a partial 200.
func renderPage(w http.ResponseWriter, name string) {
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := t.ExecuteTemplate(w, "layout", meta); err != nil {
		slog.Error("admin: render", "page", name, "err", err)
		// Best-effort: by the time ExecuteTemplate fails, the
		// response may have started — there's nothing useful to
		// send back.
	}
}

// pageHandler is the handler factory each MountX wires up. The
// returned handler is wrapped by RedirectAnonymousToLogin in the
// caller, matching the static-page setup it replaces.
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
// distinct routes — gated by RedirectAnonymousToLogin.
func mountUIPage(r chi.Router, uiPath, page string) {
	h := RedirectAnonymousToLogin(pageHandler(page))
	r.Get(uiPath, h)
	r.Get(uiPath+"/", h)
}
