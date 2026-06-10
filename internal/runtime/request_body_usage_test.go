package runtime

import (
	"testing"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// uploadAPI returns a minimal API whose single action matches by
// template only — no expression on it can observe request.body.
func uploadAPI() *models.API {
	return &models.API{
		Name:         "svc",
		BaseURL:      "https://svc.invalid",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "upload", Method: "POST", Path: "/svc/upload"},
		},
	}
}

// TestUsesRequestBodyTracksPolicyHotReload pins the dynamic half of
// the data plane's stream-vs-buffer signal: a template-only API
// starts body-blind, flips to body-using when a policy reading
// request.body is added at runtime, and flips back when that policy
// is removed.
func TestUsesRequestBodyTracksPolicyHotReload(t *testing.T) {
	rt := buildSingleAPI(t, uploadAPI())
	if rt.UsesRequestBody() {
		t.Fatal("template-only API with no policies must not use request.body")
	}

	if err := rt.Add(&models.Policy{
		API:       "svc",
		Name:      "kind-gate",
		Result:    models.Permit,
		Condition: `request.body.?kind.orValue("") == "ok"`,
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	if !rt.UsesRequestBody() {
		t.Fatal("policy condition reading request.body must flip UsesRequestBody")
	}

	if !rt.Remove("kind-gate") {
		t.Fatal("remove: policy not found")
	}
	if rt.UsesRequestBody() {
		t.Fatal("UsesRequestBody must flip back once the body-reading policy is removed")
	}
}

// TestUsesRequestBodyBodyBlindPolicy pins the negative: a policy that
// reads request fields other than body keeps the API body-blind.
func TestUsesRequestBodyBodyBlindPolicy(t *testing.T) {
	rt := buildSingleAPI(t, uploadAPI(), models.Policy{
		API:       "svc",
		Name:      "method-gate",
		Result:    models.Permit,
		Condition: `request.method == "POST"`,
	})
	if rt.UsesRequestBody() {
		t.Fatal("policy reading only request.method must not flip UsesRequestBody")
	}
}

// TestUsesRequestBodyFromActionFilter pins the static half: an action
// filter that selects request.body marks the API body-using at build
// time, before any policy exists.
func TestUsesRequestBodyFromActionFilter(t *testing.T) {
	api := uploadAPI()
	api.Actions = append(api.Actions, models.Action{
		Name:   "json_upload",
		Filter: `request.method == "POST" && has(request.body)`,
	})
	rt := buildSingleAPI(t, api)
	if !rt.UsesRequestBody() {
		t.Fatal("action filter reading request.body must mark the API body-using")
	}
}

// TestUsesRequestBodyFromBind pins the bind path against the bundled
// gmail fixture, whose create_draft_from_body action binds
// `draft{... request.body.id ...}` — real specs reach body through
// binds, so the signal must fold them in.
func TestUsesRequestBodyFromBind(t *testing.T) {
	rt := loadGmailRuntime(t)
	if !rt.UsesRequestBody() {
		t.Fatal("gmail fixture binds request.body.id; UsesRequestBody must be true")
	}
}
