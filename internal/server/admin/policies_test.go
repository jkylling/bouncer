package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// trivialAPI is the smallest API the runtime accepts: one match-all
// action, no metas. Keeps these tests focused on the HTTP layer.
func trivialAPI(name string) *models.API {
	return &models.API{
		Name:         name,
		BaseURL:      "https://" + name + ".invalid",
		PathPrefixes: []string{"/" + name},
		Actions: []models.Action{{
			Name:   "any",
			Filter: "true",
		}},
	}
}

func policyServer(t *testing.T) (*httptest.Server, *policies.Service, string) {
	t.Helper()
	b := runtime.NewBuilder()
	if err := b.AddAPI(trivialAPI("svc")); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	svc := policies.New(rt, policies.NewMemoryStore())
	keys := mustKeys(t)
	r := testRouter(keys)
	MountPolicies(r, svc)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, svc, adminBearer(t, keys)
}

func goodPolicy() models.Policy {
	return models.Policy{
		API:       "svc",
		Name:      "p1",
		Action:    "true",
		Condition: "true",
		Result:    models.Permit,
	}
}

// doJSON fires method+url with body marshalled as JSON. bearer is
// attached as the Authorization header when non-empty; pass an
// empty string to test the unauthenticated denial path.
func doJSON(t *testing.T, bearer, method, url string, body any) *http.Response {
	t.Helper()
	var raw []byte
	if body != nil {
		switch b := body.(type) {
		case []byte:
			raw = b
		case string:
			raw = []byte(b)
		default:
			var err error
			raw, err = json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestPoliciesCreateGetListDelete(t *testing.T) {
	ts, _, bearer := policyServer(t)
	p := goodPolicy()

	resp := doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesPath, p)
	// 201 must carry both Content-Type (so clients decode the body)
	// and Location (RFC convention for "created"). Header().Set
	// after WriteHeader is silently dropped, so a regression here
	// is invisible without an explicit assertion.
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("create Content-Type = %q, want application/json", ct)
	}
	if loc, want := resp.Header.Get("Location"), PoliciesPath+"/svc/p1"; loc != want {
		t.Errorf("create Location = %q, want %q", loc, want)
	}
	requireStatus(t, resp, http.StatusCreated).Body.Close()

	got := decodeOK[models.Policy](t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesPath+"/svc/p1", nil),
		http.StatusOK)
	if got != p {
		t.Errorf("got %+v, want %+v", got, p)
	}

	list := decodeOK[policiesListResponse](t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesPath, nil), http.StatusOK)
	if len(list.Policies) != 1 || list.Policies[0].Name != "p1" {
		t.Errorf("list = %+v, want one entry named p1", list)
	}

	requireStatus(t,
		doJSON(t, bearer, http.MethodDelete, ts.URL+PoliciesPath+"/svc/p1", nil),
		http.StatusNoContent).Body.Close()

	requireStatus(t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesPath+"/svc/p1", nil),
		http.StatusNotFound).Body.Close()
}

func TestPoliciesCreateConflictReturns409(t *testing.T) {
	ts, _, bearer := policyServer(t)
	p := goodPolicy()
	doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesPath, p).Body.Close()
	requireStatus(t,
		doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesPath, p),
		http.StatusConflict).Body.Close()
}

func TestPoliciesReplaceMismatchedPathReturns400(t *testing.T) {
	ts, _, bearer := policyServer(t)
	p := goodPolicy()
	// Body says name=p1, URL says name=other.
	requireStatus(t,
		doJSON(t, bearer, http.MethodPut, ts.URL+PoliciesPath+"/svc/other", p),
		http.StatusBadRequest).Body.Close()
}

func TestPoliciesDryRunOK(t *testing.T) {
	ts, _, bearer := policyServer(t)
	dr := decodeOK[dryRunResponse](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesDryRunPath, goodPolicy()),
		http.StatusOK)
	if !dr.OK || dr.Error != "" {
		t.Errorf("got %+v, want ok=true", dr)
	}
}

func TestPoliciesDryRunSurfacesCompileErr(t *testing.T) {
	ts, _, bearer := policyServer(t)
	bad := goodPolicy()
	bad.Condition = "no_such_var"
	// Always 200 — :dryRun returns the error in the body so editor
	// UIs can render it inline without intercepting non-2xx.
	dr := decodeOK[dryRunResponse](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesDryRunPath, bad),
		http.StatusOK)
	if dr.OK {
		t.Errorf("got ok=true, want false for bad condition")
	}
	if dr.Error == "" {
		t.Errorf("error empty, want compile message")
	}
}

// TestPoliciesDryRunDecodeErrorReturns4xx pins R19 S7: a request
// that doesn't decode at all (malformed JSON, unknown field,
// body-too-large) should surface as the same 4xx the Create/Replace
// paths return — not as 200 with `{ok:false}`. Compile errors keep
// the 200-in-body shape so the editor UI's keystroke loop still
// renders them without intercepting non-2xx.
func TestPoliciesDryRunDecodeErrorReturns4xx(t *testing.T) {
	ts, _, bearer := policyServer(t)
	resp := doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesDryRunPath, []byte(`{"condition":"true","unknown_field":1}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for decode error", resp.StatusCode)
	}
}

func TestPoliciesUnknownFieldReturns400(t *testing.T) {
	ts, _, bearer := policyServer(t)
	body := []byte(`{"api":"svc","name":"p1","action":"true","conditions":"true","result":"permit"}`)
	requireStatus(t,
		doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesPath, body),
		http.StatusBadRequest).Body.Close()
}

// TestPoliciesEmptyBodyHitsValidator pins the empty-body shape: a
// POST with no body decodes as the zero models.Policy, which the
// service rejects via Validate ("api is required") rather than the
// raw "invalid JSON: EOF" the decoder would surface. Same 400 either
// way; the message is the operator-visible difference.
func TestPoliciesEmptyBodyHitsValidator(t *testing.T) {
	ts, _, bearer := policyServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+PoliciesPath, http.NoBody)
	req.Header.Set("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "api is required") {
		t.Errorf("body = %q, want validator message", body)
	}
}

// TestPoliciesCapabilitiesReportsWriteable covers the default — a
// freshly mounted Service has no read-only flag set, so the UI sees
// `writeable: true` and exposes the create/edit/delete affordances.
func TestPoliciesCapabilitiesReportsWriteable(t *testing.T) {
	ts, _, bearer := policyServer(t)
	got := decodeOK[capabilitiesResponse](t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesCapabilitiesPath, nil),
		http.StatusOK)
	if !got.Writeable {
		t.Errorf("writeable = false, want true on a fresh Service")
	}
}

// TestPoliciesReadOnlyRejectsWrites pins the readonly contract end to
// end: capabilities reports false, the UI page still serves, reads
// still work, and every mutating verb returns 403 + ErrReadOnly text.
func TestPoliciesReadOnlyRejectsWrites(t *testing.T) {
	ts, svc, bearer := policyServer(t)

	// Seed one policy before flipping the switch so the read paths
	// have something to surface.
	seed := goodPolicy()
	if err := svc.Create(context.Background(), &seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc.SetReadOnly(true)

	caps := decodeOK[capabilitiesResponse](t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesCapabilitiesPath, nil),
		http.StatusOK)
	if caps.Writeable {
		t.Errorf("writeable = true after SetReadOnly(true)")
	}

	// Reads survive.
	requireStatus(t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesPath, nil),
		http.StatusOK).Body.Close()

	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, PoliciesPath, goodPolicy()},
		{http.MethodPut, PoliciesPath + "/svc/p1", goodPolicy()},
		{http.MethodDelete, PoliciesPath + "/svc/p1", nil},
	}
	for _, c := range cases {
		resp := doJSON(t, bearer, c.method, ts.URL+c.path, c.body)
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("%s %s status = %d, want 403 (body=%s)", c.method, c.path, resp.StatusCode, body)
		}
		resp.Body.Close()
	}
}

// TestPoliciesUIIndexEmbedsHTML pins the UI handler: it must serve
// the embedded policies.html page as text/html with no-store caching.
// Without the no-store header a rebuilt binary's UI would stick around
// after a redeploy until the operator hard-refreshed.
func TestPoliciesUIIndexEmbedsHTML(t *testing.T) {
	ts, _, bearer := policyServer(t)
	for _, path := range []string{PoliciesUIPath, PoliciesUIPath + "/"} {
		resp := doJSON(t, bearer, http.MethodGet, ts.URL+path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("%s Content-Type = %q", path, ct)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s Cache-Control = %q", path, cc)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(body, []byte("Policies")) {
			t.Errorf("%s body missing Policies marker", path)
		}
	}
}

func TestPoliciesExportReturnsYAML(t *testing.T) {
	ts, _, bearer := policyServer(t)
	p := goodPolicy()
	doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesPath, p).Body.Close()

	resp := doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesExportPath, nil)
	requireStatus(t, resp, http.StatusOK)
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "application/x-yaml" {
		t.Errorf("Content-Type = %q, want application/x-yaml", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "policies.yaml") {
		t.Errorf("Content-Disposition = %q, want attachment with policies.yaml", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "name: p1") {
		t.Errorf("body missing policy name, got:\n%s", body)
	}
}

func TestPoliciesExportEmpty(t *testing.T) {
	ts, _, bearer := policyServer(t)
	resp := doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesExportPath, nil)
	requireStatus(t, resp, http.StatusOK)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(bytes.TrimSpace(body)) != 0 {
		t.Errorf("expected empty export, got:\n%s", body)
	}
}

func doRaw(t *testing.T, bearer, method, url, contentType string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestPoliciesImportCreatesNew(t *testing.T) {
	ts, _, bearer := policyServer(t)
	yamlBody := []byte("api: svc\nname: imported\naction: \"true\"\ncondition: \"true\"\nresult: permit\n")

	resp := doRaw(t, bearer, http.MethodPost, ts.URL+PoliciesImportPath, "application/x-yaml", yamlBody)
	got := decodeOK[importResponse](t, resp, http.StatusOK)
	if len(got.Created) != 1 || got.Created[0] != "svc/imported" {
		t.Errorf("created = %v, want [svc/imported]", got.Created)
	}
	if len(got.Overwritten) != 0 {
		t.Errorf("overwritten = %v, want empty", got.Overwritten)
	}
}

func TestPoliciesImportOverwriteReported(t *testing.T) {
	ts, _, bearer := policyServer(t)
	p := goodPolicy()
	doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesPath, p).Body.Close()

	yamlBody := []byte("api: svc\nname: p1\naction: \"true\"\ncondition: \"true\"\nresult: deny\n")
	resp := doRaw(t, bearer, http.MethodPost, ts.URL+PoliciesImportPath, "application/x-yaml", yamlBody)
	got := decodeOK[importResponse](t, resp, http.StatusOK)
	if len(got.Overwritten) != 1 || got.Overwritten[0] != "svc/p1" {
		t.Errorf("overwritten = %v, want [svc/p1]", got.Overwritten)
	}
}

func TestPoliciesImportDryRun(t *testing.T) {
	ts, _, bearer := policyServer(t)
	yamlBody := []byte("api: svc\nname: drytest\naction: \"true\"\ncondition: \"true\"\nresult: permit\n")

	resp := doRaw(t, bearer, http.MethodPost, ts.URL+PoliciesImportPath+"?dry_run=true", "application/x-yaml", yamlBody)
	got := decodeOK[importResponse](t, resp, http.StatusOK)
	if len(got.Created) != 1 {
		t.Errorf("created = %v, want 1 entry", got.Created)
	}

	// Verify nothing was actually persisted.
	list := decodeOK[policiesListResponse](t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesPath, nil), http.StatusOK)
	if len(list.Policies) != 0 {
		t.Errorf("list after dry-run = %d, want 0", len(list.Policies))
	}
}

func TestPoliciesImportInvalidYAML(t *testing.T) {
	ts, _, bearer := policyServer(t)
	resp := doRaw(t, bearer, http.MethodPost, ts.URL+PoliciesImportPath, "application/x-yaml", []byte("not: valid: yaml: ["))
	requireStatus(t, resp, http.StatusBadRequest).Body.Close()
}

func TestPoliciesImportValidationError(t *testing.T) {
	ts, _, bearer := policyServer(t)
	yamlBody := []byte("api: svc\nname: bad\naction: \"true\"\ncondition: no_such_var\nresult: permit\n")
	resp := doRaw(t, bearer, http.MethodPost, ts.URL+PoliciesImportPath, "application/x-yaml", yamlBody)
	requireStatus(t, resp, http.StatusBadRequest)
	defer resp.Body.Close()
	var got importResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Errors) == 0 {
		t.Errorf("errors empty, want validation message")
	}
}

func TestPoliciesImportEmpty(t *testing.T) {
	ts, _, bearer := policyServer(t)
	resp := doRaw(t, bearer, http.MethodPost, ts.URL+PoliciesImportPath, "application/x-yaml", []byte(""))
	requireStatus(t, resp, http.StatusBadRequest).Body.Close()
}

func TestPoliciesImportRoundTrip(t *testing.T) {
	ts, _, bearer := policyServer(t)
	p := goodPolicy()
	doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesPath, p).Body.Close()

	// Export
	exportResp := doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesExportPath, nil)
	requireStatus(t, exportResp, http.StatusOK)
	yamlBody, _ := io.ReadAll(exportResp.Body)
	exportResp.Body.Close()

	// Delete the existing policy
	doJSON(t, bearer, http.MethodDelete, ts.URL+PoliciesPath+"/svc/p1", nil).Body.Close()

	// Import the exported YAML
	importResp := doRaw(t, bearer, http.MethodPost, ts.URL+PoliciesImportPath, "application/x-yaml", yamlBody)
	got := decodeOK[importResponse](t, importResp, http.StatusOK)
	if len(got.Created) != 1 {
		t.Errorf("round-trip created = %v, want 1", got.Created)
	}

	// Verify it's back
	list := decodeOK[policiesListResponse](t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesPath, nil), http.StatusOK)
	if len(list.Policies) != 1 || list.Policies[0].Name != "p1" {
		t.Errorf("round-trip list = %+v, want one entry named p1", list.Policies)
	}
}

func TestPoliciesListFiltersByAPI(t *testing.T) {
	// Adds two APIs so we can verify ?api= filtering.
	b := runtime.NewBuilder()
	if err := b.AddAPI(trivialAPI("a")); err != nil {
		t.Fatalf("add api a: %v", err)
	}
	if err := b.AddAPI(trivialAPI("b")); err != nil {
		t.Fatalf("add api b: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	svc := policies.New(rt, policies.NewMemoryStore())
	keys := mustKeys(t)
	r := testRouter(keys)
	MountPolicies(r, svc)
	ts := httptest.NewServer(r)
	defer ts.Close()
	bearer := adminBearer(t, keys)

	for _, p := range []models.Policy{
		{API: "a", Name: "p", Action: "true", Condition: "true", Result: models.Permit},
		{API: "b", Name: "p", Action: "true", Condition: "true", Result: models.Permit},
	} {
		doJSON(t, bearer, http.MethodPost, ts.URL+PoliciesPath, p).Body.Close()
	}
	list := decodeOK[policiesListResponse](t,
		doJSON(t, bearer, http.MethodGet, ts.URL+PoliciesPath+"?api=a", nil),
		http.StatusOK)
	if len(list.Policies) != 1 || list.Policies[0].API != "a" {
		t.Errorf("list = %+v, want one entry on api=a", list)
	}
}
