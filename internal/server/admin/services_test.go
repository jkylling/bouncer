package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/connections"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/services"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// servicesFixture builds the smallest plausible /_api/services
// surface: one bundle named "google" (matches the connections
// allow-list), one token variant with a required field, one
// suggested policy (`p1`) referenced by the live runtime under
// API "google".
func servicesFixture(t *testing.T) (
	*httptest.Server,
	*services.Registry,
	*connections.Store,
	*policies.Service,
	string,
) {
	t.Helper()

	suggested := bundles.LoadedSuggestedPolicy{
		Meta: bundles.SuggestedPolicy{
			ID:             "p1",
			Title:          "Permit everything",
			DefaultEnabled: true,
		},
		YAML: []byte(policyYAML("google", "p1")),
	}
	defaultOff := bundles.LoadedSuggestedPolicy{
		Meta: bundles.SuggestedPolicy{
			ID:    "p2",
			Title: "Off by default",
		},
		YAML: []byte(policyYAML("google", "p2")),
	}
	loaded := []bundles.LoadedService{{
		Service: &bundles.Service{
			Slug:        "google",
			Title:       "Google",
			Description: "Google Workspace",
		},
		TokenVariants: []bundles.TokenVariant{{
			ID:    "service-account",
			Title: "Service account",
			Fields: []bundles.TokenField{{
				Name:     "access_token",
				Required: true,
			}},
		}},
		SuggestedPolicies: []bundles.LoadedSuggestedPolicy{suggested, defaultOff},
		APIs:              []string{"google"},
		BundleName:        "google",
	}}

	connStore := connections.NewStore(filepath.Join(t.TempDir(), "connections"))
	reg := services.New(loaded, nil, connStore)

	b := runtime.NewBuilder()
	if err := b.AddAPI(trivialAPI("google")); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	polSvc := policies.New(rt, policies.NewMemoryStore())

	keys := mustKeys(t)
	r := testRouter(keys)
	MountServices(r, reg, connStore, polSvc)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	return ts, reg, connStore, polSvc, adminBearer(t, keys)
}

// policyYAML returns one valid models.Policy doc the trivial API
// accepts. Result=permit + always-true condition keeps the runtime
// validator from rejecting it on compile.
func policyYAML(api, name string) string {
	return "api: " + api + "\n" +
		"name: " + name + "\n" +
		"action: \"true\"\n" +
		"condition: \"true\"\n" +
		"result: permit\n"
}

func doServiceJSON(t *testing.T, bearer, method, url string, body any) *http.Response {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new req: %v", err)
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

func TestListServicesEmptyOnNilRegistry(t *testing.T) {
	keys := mustKeys(t)
	r := testRouter(keys)
	MountServices(r, nil, nil, nil)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	resp := doServiceJSON(t, adminBearer(t, keys), http.MethodGet, ts.URL+ServicesPath, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out listServicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Services) != 0 {
		t.Fatalf("services = %v, want []", out.Services)
	}
}

func TestListServicesReturnsDescriptors(t *testing.T) {
	ts, _, _, _, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodGet, ts.URL+ServicesPath, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out listServicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Services) != 1 || out.Services[0].Slug != "google" {
		t.Fatalf("services = %+v, want one google entry", out.Services)
	}
	d := out.Services[0]
	if d.Title != "Google" || len(d.TokenVariants) != 1 || len(d.SuggestedPolicy) != 2 {
		t.Fatalf("descriptor mismatch: %+v", d)
	}
}

func TestGetServiceUnknownReturns404(t *testing.T) {
	ts, _, _, _, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodGet, ts.URL+"/_api/services/unknown", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGetServiceAppliedReflectsLivePolicies(t *testing.T) {
	ts, _, _, polSvc, bearer := servicesFixture(t)
	// p1 is applied; p2 isn't.
	if err := polSvc.Create(t.Context(), &models.Policy{
		API: "google", Name: "p1",
		Action: "true", Condition: "true", Result: models.Permit,
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	resp := doServiceJSON(t, bearer, http.MethodGet, ts.URL+"/_api/services/google", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var d services.Descriptor
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	applied := map[string]bool{}
	for _, p := range d.SuggestedPolicy {
		applied[p.ID] = p.Applied
	}
	if !applied["p1"] || applied["p2"] {
		t.Fatalf("applied = %+v, want p1=true p2=false", applied)
	}
}

func TestConnectServiceNilStoreReturns503(t *testing.T) {
	keys := mustKeys(t)
	r := testRouter(keys)
	// Registry must not be nil — the connect handler reaches Get
	// before checking the store, and a nil registry would panic.
	reg := services.New([]bundles.LoadedService{{
		Service: &bundles.Service{Slug: "google", Title: "Google"},
	}}, nil, nil)
	MountServices(r, reg, nil, nil)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	resp := doServiceJSON(t, adminBearer(t, keys), http.MethodPost,
		ts.URL+"/_api/services/google/connect",
		connectServiceRequest{Variant: "any"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestConnectServiceUnknownVariantReturns400(t *testing.T) {
	ts, _, _, _, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodPost,
		ts.URL+"/_api/services/google/connect",
		connectServiceRequest{Variant: "no-such-variant", Fields: map[string]string{"access_token": "x"}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestConnectServiceMissingRequiredFieldReturns400(t *testing.T) {
	ts, _, _, _, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodPost,
		ts.URL+"/_api/services/google/connect",
		connectServiceRequest{Variant: "service-account", Fields: map[string]string{}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "access_token") {
		t.Fatalf("body = %s, want mention of missing field", body)
	}
}

func TestConnectServiceHappyPath(t *testing.T) {
	ts, _, connStore, _, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodPost,
		ts.URL+"/_api/services/google/connect",
		connectServiceRequest{Variant: "service-account", Fields: map[string]string{"access_token": "ya29-fake"}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201, body = %s", resp.StatusCode, body)
	}
	// Store must reflect the variant + fields, not just an empty
	// record — the legacy "Credentials" triple is irrelevant for
	// this variant.
	rec, err := connStore.Get("google")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec.Variant != "service-account" || rec.Fields["access_token"] != "ya29-fake" {
		t.Fatalf("persisted = %+v, want variant=service-account access_token=ya29-fake", rec)
	}
}

func TestListServicePoliciesUnknownReturns404(t *testing.T) {
	ts, _, _, _, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodGet, ts.URL+"/_api/services/unknown/policies", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestApplyServicePolicyNilSvcReturns503(t *testing.T) {
	keys := mustKeys(t)
	r := testRouter(keys)
	reg := services.New([]bundles.LoadedService{{
		Service: &bundles.Service{Slug: "google", Title: "Google"},
	}}, nil, nil)
	MountServices(r, reg, nil, nil)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	resp := doServiceJSON(t, adminBearer(t, keys), http.MethodPost,
		ts.URL+"/_api/services/google/policies/p1/apply", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestApplyServicePolicyUnknownPolicyReturns404(t *testing.T) {
	ts, _, _, _, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodPost,
		ts.URL+"/_api/services/google/policies/nope/apply", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestApplyServicePolicyHappyPath(t *testing.T) {
	ts, _, _, polSvc, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodPost,
		ts.URL+"/_api/services/google/policies/p1/apply", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201, body = %s", resp.StatusCode, body)
	}
	if _, err := polSvc.Get("google", "p1"); err != nil {
		t.Fatalf("post-apply: %v", err)
	}
}

func TestApplyServicePolicyIsIdempotent(t *testing.T) {
	// Two applies of the same policy should both succeed — the
	// service layer falls back to Replace on conflict so the
	// operator can re-click "Apply" without seeing 409.
	ts, _, _, polSvc, bearer := servicesFixture(t)
	for i := 0; i < 2; i++ {
		resp := doServiceJSON(t, bearer, http.MethodPost,
			ts.URL+"/_api/services/google/policies/p1/apply", nil)
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("apply #%d: status = %d, body = %s", i+1, resp.StatusCode, body)
		}
		resp.Body.Close()
	}
	if _, err := polSvc.Get("google", "p1"); err != nil {
		t.Fatalf("post-apply: %v", err)
	}
}

func TestApplyServicePoliciesEmptyIDsAppliesDefaults(t *testing.T) {
	ts, _, _, polSvc, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodPost,
		ts.URL+"/_api/services/google/policies/apply",
		applyServicePoliciesRequest{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	// Only p1 has DefaultEnabled=true.
	if _, err := polSvc.Get("google", "p1"); err != nil {
		t.Fatalf("p1: %v", err)
	}
	if _, err := polSvc.Get("google", "p2"); err == nil {
		t.Fatalf("p2 was applied but DefaultEnabled=false")
	}
}

func TestApplyServicePoliciesSpecificIDs(t *testing.T) {
	ts, _, _, polSvc, bearer := servicesFixture(t)
	resp := doServiceJSON(t, bearer, http.MethodPost,
		ts.URL+"/_api/services/google/policies/apply",
		applyServicePoliciesRequest{IDs: []string{"p2"}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if _, err := polSvc.Get("google", "p2"); err != nil {
		t.Fatalf("p2: %v", err)
	}
	if _, err := polSvc.Get("google", "p1"); err == nil {
		t.Fatalf("p1 was applied but not requested")
	}
}

func TestFindVariant(t *testing.T) {
	d := services.Descriptor{
		TokenVariants: []services.VariantDescriptor{
			{ID: "a"}, {ID: "b"},
		},
	}
	if _, ok := findVariant(d, "a"); !ok {
		t.Fatal("a not found")
	}
	if _, ok := findVariant(d, "missing"); ok {
		t.Fatal("missing should not be found")
	}
}

func TestBytesReaderRoundTrips(t *testing.T) {
	in := []byte("hello, world")
	out, err := io.ReadAll(bytesReader(in))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out) != string(in) {
		t.Fatalf("out = %q, want %q", out, in)
	}
}

func TestAllLive(t *testing.T) {
	live := map[string]bool{"google/p1": true}
	doc := []byte(policyYAML("google", "p1"))
	if !allLive(live, doc) {
		t.Fatal("allLive returned false for a present doc")
	}
	missing := []byte(policyYAML("google", "p2"))
	if allLive(live, missing) {
		t.Fatal("allLive returned true for a missing doc")
	}
	// A two-doc body where one is missing must be false.
	both := append(append([]byte{}, doc...), []byte("---\n")...)
	both = append(both, missing...)
	if allLive(live, both) {
		t.Fatal("allLive returned true for a partial match")
	}
	// Empty body → false (no docs, nothing to be live).
	if allLive(live, nil) {
		t.Fatal("allLive returned true for an empty body")
	}
}
