package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Policy endpoint paths. The collection lives at `/_api/policies`,
// items at `/_api/policies/{api}/{name}`, `:dryRun` is a literal
// sub-resource (Google-style) for compile-without-persist, and
// `:capabilities` reports whether the underlying store accepts writes.
const (
	PoliciesPath             = "/_api/policies"
	PolicyItemPath           = "/_api/policies/{api}/{name}"
	PoliciesDryRunPath       = "/_api/policies:dryRun"
	PoliciesCapabilitiesPath = "/_api/policies:capabilities"
	PoliciesExportPath       = "/_api/policies:export"
	PoliciesImportPath       = "/_api/policies:import"
	PoliciesUIPath           = "/_admin/policies"
)

const (
	// MaxPolicyBodyBytes caps the JSON body the policy endpoints read.
	MaxPolicyBodyBytes int64 = 1 << 16 // 64 KiB

	// MaxImportBodyBytes caps the YAML body on the import endpoint.
	MaxImportBodyBytes int64 = 1 << 20 // 1 MiB
)

// MountPolicies attaches the policy CRUD endpoints to r, backed by
// svc. Following the MountTraffic pattern: the parent server
// constructs the dependency and calls this only when policy CRUD is
// wanted (it's a no-op otherwise).
//
// Per-route access tiers (open / authenticated / admin / login
// redirect) are now expressed in the embedded internal-policy set
// keyed off the action names declared in
// `internal_apis/api.yaml` — this function just wires raw handlers.
func MountPolicies(r chi.Router, svc *policies.Service) {
	r.Get(PoliciesCapabilitiesPath, capabilitiesHandler(svc))
	r.Get(PoliciesPath, listPoliciesHandler(svc))
	r.Get(PolicyItemPath, getPolicyHandler(svc))
	r.Post(PoliciesDryRunPath, dryRunPolicyHandler(svc))
	r.Post(PoliciesPath, createPolicyHandler(svc))
	r.Put(PolicyItemPath, replacePolicyHandler(svc))
	r.Delete(PolicyItemPath, deletePolicyHandler(svc))
	r.Get(PoliciesExportPath, exportPoliciesHandler(svc))
	r.Post(PoliciesImportPath, importPoliciesHandler(svc))
	mountUIPage(r, PoliciesUIPath, "policies")
}

// capabilitiesResponse is the GET /_api/policies:capabilities body.
// `writeable` drives whether the UI exposes create/edit/delete
// affordances; a future field (e.g. backend kind) can be added without
// breaking clients that only read this one.
type capabilitiesResponse struct {
	Writeable bool `json:"writeable"`
}

func capabilitiesHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, capabilitiesResponse{Writeable: svc.Writeable()})
	}
}

// policiesListResponse is the GET /_api/policies body. Wrapped in an
// object so a future field (pagination, version) can be added without
// breaking clients that decoded a bare array.
type policiesListResponse struct {
	Policies []models.Policy `json:"policies"`
}

func listPoliciesHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// `api` can be repeated (?api=foo&api=bar) for per-service
		// policy views that scope to the bundle's full API set in one
		// query. A single value is the legacy single-filter form.
		filters := r.URL.Query()["api"]
		all := svc.List()
		if len(filters) > 0 {
			allow := make(map[string]bool, len(filters))
			for _, f := range filters {
				allow[f] = true
			}
			out := make([]models.Policy, 0, len(all))
			for _, p := range all {
				if allow[p.API] {
					out = append(out, p)
				}
			}
			all = out
		}
		writeJSON(w, policiesListResponse{Policies: all})
	}
}

func getPolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api := chi.URLParam(r, "api")
		name := chi.URLParam(r, "name")
		p, err := svc.Get(api, name)
		if err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		writeJSON(w, p)
	}
}

func createPolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p models.Policy
		if err := decodeJSONBody(w, r, MaxPolicyBodyBytes, &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		if err := svc.Create(r.Context(), &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		// URL-escape both segments: p.API and p.Name come from the
		// caller's JSON body. validAPIName / validPolicyName reject
		// CRLF and other unsafe characters at validate time, but
		// path-escaping defends against a future schema relaxation
		// silently re-opening response-header injection.
		writeJSONStatus(w, http.StatusCreated,
			PoliciesPath+"/"+url.PathEscape(p.API)+"/"+url.PathEscape(p.Name), p)
	}
}

func replacePolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api := chi.URLParam(r, "api")
		name := chi.URLParam(r, "name")
		var p models.Policy
		if err := decodeJSONBody(w, r, MaxPolicyBodyBytes, &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		if err := svc.Replace(r.Context(), api, name, &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		writeJSON(w, p)
	}
}

func deletePolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api := chi.URLParam(r, "api")
		name := chi.URLParam(r, "name")
		if err := svc.Delete(r.Context(), api, name); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// dryRunPolicyHandler validates a policy against the live runtime
// without persisting or applying it. UIs call this on every keystroke
// for live feedback, so the response is JSON-shaped (a structured
// error rather than a bare 400 body) on the *compile* path.
// "Couldn't decode the request at all" — body too large, malformed
// JSON, unknown field — surfaces as the same 4xx the Create / Replace
// paths return, so a future shared HTTP client that retries on 4xx
// vs. 200 doesn't retry-storm against a malformed payload.
func dryRunPolicyHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p models.Policy
		if err := decodeJSONBody(w, r, MaxPolicyBodyBytes, &p); err != nil {
			writePolicyError(r.Context(), w, err)
			return
		}
		if err := svc.Validate(&p); err != nil {
			writeJSON(w, dryRunResponse{OK: false, Error: err.Error()})
			return
		}
		writeJSON(w, dryRunResponse{OK: true})
	}
}

// dryRunResponse is the JSON shape POST /_api/policies:dryRun returns.
// `ok=false` always carries a human-readable error message; `ok=true`
// has neither.
type dryRunResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func exportPoliciesHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filters := r.URL.Query()["api"]
		all := svc.List()
		if len(filters) > 0 {
			allow := make(map[string]bool, len(filters))
			for _, f := range filters {
				allow[f] = true
			}
			out := make([]models.Policy, 0, len(all))
			for _, p := range all {
				if allow[p.API] {
					out = append(out, p)
				}
			}
			all = out
		}

		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", `attachment; filename="policies.yaml"`)
		if len(all) == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		for i := range all {
			if err := enc.Encode(all[i]); err != nil {
				writeJSONError(w, "encode error", http.StatusInternalServerError)
				return
			}
		}
		if err := enc.Close(); err != nil {
			writeJSONError(w, "encode error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}
}

type importResponse struct {
	Created     []string `json:"created"`
	Overwritten []string `json:"overwritten"`
	Errors      []string `json:"errors,omitempty"`
}

func importPoliciesHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxImportBodyBytes)
		defer r.Body.Close()
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeJSONError(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			writeJSONError(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}

		parsed, err := decodePoliciesYAML(raw)
		if err != nil {
			writeJSONError(w, "invalid YAML: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(parsed) == 0 {
			writeJSONError(w, "no policies found in YAML", http.StatusBadRequest)
			return
		}

		dryRun := r.URL.Query().Get("dry_run") == "true"
		result, err := svc.Import(r.Context(), parsed, dryRun)
		resp := importResponse{
			Created:     result.Created,
			Overwritten: result.Overwritten,
			Errors:      result.Errors,
		}
		if err != nil {
			if errors.Is(err, policies.ErrInvalid) {
				writeJSONStatus(w, http.StatusBadRequest, "", resp)
				return
			}
			writePolicyError(r.Context(), w, err)
			return
		}
		writeJSON(w, resp)
	}
}

func decodePoliciesYAML(raw []byte) ([]models.Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var out []models.Policy
	for {
		var p models.Policy
		if err := dec.Decode(&p); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if p.API == "" && p.Name == "" {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func writePolicyError(ctx context.Context, w http.ResponseWriter, err error) {
	writeMappedError(ctx, w, "policies", err, []errMap{
		{sentinel: policies.ErrInvalid, status: http.StatusBadRequest},
		{sentinel: policies.ErrAPIPath, status: http.StatusBadRequest},
		{sentinel: policies.ErrConflict, status: http.StatusConflict},
		{sentinel: policies.ErrNotFound, status: http.StatusNotFound, msg: "not found"},
		{sentinel: policies.ErrReadOnly, status: http.StatusForbidden},
	})
}
