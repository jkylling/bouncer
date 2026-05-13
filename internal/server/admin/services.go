package admin

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/jkylling/bouncer/internal/control/connections"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/services"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Service-surface paths. The connection-mutating /connect endpoint
// delegates to the existing connections.Store; the policy-apply
// endpoints delegate to the existing policies.Service. The package
// keeps no state of its own.
const (
	ServicesPath                = "/_api/services"
	ServiceItemPath             = "/_api/services/{slug}"
	ServiceConnectPath          = "/_api/services/{slug}/connect"
	ServicePoliciesPath         = "/_api/services/{slug}/policies"
	ServicePolicyApplyPath      = "/_api/services/{slug}/policies/{id}/apply"
	ServicePoliciesApplyAllPath = "/_api/services/{slug}/policies/apply"

	// UI shells. Both shells read /_api/services in the browser, so
	// they need no per-request server-side data.
	ServicesUIPath      = "/_admin/services"
	ServiceDetailUIPath = "/_admin/services/{slug}"
)

// MaxServiceBodyBytes caps the JSON body the connect / apply
// endpoints read. Token fields are small; 32 KiB is generous.
const MaxServiceBodyBytes int64 = 1 << 15

// MountServices wires the /_api/services* endpoints. svc is the
// boot-time-frozen registry; connStore is the credential-store
// backing the /connect path; polSvc is the policies service backing
// the suggested-policies apply path. Any of those may be nil — the
// matching endpoint then returns 503 (configurable later).
func MountServices(r chi.Router, svc *services.Registry, connStore *connections.Store, polSvc *policies.Service) {
	r.Get(ServicesPath, listServicesHandler(svc, polSvc))
	r.Get(ServiceItemPath, getServiceHandler(svc, polSvc))
	r.Post(ServiceConnectPath, connectServiceHandler(svc, connStore))
	r.Get(ServicePoliciesPath, listServicePoliciesHandler(svc, polSvc))
	r.Post(ServicePolicyApplyPath, applyServicePolicyHandler(svc, polSvc))
	r.Post(ServicePoliciesApplyAllPath, applyServicePoliciesHandler(svc, polSvc))

	mountUIPage(r, ServicesUIPath, "services")

	// Service detail bakes the resolved Descriptor into the rendered
	// HTML (no client-side fetch + Loading… placeholder) so the page
	// shows up populated on first paint. Falls through to the
	// not-found page when the slug doesn't match a registered
	// service.
	r.Get(ServiceDetailUIPath, serviceDetailUIHandler(svc))
	r.Get(ServiceDetailUIPath+"/", serviceDetailUIHandler(svc))
}

// serviceDetailUIExtra is the per-request bundle the service-detail
// template reads as `.Extra`. The full Descriptor is embedded plus
// a pre-computed initial letter for the icon (avoids template-side
// substring fiddling on non-ASCII titles).
type serviceDetailUIExtra struct {
	*services.Descriptor
	InitialLetter string
}

func serviceDetailUIHandler(svc *services.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		if svc == nil {
			http.NotFound(w, r)
			return
		}
		d, err := svc.Get(slug)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		initial := "?"
		for _, ch := range d.Title {
			initial = strings.ToUpper(string(ch))
			break
		}
		renderPageWith(w, "service_detail", serviceDetailUIExtra{
			Descriptor:    &d,
			InitialLetter: initial,
		})
	}
}

type listServicesResponse struct {
	Services []services.Descriptor `json:"services"`
}

func listServicesHandler(svc *services.Registry, polSvc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if svc == nil {
			writeJSON(w, listServicesResponse{Services: []services.Descriptor{}})
			return
		}
		list := svc.List()
		fillApplied(svc, polSvc, list)
		writeJSON(w, listServicesResponse{Services: list})
	}
}

func getServiceHandler(svc *services.Registry, polSvc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			respondServiceError(w, r, services.ErrUnknown)
			return
		}
		d, err := svc.Get(chi.URLParam(r, "slug"))
		if err != nil {
			respondServiceError(w, r, err)
			return
		}
		fillApplied(svc, polSvc, []services.Descriptor{d})
		writeJSON(w, d)
	}
}

// connectServiceRequest is the body posted to /connect. Variant
// selects which TokenVariant the bundle declared; Fields is the
// per-variant input map keyed by TokenField.Name.
type connectServiceRequest struct {
	Variant string            `json:"variant"`
	Fields  map[string]string `json:"fields"`
}

func connectServiceHandler(svc *services.Registry, store *connections.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSONError(w, "connection store not configured", http.StatusServiceUnavailable)
			return
		}
		var body connectServiceRequest
		if err := decodeJSONBody(w, r, MaxServiceBodyBytes, &body); err != nil {
			respondServiceError(w, r, err)
			return
		}
		slug := chi.URLParam(r, "slug")
		d, err := svc.Get(slug)
		if err != nil {
			respondServiceError(w, r, err)
			return
		}
		// Validate variant + required fields against the bundle's
		// declared shape before we touch the store. A blank variant
		// is rejected — the UI always sends one.
		variant, ok := findVariant(d, body.Variant)
		if !ok {
			writeJSONError(w, fmt.Sprintf("unknown variant %q", body.Variant), http.StatusBadRequest)
			return
		}
		for _, f := range variant.Fields {
			if f.Required && body.Fields[f.Name] == "" {
				writeJSONError(w, fmt.Sprintf("field %q is required", f.Name), http.StatusBadRequest)
				return
			}
		}
		rec, err := store.PutVariant(slug, body.Variant, body.Fields)
		if err != nil {
			respondConnectionError(w, r, err)
			return
		}
		writeJSONStatus(w, http.StatusCreated, "", rec)
	}
}

type servicePoliciesResponse struct {
	Policies []services.PolicyDescriptor `json:"policies"`
}

func listServicePoliciesHandler(svc *services.Registry, polSvc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, err := svc.Get(chi.URLParam(r, "slug"))
		if err != nil {
			respondServiceError(w, r, err)
			return
		}
		fillApplied(svc, polSvc, []services.Descriptor{d})
		writeJSON(w, servicePoliciesResponse{Policies: d.SuggestedPolicy})
	}
}

type applyPolicyResponse struct {
	Applied []models.Policy `json:"applied"`
	Count   int             `json:"count"`
}

func applyServicePolicyHandler(svc *services.Registry, polSvc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if polSvc == nil {
			writeJSONError(w, "policy service not configured", http.StatusServiceUnavailable)
			return
		}
		slug := chi.URLParam(r, "slug")
		id := chi.URLParam(r, "id")
		loaded, err := svc.LoadedSuggestedPolicies(slug)
		if err != nil {
			respondServiceError(w, r, err)
			return
		}
		idx := -1
		for i, p := range loaded {
			if p.Meta.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			writeJSONError(w, fmt.Sprintf("unknown policy %q", id), http.StatusNotFound)
			return
		}
		applied, err := applyPolicyBody(r, polSvc, loaded[idx].YAML)
		if err != nil {
			respondRecipeError(w, r, err) // shares the same error map
			return
		}
		writeJSONStatus(w, http.StatusCreated, "", applyPolicyResponse{Applied: applied, Count: len(applied)})
	}
}

type applyServicePoliciesRequest struct {
	IDs []string `json:"ids"`
}

func applyServicePoliciesHandler(svc *services.Registry, polSvc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if polSvc == nil {
			writeJSONError(w, "policy service not configured", http.StatusServiceUnavailable)
			return
		}
		var body applyServicePoliciesRequest
		if err := decodeJSONBody(w, r, MaxServiceBodyBytes, &body); err != nil {
			respondServiceError(w, r, err)
			return
		}
		slug := chi.URLParam(r, "slug")
		loaded, err := svc.LoadedSuggestedPolicies(slug)
		if err != nil {
			respondServiceError(w, r, err)
			return
		}
		want := make(map[string]bool, len(body.IDs))
		for _, id := range body.IDs {
			want[id] = true
		}
		var allApplied []models.Policy
		for _, p := range loaded {
			if len(body.IDs) > 0 && !want[p.Meta.ID] {
				continue
			}
			if len(body.IDs) == 0 && !p.Meta.DefaultEnabled {
				continue
			}
			applied, err := applyPolicyBody(r, polSvc, p.YAML)
			if err != nil {
				respondRecipeError(w, r, err)
				return
			}
			allApplied = append(allApplied, applied...)
		}
		writeJSONStatus(w, http.StatusCreated, "", applyPolicyResponse{Applied: allApplied, Count: len(allApplied)})
	}
}

// applyPolicyBody decodes one or more multi-doc YAML policy entries
// from the bundle, then persists each through polSvc with the same
// "Create -> Replace on conflict" idempotency the recipe flow uses.
func applyPolicyBody(r *http.Request, polSvc *policies.Service, body []byte) ([]models.Policy, error) {
	dec := yaml.NewDecoder(bytesReader(body))
	dec.KnownFields(true)
	var out []models.Policy
	for {
		var p models.Policy
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%w: %v", policies.ErrInvalid, err)
		}
		if err := polSvc.Create(r.Context(), &p); err != nil {
			if errors.Is(err, policies.ErrConflict) {
				if rerr := polSvc.Replace(r.Context(), p.API, p.Name, &p); rerr != nil {
					return nil, rerr
				}
			} else {
				return nil, err
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// fillApplied looks up each descriptor's suggested-policy entries
// against the live policies.Service and stamps Applied=true on the
// ones whose every declared policy doc is currently live.
func fillApplied(svc *services.Registry, polSvc *policies.Service, list []services.Descriptor) {
	if polSvc == nil {
		return
	}
	live := indexLivePolicies(polSvc)
	for i := range list {
		loaded, err := svc.LoadedSuggestedPolicies(list[i].Slug)
		if err != nil {
			continue
		}
		for j := range list[i].SuggestedPolicy {
			id := list[i].SuggestedPolicy[j].ID
			for _, p := range loaded {
				if p.Meta.ID != id {
					continue
				}
				list[i].SuggestedPolicy[j].Applied = allLive(live, p.YAML)
				break
			}
		}
	}
}

func indexLivePolicies(polSvc *policies.Service) map[string]bool {
	out := map[string]bool{}
	for _, p := range polSvc.List() {
		out[p.API+"/"+p.Name] = true
	}
	return out
}

// allLive reports whether every policy document encoded in body is
// present in the live index. Returns false on any decode error so a
// half-broken bundle never flips Applied=true.
func allLive(live map[string]bool, body []byte) bool {
	dec := yaml.NewDecoder(bytesReader(body))
	dec.KnownFields(true)
	any := false
	for {
		var p models.Policy
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false
		}
		if !live[p.API+"/"+p.Name] {
			return false
		}
		any = true
	}
	return any
}

func findVariant(d services.Descriptor, id string) (services.VariantDescriptor, bool) {
	for _, v := range d.TokenVariants {
		if v.ID == id {
			return v, true
		}
	}
	return services.VariantDescriptor{}, false
}

func respondServiceError(w http.ResponseWriter, r *http.Request, err error) {
	writeMappedError(r.Context(), w, "services", err, []errMap{
		{sentinel: services.ErrUnknown, status: http.StatusNotFound},
	})
}

// bytesReader wraps a []byte in an io.Reader without pulling in
// bytes.Reader for one call site. Kept as a tiny helper so the
// imports stay minimal.
func bytesReader(b []byte) io.Reader { return &byteSliceReader{b: b} }

type byteSliceReader struct {
	b []byte
	i int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
