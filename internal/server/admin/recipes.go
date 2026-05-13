package admin

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/recipes"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Recipe endpoint paths. /preview returns rendered policy YAML without
// touching the store; /apply persists through the existing
// policies.Service so the same validate-then-write discipline applies.
const (
	RecipesListPath    = "/_api/recipes"
	RecipesPreviewPath = "/_api/recipes/{id}/preview"
	RecipesApplyPath   = "/_api/recipes/{id}/apply"
)

// MaxRecipeBodyBytes caps the JSON body /preview and /apply read —
// the parameter struct is tiny (label names, a window, an address)
// so a small cap keeps a hostile body from wasting cycles.
const MaxRecipeBodyBytes int64 = 1 << 14

// MountRecipes wires the recipes endpoints. svc is optional: when
// nil, /apply returns 501 (the same opt-in pattern other admin
// surfaces use). /preview never writes so it doesn't need svc.
func MountRecipes(r chi.Router, svc *policies.Service) {
	r.Get(RecipesListPath, listRecipesHandler())
	r.Post(RecipesPreviewPath, previewRecipeHandler())
	r.Post(RecipesApplyPath, applyRecipeHandler(svc))
}

// recipeMeta is the per-recipe shape the list endpoint surfaces.
// Recipe.Render is a func — uncopiable and not interesting to the
// client — so we project Render-free metadata.
type recipeMeta struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type listRecipesResponse struct {
	Recipes []recipeMeta `json:"recipes"`
}

func listRecipesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		all := recipes.All()
		out := make([]recipeMeta, 0, len(all))
		for _, rcp := range all {
			out = append(out, recipeMeta{ID: rcp.ID, Title: rcp.Title, Description: rcp.Description})
		}
		writeJSON(w, listRecipesResponse{Recipes: out})
	}
}

type previewResponse struct {
	YAML     string          `json:"yaml"`
	Policies []models.Policy `json:"policies"`
	Count    int             `json:"count"`
}

func previewRecipeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params recipes.Params
		if err := decodeJSONBody(w, r, MaxRecipeBodyBytes, &params); err != nil {
			respondRecipeError(w, r, err)
			return
		}
		rcp, err := recipes.Get(chi.URLParam(r, "id"))
		if err != nil {
			respondRecipeError(w, r, err)
			return
		}
		out, err := rcp.Render(params)
		if err != nil {
			respondRecipeError(w, r, err)
			return
		}
		yamlBody, err := encodePoliciesYAML(out)
		if err != nil {
			respondRecipeError(w, r, err)
			return
		}
		writeJSON(w, previewResponse{YAML: yamlBody, Policies: out, Count: len(out)})
	}
}

type applyResponse struct {
	Applied []models.Policy `json:"applied"`
	Count   int             `json:"count"`
}

func applyRecipeHandler(svc *policies.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			writeJSONError(w, "policy service not configured", http.StatusServiceUnavailable)
			return
		}
		var params recipes.Params
		if err := decodeJSONBody(w, r, MaxRecipeBodyBytes, &params); err != nil {
			respondRecipeError(w, r, err)
			return
		}
		rcp, err := recipes.Get(chi.URLParam(r, "id"))
		if err != nil {
			respondRecipeError(w, r, err)
			return
		}
		out, err := rcp.Render(params)
		if err != nil {
			respondRecipeError(w, r, err)
			return
		}
		for i := range out {
			p := out[i]
			if err := svc.Create(r.Context(), &p); err != nil {
				respondPolicyAlreadyExistsOr(w, r, err, svc, &p)
				return
			}
		}
		writeJSONStatus(w, http.StatusCreated, "", applyResponse{Applied: out, Count: len(out)})
	}
}

// respondPolicyAlreadyExistsOr falls back to Replace when Create
// reports a duplicate — re-applying a recipe should be idempotent
// from the operator's view ("apply two-label" twice is "I want
// two-label live", not "fail because it already exists"). Other
// errors flow through the standard mapper.
func respondPolicyAlreadyExistsOr(w http.ResponseWriter, r *http.Request, err error, svc *policies.Service, p *models.Policy) {
	if isPolicyAlreadyExists(err) {
		if rerr := svc.Replace(r.Context(), p.API, p.Name, p); rerr == nil {
			return
		} else {
			err = rerr
		}
	}
	respondRecipeError(w, r, err)
}

// isPolicyAlreadyExists reports whether err is the policies service's
// duplicate-create signal. The policies package exports ErrConflict;
// matching via errors.Is keeps us decoupled from wording.
func isPolicyAlreadyExists(err error) bool {
	return errors.Is(err, policies.ErrConflict)
}

// encodePoliciesYAML renders policies as a multi-document YAML stream.
// One document per policy mirrors the on-disk file-store shape.
func encodePoliciesYAML(ps []models.Policy) (string, error) {
	var out []byte
	for i, p := range ps {
		if i > 0 {
			out = append(out, []byte("---\n")...)
		}
		b, err := yaml.Marshal(p)
		if err != nil {
			return "", err
		}
		out = append(out, b...)
	}
	return string(out), nil
}

func respondRecipeError(w http.ResponseWriter, r *http.Request, err error) {
	writeMappedError(r.Context(), w, "recipes", err, []errMap{
		{sentinel: recipes.ErrUnknown, status: http.StatusNotFound},
		{sentinel: recipes.ErrInvalid, status: http.StatusBadRequest},
		{sentinel: policies.ErrInvalid, status: http.StatusBadRequest},
		{sentinel: policies.ErrReadOnly, status: http.StatusForbidden},
	})
}
