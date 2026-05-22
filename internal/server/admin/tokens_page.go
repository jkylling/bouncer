package admin

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/services"
)

// Tokens page paths. /_admin/tokens is the form; the issue endpoints
// at /_api/issue/tokens and /_api/issue/refresh handle submission
// (those are mounted in admin.go).
const (
	TokensUIPath           = "/_admin/tokens"
	TokensIssuePath        = "/_api/tokens/issue"
	TokensIssueRefreshPath = "/_api/tokens/issue/refresh"
)

// defaultAccessTokenTTL is the access-JWT lifetime issued from the
// tokens screen. Mirrors the cmd/issue-token default.
const defaultAccessTokenTTL = 1 * time.Hour

// MaxTokensIssueBodyBytes caps the JSON body the tokens-issue
// endpoints accept. The payload is one variant + a small map of
// per-field values; 32 KiB is generous.
const MaxTokensIssueBodyBytes int64 = 1 << 15

// MountTokensPage wires the tokens UI shell plus the matching issue
// endpoints. The services Registry resolves variant metadata at
// request time (no per-token persistence).
func MountTokensPage(r chi.Router, keys *auth.ServerKeys, svc *services.Registry) {
	mountUIPage(r, TokensUIPath, "tokens")
	r.Post(TokensIssuePath, tokensIssueHandler(keys, svc))
	r.Post(TokensIssueRefreshPath, tokensIssueRefreshHandler(keys, svc))
}

// tokensIssueRequest is the body posted to /_api/tokens/issue and
// /_api/tokens/issue/refresh. Subject is required (rides as the JWT
// `sub` claim); Service + Variant pick the bundle's TokenVariant;
// Fields is the per-variant input map keyed by TokenField.Name.
type tokensIssueRequest struct {
	Subject string            `json:"subject"`
	Service string            `json:"service"`
	Variant string            `json:"variant"`
	Fields  map[string]string `json:"fields"`
}

// tokensIssueResponse mirrors admin.IssueResponse — kept as its own
// type so the UI's deserialization is decoupled from the older
// shape used by the raw /_api/issue/tokens endpoint.
type tokensIssueResponse struct {
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func tokensIssueHandler(keys *auth.ServerKeys, svc *services.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := decodeIssueRequest(w, r)
		if err != nil {
			return
		}
		variant, err := resolveVariant(svc, body)
		if err != nil {
			respondTokensError(w, r, err)
			return
		}
		if variant.Refresh != nil {
			writeJSONError(w, "variant is refresh-only; POST to "+TokensIssueRefreshPath, http.StatusBadRequest)
			return
		}
		creds, err := buildAccessCreds(variant, body.Fields)
		if err != nil {
			respondTokensError(w, r, err)
			return
		}
		ttl := defaultAccessTokenTTL
		tok, err := auth.IssueAccessToken(keys, body.Subject, creds, ttl, false)
		if err != nil {
			respondTokensError(w, r, fmt.Errorf("issue: %w", err))
			return
		}
		exp := time.Now().Add(ttl)
		writeJSON(w, tokensIssueResponse{Token: tok, ExpiresAt: &exp})
	}
}

func tokensIssueRefreshHandler(keys *auth.ServerKeys, svc *services.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := decodeIssueRequest(w, r)
		if err != nil {
			return
		}
		variant, err := resolveVariant(svc, body)
		if err != nil {
			respondTokensError(w, r, err)
			return
		}
		if variant.Refresh == nil {
			writeJSONError(w, "variant does not declare a refresh token_url", http.StatusBadRequest)
			return
		}
		refreshTok := body.Fields["refresh_token"]
		if refreshTok == "" {
			writeJSONError(w, `field "refresh_token" is required`, http.StatusBadRequest)
			return
		}
		creds := auth.RefreshCreds{
			RefreshToken: refreshTok,
			TokenURL:     variant.Refresh.TokenURL,
		}
		tok, err := auth.IssueRefreshToken(keys, body.Subject, creds, 0, false)
		if err != nil {
			respondTokensError(w, r, fmt.Errorf("issue: %w", err))
			return
		}
		writeJSON(w, tokensIssueResponse{Token: tok})
	}
}

func decodeIssueRequest(w http.ResponseWriter, r *http.Request) (*tokensIssueRequest, error) {
	var body tokensIssueRequest
	if err := decodeJSONBody(w, r, MaxTokensIssueBodyBytes, &body); err != nil {
		respondTokensError(w, r, err)
		return nil, err
	}
	if strings.TrimSpace(body.Subject) == "" {
		writeJSONError(w, "subject is required", http.StatusBadRequest)
		return nil, errors.New("subject")
	}
	if strings.TrimSpace(body.Service) == "" {
		writeJSONError(w, "service is required", http.StatusBadRequest)
		return nil, errors.New("service")
	}
	if strings.TrimSpace(body.Variant) == "" {
		writeJSONError(w, "variant is required", http.StatusBadRequest)
		return nil, errors.New("variant")
	}
	return &body, nil
}

// resolveVariant looks up the requested variant on the registry and
// validates that every required field on the variant has a non-empty
// value in the submission.
func resolveVariant(svc *services.Registry, body *tokensIssueRequest) (bundles.TokenVariant, error) {
	if svc == nil {
		return bundles.TokenVariant{}, errors.New("services registry not configured")
	}
	v, err := svc.Variant(body.Service, body.Variant)
	if err != nil {
		return bundles.TokenVariant{}, err
	}
	for _, f := range v.Fields {
		if f.Required && strings.TrimSpace(body.Fields[f.Name]) == "" {
			return bundles.TokenVariant{}, fmt.Errorf("field %q is required", f.Name)
		}
	}
	return v, nil
}

// buildAccessCreds renders each declared field through its
// Header/Template pair (with defaults) and collects the resulting
// rows into an auth.AccessCreds.Headers slice.
func buildAccessCreds(v bundles.TokenVariant, fields map[string]string) (auth.AccessCreds, error) {
	headers := make([]auth.Header, 0, len(v.Fields))
	for _, f := range v.Fields {
		val := fields[f.Name]
		if val == "" {
			// Optional, unfilled — skip rather than emit an empty
			// header.
			continue
		}
		name := f.Header
		if name == "" {
			name = "Authorization"
		}
		tmpl := f.Template
		if tmpl == "" {
			if strings.EqualFold(name, "Authorization") {
				tmpl = "Bearer {{.}}"
			} else {
				tmpl = "{{.}}"
			}
		}
		rendered, err := renderTemplate(tmpl, val)
		if err != nil {
			return auth.AccessCreds{}, fmt.Errorf("field %q: %w", f.Name, err)
		}
		headers = append(headers, auth.Header{Name: name, Value: rendered})
	}
	if len(headers) == 0 {
		return auth.AccessCreds{}, errors.New("no field values supplied")
	}
	return auth.AccessCreds{Headers: headers}, nil
}

func renderTemplate(body, value string) (string, error) {
	t, err := template.New("hdr").Parse(body)
	if err != nil {
		return "", fmt.Errorf("parse template %q: %w", body, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, value); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

func respondTokensError(w http.ResponseWriter, r *http.Request, err error) {
	writeMappedError(r.Context(), w, "tokens", err, []errMap{
		{sentinel: services.ErrUnknown, status: http.StatusNotFound},
	})
}
