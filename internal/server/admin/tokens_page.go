package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/services"
	"github.com/jkylling/bouncer/internal/control/tokens"
)

// Tokens page paths. /_admin/tokens is the form; the issue endpoints
// below handle submission and double as the external HTTP issue API.
const (
	TokensUIPath           = "/_admin/tokens"
	TokensIssuePath        = "/_api/tokens/issue"
	TokensIssueRefreshPath = "/_api/tokens/issue/refresh"
)

// defaultAccessTokenTTL is the access-JWT lifetime issued from the
// tokens screen. Mirrors the cmd/issue-token default.
const defaultAccessTokenTTL = 1 * time.Hour

// MaxTokensIssueBodyBytes caps the JSON body the tokens-issue
// endpoints accept. The payload is one raw spec or one variant + a
// small map of per-field values; 64 KiB is generous.
const MaxTokensIssueBodyBytes int64 = 1 << 16

// MountTokensPage wires the tokens UI shell plus the matching issue
// endpoints. The services Registry resolves variant metadata at
// request time (no per-token persistence).
func MountTokensPage(r chi.Router, keys *auth.ServerKeys, svc *services.Registry) {
	mountUIPage(r, TokensUIPath, "tokens")
	r.Post(TokensIssuePath, tokensIssueHandler(keys, svc))
	r.Post(TokensIssueRefreshPath, tokensIssueRefreshHandler(keys, svc))
}

// tokensIssueRequest is the variant-form body posted to
// /_api/tokens/issue and /_api/tokens/issue/refresh. Subject is
// required (rides as the JWT `sub` claim); Service + Variant pick the
// bundle's TokenVariant; Fields is the per-variant input map keyed by
// TokenField.Name.
type tokensIssueRequest struct {
	Subject string            `json:"subject"`
	Service string            `json:"service"`
	Variant string            `json:"variant"`
	Fields  map[string]string `json:"fields"`
}

// IssueResponse is the JSON shape both issue endpoints return.
// ExpiresAt is a pointer so a non-expiring refresh JWT omits the
// field rather than carrying a misleading 0001-01-01 timestamp.
// Exported so external callers (and the integration test living in
// the parent package) can decode without restating the shape.
type IssueResponse struct {
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// isVariantRequest reports whether the body carries the tokens-form
// shape. `service` is not a field on either raw spec, so its
// presence is an unambiguous discriminator.
func isVariantRequest(raw []byte) bool {
	var probe struct {
		Service string `json:"service"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.Service != ""
}

// tokensIssueHandler serves POST /_api/tokens/issue — the single
// access-JWT issue endpoint. Two body shapes land here, dispatched
// by isVariantRequest:
//
//   - the tokens-page form ({subject, service, variant, fields}):
//     variant metadata resolves server-side into credential headers.
//   - a raw tokens.Spec: the curl/CLI-parity shape — the same JSON
//     cmd/issue-token reads from --credentials-file, so a payload
//     from one source replays cleanly through the other.
//
// Admin gating is enforced upstream by InternalPolicyMiddleware
// against the `tokens_issue` action.
func tokensIssueHandler(keys *auth.ServerKeys, svc *services.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := readIssueBody(w, r)
		if err != nil {
			respondTokensError(w, r, err)
			return
		}
		if !isVariantRequest(raw) {
			var spec tokens.Spec
			if err := decodeStrict(raw, &spec); err != nil {
				respondTokensError(w, r, err)
				return
			}
			res, err := tokens.Issue(r.Context(), keys, &spec)
			if err != nil {
				respondTokensError(w, r, err)
				return
			}
			exp := res.ExpiresAt
			writeJSON(w, IssueResponse{Token: res.Token, ExpiresAt: &exp})
			return
		}
		body, err := decodeIssueRequest(w, r, raw)
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
		writeJSON(w, IssueResponse{Token: tok, ExpiresAt: &exp})
	}
}

// tokensIssueRefreshHandler is the refresh-JWT counterpart — same
// two-shape dispatch with tokens.RefreshSpec as the raw form.
func tokensIssueRefreshHandler(keys *auth.ServerKeys, svc *services.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := readIssueBody(w, r)
		if err != nil {
			respondTokensError(w, r, err)
			return
		}
		if !isVariantRequest(raw) {
			var spec tokens.RefreshSpec
			if err := decodeStrict(raw, &spec); err != nil {
				respondTokensError(w, r, err)
				return
			}
			res, err := tokens.IssueRefresh(r.Context(), keys, &spec)
			if err != nil {
				respondTokensError(w, r, err)
				return
			}
			out := IssueResponse{Token: res.Token}
			if !res.ExpiresAt.IsZero() {
				out.ExpiresAt = &res.ExpiresAt
			}
			writeJSON(w, out)
			return
		}
		body, err := decodeIssueRequest(w, r, raw)
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
		writeJSON(w, IssueResponse{Token: tok})
	}
}

// readIssueBody slurps the capped request body so the handler can
// dispatch on shape before the strict decode.
func readIssueBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxTokensIssueBodyBytes)
	defer r.Body.Close()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, errBodyTooLarge
		}
		return nil, &decodeError{cause: err}
	}
	return raw, nil
}

// decodeStrict is decodeJSONBody's unknown-field-rejecting decode
// over already-read bytes.
func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return &decodeError{cause: err}
	}
	return nil
}

func decodeIssueRequest(w http.ResponseWriter, r *http.Request, raw []byte) (*tokensIssueRequest, error) {
	var body tokensIssueRequest
	if err := decodeStrict(raw, &body); err != nil {
		respondTokensError(w, r, err)
		return nil, err
	}
	if strings.TrimSpace(body.Subject) == "" {
		writeJSONError(w, "subject is required", http.StatusBadRequest)
		return nil, errors.New("subject")
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
			// Caller fault: wrapped in ErrInvalidSpec so
			// respondTokensError maps it to 400, not a logged 500.
			return bundles.TokenVariant{}, fmt.Errorf("%w: field %q is required", tokens.ErrInvalidSpec, f.Name)
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
		// Caller fault (every optional field left empty) -> 400.
		// Template render errors above stay unwrapped: a broken
		// Header/Template pair is bundle-config fault, and a 500 +
		// error log is the right operator signal.
		return auth.AccessCreds{}, fmt.Errorf("%w: no field values supplied", tokens.ErrInvalidSpec)
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
		{sentinel: tokens.ErrInvalidSpec, status: http.StatusBadRequest},
	})
}
