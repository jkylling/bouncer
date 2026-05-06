// Package oauth implements POST /token (RFC 6749 §6, refresh_token
// grant). Clients present a refresh JWT issued by issue-token; the
// handler exchanges its embedded upstream refresh token for a fresh
// upstream access token and returns a new proxy access JWT.
//
// Threat-model rule: upstream error bodies are never echoed. Every
// failure collapses to one of the four RFC 6749 §5.2 codes so
// clients cannot probe upstream behaviour through the proxy.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/httpdo"
	"github.com/jkylling/bouncer/internal/observability"
)

// Path is the canonical mount path. Exported so the parent server
// (and tests) can reference it without restating the literal.
const Path = "/token"

// MaxFormBodyBytes caps the form body the handler will read. The
// payload is one refresh request — a few hundred bytes in practice
// — so 16 KiB is generous.
const MaxFormBodyBytes int64 = 1 << 14

// MaxUpstreamBodyBytes caps the JSON body we read from upstream.
// 64 KiB easily holds an OAuth2 token response; capping the read
// stops a hostile or broken upstream from OOMing the proxy.
const MaxUpstreamBodyBytes int64 = 1 << 16

var tracerName = observability.PackagePath()

// Handler holds the dependencies POST /token needs. Constructed
// once at boot and reused across requests.
type Handler struct {
	keys       *auth.ServerKeys
	httpClient httpdo.Client

	// refreshTTL controls the `exp` of newly-issued refresh JWTs
	// when the upstream rotates the refresh token. Zero means "no
	// exp", matching the default issue-token shape so a rotation
	// does not silently shrink the refresh lifetime.
	refreshTTL time.Duration
}

// New constructs a Handler. httpClient is used for the upstream
// /token POST; production wiring passes the same instrumented
// client used elsewhere in the server so refresh calls show up as
// child spans of the inbound request.
func New(keys *auth.ServerKeys, httpClient httpdo.Client, refreshTTL time.Duration) *Handler {
	return &Handler{keys: keys, httpClient: httpClient, refreshTTL: refreshTTL}
}

// ServeHTTP implements http.Handler. POST-only; the form is parsed
// inside one helper so the per-error logic stays in one place.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, errOAuth(http.StatusMethodNotAllowed, "invalid_request", "POST required"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, errOAuth(http.StatusBadRequest, "invalid_request", "could not parse form"))
		return
	}
	if grant := r.PostForm.Get("grant_type"); grant != "refresh_token" {
		writeError(w, errOAuth(http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("grant_type %q not supported (only refresh_token)", grant)))
		return
	}

	refreshJWT := r.PostForm.Get("refresh_token")
	if refreshJWT == "" {
		writeError(w, errOAuth(http.StatusBadRequest, "invalid_request", "refresh_token required"))
		return
	}
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")

	rt, err := auth.VerifyRefreshToken(h.keys, refreshJWT)
	if err != nil {
		// Verify failures cover signature, exp (if present), AEAD,
		// and typ mismatch. They all collapse to invalid_grant per
		// the plan so we don't telegraph which check failed.
		writeError(w, errOAuth(http.StatusBadRequest, "invalid_grant", "refresh token rejected"))
		slog.WarnContext(r.Context(), "refresh verify failed", "err", err)
		return
	}

	// Refuse a refresh JWT whose `exp` is past — the verifier admits
	// up to AccessLeeway past exp to absorb clock skew, but issuing
	// a rotated JWT off an exhausted original would either silently
	// extend lifetime (TTL=0 → no exp) or burn an upstream rotation
	// for a JWT we cannot honour. Force the client to re-auth here,
	// before we touch the upstream.
	if !rt.ExpiresAt.IsZero() && !rt.ExpiresAt.After(time.Now()) {
		writeError(w, errOAuth(http.StatusBadRequest, "invalid_grant", "refresh token expired"))
		slog.InfoContext(r.Context(), "refresh exhausted, re-auth required",
			"subject", rt.Subject, "exp", rt.ExpiresAt)
		return
	}

	upstream, err := h.exchange(r.Context(), rt.Creds, clientID, clientSecret)
	if err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.issueResponse(rt, upstream)
	if err != nil {
		slog.ErrorContext(r.Context(), "issue refresh response", "err", err)
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.ErrorContext(r.Context(), "encode refresh response", "err", err)
	}
}

// exchange does the upstream /token POST. The form is built
// internally so the upstream call shape never accidentally mirrors
// the inbound form (e.g. forwarding stray fields). errOAuth values
// returned from this method are written verbatim to the client.
func (h *Handler) exchange(ctx context.Context, creds auth.RefreshCreds, clientID, clientSecret string) (upstreamTokens, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "oauth.exchange")
	defer span.End()

	if err := validateTokenURL(creds.TokenURL); err != nil {
		// SSRF defense in depth: a leaked secret or mis-configured
		// issue-token could otherwise issue a JWT pointing at an
		// arbitrary internal http URL.
		return upstreamTokens{}, errOAuth(http.StatusBadRequest, "invalid_grant", "refresh token rejected")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", creds.RefreshToken)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, creds.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return upstreamTokens{}, errOAuth(http.StatusInternalServerError, "server_error", "could not build upstream request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return upstreamTokens{}, errOAuth(http.StatusServiceUnavailable, "temporarily_unavailable", "upstream unreachable")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxUpstreamBodyBytes+1))
	if err != nil {
		return upstreamTokens{}, errOAuth(http.StatusServiceUnavailable, "temporarily_unavailable", "could not read upstream response")
	}
	if int64(len(body)) > MaxUpstreamBodyBytes {
		return upstreamTokens{}, errOAuth(http.StatusServiceUnavailable, "temporarily_unavailable", "upstream response too large")
	}

	if resp.StatusCode >= 500 {
		return upstreamTokens{}, errOAuth(http.StatusServiceUnavailable, "temporarily_unavailable", "upstream service error")
	}
	if resp.StatusCode >= 400 {
		// Upstream rejected the credentials (bad client_secret,
		// revoked refresh token, etc.). All collapse to invalid_grant
		// so the upstream's error vocabulary does not leak through.
		return upstreamTokens{}, errOAuth(http.StatusBadRequest, "invalid_grant", "upstream rejected refresh")
	}

	var u upstreamTokens
	if err := json.Unmarshal(body, &u); err != nil {
		return upstreamTokens{}, errOAuth(http.StatusBadGateway, "server_error", "could not parse upstream response")
	}
	if u.AccessToken == "" {
		return upstreamTokens{}, errOAuth(http.StatusBadGateway, "server_error", "upstream returned no access_token")
	}
	return u, nil
}

// issueResponse builds the OAuth2 success body. New access JWT every
// time; new refresh JWT only when upstream rotated. All error
// returns are *oauthError so the caller can write them verbatim.
func (h *Handler) issueResponse(rt *auth.RefreshToken, u upstreamTokens) (response, error) {
	// Shrink the access JWT TTL by the verifier's leeway window so
	// the proxy never admits a JWT whose embedded upstream token has
	// already expired upstream. If the upstream TTL is shorter than
	// the leeway, refuse so the client retries on a rotation rather
	// than getting a JWT it cannot safely present.
	accessTTL := time.Duration(u.ExpiresIn) * time.Second
	if accessTTL <= auth.AccessLeeway {
		return response{}, errOAuth(http.StatusServiceUnavailable, "temporarily_unavailable",
			"upstream access TTL too short to issue a safe access token")
	}
	accessTTL -= auth.AccessLeeway
	accessJWT, err := auth.IssueAccessToken(h.keys, rt.Subject, auth.AccessCreds{
		AccessToken: u.AccessToken,
		Headers:     rt.Creds.Headers,
	}, accessTTL, rt.Admin)
	if err != nil {
		return response{}, errOAuth(http.StatusInternalServerError, "server_error", "could not issue access token")
	}
	resp := response{
		AccessToken: accessJWT,
		TokenType:   "Bearer",
		ExpiresIn:   int64(accessTTL / time.Second),
	}
	if u.RefreshToken != "" && u.RefreshToken != rt.Creds.RefreshToken {
		// Cap rotated refresh-JWT lifetime by the original's
		// remaining lifetime. Without this a chain of rotations
		// would extend lifetime indefinitely. ServeHTTP rejects
		// past-exp originals before reaching here, so the (0, false)
		// branch is defence in depth.
		ttl, ok := rotatedRefreshTTL(rt.ExpiresAt, h.refreshTTL, time.Now())
		if !ok {
			return resp, nil
		}
		newRefresh, err := auth.IssueRefreshToken(h.keys, rt.Subject, auth.RefreshCreds{
			RefreshToken: u.RefreshToken,
			TokenURL:     rt.Creds.TokenURL,
			Headers:      rt.Creds.Headers,
		}, ttl, rt.Admin)
		if err != nil {
			return response{}, errOAuth(http.StatusInternalServerError, "server_error", "could not issue refresh token")
		}
		resp.RefreshToken = newRefresh
	}
	return resp, nil
}

// rotatedRefreshTTL returns the TTL the rotated refresh JWT should
// carry. The bool reports whether the rotated JWT can be safely
// issued at all:
//
//   - both bounds zero → ttl=0, ok=true (no exp on either side, the
//     non-expiring shape).
//   - only configured set → ttl=configured, ok=true.
//   - only original set, in the future → ttl=remaining, ok=true.
//   - both set → ttl=min(remaining, configured), ok=true.
//   - original set but remaining ≤ 0 → ok=false. Caller skips the
//     rotation; the client falls through to re-auth.
func rotatedRefreshTTL(originalExp time.Time, configuredTTL time.Duration, now time.Time) (time.Duration, bool) {
	if originalExp.IsZero() {
		return configuredTTL, true
	}
	remaining := originalExp.Sub(now)
	if remaining <= 0 {
		return 0, false
	}
	if configuredTTL == 0 || remaining < configuredTTL {
		return remaining, true
	}
	return configuredTTL, true
}

// validateTokenURL enforces the SSRF policy on the JWT-embedded
// refresh URL. https is allowed everywhere; http only to loopback so
// httptest-backed integration tests keep working without poking a
// hole for production.
func validateTokenURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("token_url parse: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("token_url has no host: %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("token_url http allowed only to loopback, got %q", raw)
	default:
		return fmt.Errorf("token_url scheme %q not allowed", u.Scheme)
	}
}

// upstreamTokens is the subset of an OAuth2 token response the
// handler uses. Extra fields (id_token, scope, etc.) are ignored.
type upstreamTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
}

// response is the OAuth2 success body shape.
type response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// oauthError is a typed RFC 6749 §5.2 error: a status code paired
// with the JSON `error` / `error_description` body.
type oauthError struct {
	Status      int
	Code        string
	Description string
}

func (e *oauthError) Error() string {
	return fmt.Sprintf("oauth %d %s: %s", e.Status, e.Code, e.Description)
}

func errOAuth(status int, code, description string) error {
	return &oauthError{Status: status, Code: code, Description: description}
}

// writeError serialises any error as an RFC 6749 §5.2 JSON body
// when it is an *oauthError; falls back to a generic server_error
// otherwise so an unwrapped error never reaches the client as a
// stack-trace-leaking response.
func writeError(w http.ResponseWriter, err error) {
	var oe *oauthError
	if !errors.As(err, &oe) {
		oe = &oauthError{Status: http.StatusInternalServerError, Code: "server_error", Description: "unexpected error"}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(oe.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             oe.Code,
		"error_description": oe.Description,
	})
}
