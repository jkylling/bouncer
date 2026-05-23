package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/auth/authtest"
)

// stubUpstream returns an httptest server that asserts the inbound
// form fields and replies with the provided body / status. Returned
// alongside a *string the test can read to introspect the form.
func stubUpstream(t *testing.T, status int, body string) (*httptest.Server, *url.Values) {
	t.Helper()
	form := &url.Values{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*form = r.PostForm
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, form
}

func mustKeys(t *testing.T) *auth.ServerKeys {
	t.Helper()
	keys, err := auth.FromSecret(authtest.Secret())
	require.NoError(t, err)
	return keys
}

func mustRefreshJWT(t *testing.T, keys *auth.ServerKeys, subject, refresh, tokenURL string) string {
	t.Helper()
	tok, err := auth.IssueRefreshToken(keys, subject, auth.RefreshCreds{
		RefreshToken: refresh,
		TokenURL:     tokenURL,
	}, 0, false)
	require.NoError(t, err)
	return tok
}

// post is a small wrapper that fires a form-encoded POST against
// the handler. Returns the parsed JSON body and the status so the
// per-test assertions stay focused on the protocol, not transport.
func post(t *testing.T, h http.Handler, form url.Values) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	}
	return rec.Code, body
}

// TestRefreshHappyPath: a valid refresh JWT + matching upstream
// returns 200 with a fresh access JWT that verifies under the
// proxy's keys and points at the upstream's new access token.
func TestRefreshHappyPath(t *testing.T) {
	upstream, form := stubUpstream(t, http.StatusOK, `{"access_token":"new-upstream-at","expires_in":3600,"token_type":"Bearer"}`)
	keys := mustKeys(t)
	refresh := mustRefreshJWT(t, keys, "agent-1", "rt-original", upstream.URL)

	h := New(keys, http.DefaultClient, 0)
	status, body := post(t, h, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {"client-id-x"},
		"client_secret": {"client-secret-y"},
	})

	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "Bearer", body["token_type"])
	require.NotEmpty(t, body["access_token"])
	require.InDelta(t, 3570, body["expires_in"], 1)
	require.NotContains(t, body, "refresh_token", "no refresh in response when upstream did not rotate")

	// Upstream form: refresh token is from the *blob*, client_id /
	// client_secret are from the inbound form, grant_type is fixed.
	require.Equal(t, "refresh_token", form.Get("grant_type"))
	require.Equal(t, "rt-original", form.Get("refresh_token"))
	require.Equal(t, "client-id-x", form.Get("client_id"))
	require.Equal(t, "client-secret-y", form.Get("client_secret"))

	// New access JWT verifies and points at the new upstream token.
	newAccess, err := auth.VerifyAccessToken(keys, body["access_token"].(string))
	require.NoError(t, err)
	require.Equal(t, "agent-1", newAccess.Subject)
	require.Equal(t, "new-upstream-at", newAccess.Creds.AccessToken)
}

// TestRefreshRotation: when upstream returns a new refresh_token
// the handler issues a new refresh JWT, decryptable against the
// proxy keys, carrying the rotated upstream refresh + same
// token_url.
func TestRefreshRotation(t *testing.T) {
	upstream, _ := stubUpstream(t, http.StatusOK, `{"access_token":"new-at","expires_in":3600,"refresh_token":"rt-rotated"}`)
	keys := mustKeys(t)
	refresh := mustRefreshJWT(t, keys, "u", "rt-original", upstream.URL)

	h := New(keys, http.DefaultClient, 0)
	status, body := post(t, h, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})

	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, "refresh_token")
	rotated, err := auth.VerifyRefreshToken(keys, body["refresh_token"].(string))
	require.NoError(t, err)
	require.Equal(t, "rt-rotated", rotated.Creds.RefreshToken)
	require.Equal(t, upstream.URL, rotated.Creds.TokenURL, "token_url preserved across rotation")
}

// TestRefreshHeadersPropagateToAccess pins the refresh→access
// header propagation: a refresh JWT issued with extra Headers makes
// every freshly-rotated access JWT carry those same headers, so the
// forward path stamps them on subsequent calls. Used by upstreams
// that pair an OAuth2 bearer with a fixed per-call header
// (X-Tenant-ID, etc.).
func TestRefreshHeadersPropagateToAccess(t *testing.T) {
	upstream, _ := stubUpstream(t, http.StatusOK, `{"access_token":"new-at","expires_in":3600,"token_type":"Bearer"}`)
	keys := mustKeys(t)
	refreshJWT, err := auth.IssueRefreshToken(keys, "u", auth.RefreshCreds{
		RefreshToken: "rt-original",
		TokenURL:     upstream.URL,
		Headers: []auth.Header{
			{Name: "X-Tenant-ID", Value: "tenant-42"},
		},
	}, 0, false)
	require.NoError(t, err)

	h := New(keys, http.DefaultClient, 0)
	status, body := post(t, h, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshJWT},
	})
	require.Equal(t, http.StatusOK, status)

	access, err := auth.VerifyAccessToken(keys, body["access_token"].(string))
	require.NoError(t, err)
	require.Len(t, access.Creds.Headers, 1)
	require.Equal(t, "X-Tenant-ID", access.Creds.Headers[0].Name)
	require.Equal(t, "tenant-42", access.Creds.Headers[0].Value)
}

// TestRefreshHeadersSurviveRotation pins the headers-propagate-on-
// rotation case: when upstream rotates the refresh token, the new
// refresh JWT carries the original Headers list forward (otherwise
// the next /token call would lose them).
func TestRefreshHeadersSurviveRotation(t *testing.T) {
	upstream, _ := stubUpstream(t, http.StatusOK, `{"access_token":"new-at","expires_in":3600,"refresh_token":"rt-rotated"}`)
	keys := mustKeys(t)
	refreshJWT, err := auth.IssueRefreshToken(keys, "u", auth.RefreshCreds{
		RefreshToken: "rt-original",
		TokenURL:     upstream.URL,
		Headers:      []auth.Header{{Name: "X-Tenant-ID", Value: "tenant-42"}},
	}, 0, false)
	require.NoError(t, err)

	h := New(keys, http.DefaultClient, 0)
	status, body := post(t, h, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshJWT},
	})
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, "refresh_token")

	rotated, err := auth.VerifyRefreshToken(keys, body["refresh_token"].(string))
	require.NoError(t, err)
	require.Equal(t, "rt-rotated", rotated.Creds.RefreshToken)
	require.Len(t, rotated.Creds.Headers, 1, "headers must survive rotation")
	require.Equal(t, "X-Tenant-ID", rotated.Creds.Headers[0].Name)
}

// TestRefreshNoRotationWhenSame: upstream returning the same
// refresh value back (some providers do) should *not* issue a new
// refresh JWT — no rotation happened, the client already has the
// right one.
func TestRefreshNoRotationWhenSame(t *testing.T) {
	upstream, _ := stubUpstream(t, http.StatusOK, `{"access_token":"new-at","expires_in":3600,"refresh_token":"rt-same"}`)
	keys := mustKeys(t)
	refresh := mustRefreshJWT(t, keys, "u", "rt-same", upstream.URL)

	h := New(keys, http.DefaultClient, 0)
	status, body := post(t, h, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, body, "refresh_token")
}

// TestRotatedRefreshCappedByOriginal pins B6: the rotated refresh
// JWT cannot extend lifetime past the original's exp. With an
// original TTL of 1 hour and a configured refresh-ttl of 24 hours,
// rotation must produce a token whose exp is bounded by the 1-hour
// original — otherwise a chain of rotations grows the lifetime
// without bound.
func TestRotatedRefreshCappedByOriginal(t *testing.T) {
	upstream, _ := stubUpstream(t, http.StatusOK, `{"access_token":"new-at","expires_in":3600,"refresh_token":"rt-rotated"}`)
	keys := mustKeys(t)
	// IssueRefreshToken with a 1-hour exp so the original carries
	// one. mustRefreshJWT issues with no expiry, which is the wrong
	// shape for this test — the cap is what we're proving.
	refresh, err := auth.IssueRefreshToken(keys, "u", auth.RefreshCreds{
		RefreshToken: "rt-original",
		TokenURL:     upstream.URL,
	}, time.Hour, false)
	require.NoError(t, err)

	// Configure the handler with a 24h TTL — well past the original's.
	h := New(keys, http.DefaultClient, 24*time.Hour)
	status, body := post(t, h, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, "refresh_token")

	rotated, err := auth.VerifyRefreshToken(keys, body["refresh_token"].(string))
	require.NoError(t, err)
	// Rotated exp must not exceed original's (1 hour) by any
	// meaningful margin. A few seconds of test scheduler slack is
	// fine; 23 hours of slack would mean the cap didn't apply.
	require.False(t, rotated.ExpiresAt.IsZero(), "rotated token must carry an exp")
	require.WithinDuration(t, time.Now().Add(time.Hour), rotated.ExpiresAt, 2*time.Minute,
		"rotated exp must be capped by the original's 1-hour exp, not the configured 24h")
}

// TestRotatedRefreshTTL covers the small piecewise-min table. The
// "exhausted-original" rows pin an original exp that
// has passed (admitted by the verifier's leeway) must NOT produce a
// rotated JWT, because dropping `exp` (TTL=0) silently extends
// lifetime past the operator's intent.
func TestRotatedRefreshTTL(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		originalExp time.Time
		configured  time.Duration
		wantTTL     time.Duration
		wantOK      bool
	}{
		{"both zero", time.Time{}, 0, 0, true},
		{"only configured", time.Time{}, time.Hour, time.Hour, true},
		{"only original", now.Add(time.Hour), 0, time.Hour, true},
		{"original shorter", now.Add(time.Hour), 24 * time.Hour, time.Hour, true},
		{"configured shorter", now.Add(24 * time.Hour), time.Hour, time.Hour, true},
		{"original already past, configured set", now.Add(-time.Hour), time.Hour, 0, false},
		{"original already past, configured zero", now.Add(-time.Hour), 0, 0, false},
		{"original at now", now, time.Hour, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTTL, gotOK := rotatedRefreshTTL(tc.originalExp, tc.configured, now)
			require.Equal(t, tc.wantTTL, gotTTL, "ttl")
			require.Equal(t, tc.wantOK, gotOK, "ok")
		})
	}
}

// TestExhaustedRefreshRejectedBeforeUpstream pins the early-refusal
// guard: when the original refresh JWT's `exp` is past at /token
// time (admitted only by the verifier's 30s leeway), the proxy
// returns 400 invalid_grant *without* hitting upstream. Calling the
// upstream first would consume its rotated refresh token for a JWT
// the proxy refuses to issue, leaving the client stuck.
func TestExhaustedRefreshRejectedBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"access_token":"x","expires_in":3600,"refresh_token":"rt-rotated"}`)
	}))
	t.Cleanup(upstream.Close)

	keys := mustKeys(t)
	// Issue a refresh JWT whose exp is already past (1ns TTL). The
	// verifier admits it via the 30s leeway window; our guard at
	// ServeHTTP entry should still refuse it.
	refresh, err := auth.IssueRefreshToken(keys, "u", auth.RefreshCreds{
		RefreshToken: "rt-original",
		TokenURL:     upstream.URL,
	}, time.Nanosecond, false)
	require.NoError(t, err)

	h := New(keys, http.DefaultClient, 0)
	status, body := post(t, h, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_grant", body["error"])
	require.Zero(t, upstreamCalls.Load(),
		"exhausted-refresh path must not call upstream")
}

// TestRefreshShortLivedRefuses: when upstream returns a TTL inside
// the verifier's leeway window the proxy cannot issue a JWT that
// stops being accepted before its embedded upstream token expires.
// Refuse with 503 rather than admit a near-expired token.
func TestRefreshShortLivedRefuses(t *testing.T) {
	for _, expiresIn := range []int{0, 10, 30} {
		t.Run(fmt.Sprintf("expires_in=%d", expiresIn), func(t *testing.T) {
			body := fmt.Sprintf(`{"access_token":"new-at","expires_in":%d}`, expiresIn)
			upstream, _ := stubUpstream(t, http.StatusOK, body)
			keys := mustKeys(t)
			refresh := mustRefreshJWT(t, keys, "u", "rt", upstream.URL)

			h := New(keys, http.DefaultClient, 0)
			status, resp := post(t, h, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refresh},
			})
			require.Equal(t, http.StatusServiceUnavailable, status)
			require.Equal(t, "temporarily_unavailable", resp["error"])
		})
	}
}

// TestErrors covers the RFC 6749 §5.2 error mapping table from the
// plan. One subtest per row keeps the failure mode obvious.
func TestErrors(t *testing.T) {
	keys := mustKeys(t)

	cases := []struct {
		name       string
		setup      func(t *testing.T) (*Handler, url.Values)
		wantStatus int
		wantCode   string
	}{
		{
			name: "missing_grant_type",
			setup: func(t *testing.T) (*Handler, url.Values) {
				return New(keys, http.DefaultClient, 0), url.Values{}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "unsupported_grant_type",
		},
		{
			name: "unknown_grant_type",
			setup: func(t *testing.T) (*Handler, url.Values) {
				return New(keys, http.DefaultClient, 0), url.Values{"grant_type": {"password"}}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "unsupported_grant_type",
		},
		{
			name: "missing_refresh_token",
			setup: func(t *testing.T) (*Handler, url.Values) {
				return New(keys, http.DefaultClient, 0), url.Values{"grant_type": {"refresh_token"}}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name: "garbled_refresh_jwt",
			setup: func(t *testing.T) (*Handler, url.Values) {
				return New(keys, http.DefaultClient, 0), url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {"not-a-jwt"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_grant",
		},
		{
			name: "wrong_typ", // an access JWT presented as a refresh JWT
			setup: func(t *testing.T) (*Handler, url.Values) {
				access, err := auth.IssueAccessToken(keys, "u", auth.AccessCreds{AccessToken: "x"}, time.Hour, false)
				require.NoError(t, err)
				return New(keys, http.DefaultClient, 0), url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {access},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_grant",
		},
		{
			name: "upstream_4xx",
			setup: func(t *testing.T) (*Handler, url.Values) {
				upstream, _ := stubUpstream(t, http.StatusBadRequest, `{"error":"invalid_grant"}`)
				return New(keys, http.DefaultClient, 0), url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {mustRefreshJWT(t, keys, "u", "rt", upstream.URL)},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_grant",
		},
		{
			name: "upstream_5xx",
			setup: func(t *testing.T) (*Handler, url.Values) {
				upstream, _ := stubUpstream(t, http.StatusInternalServerError, `oops`)
				return New(keys, http.DefaultClient, 0), url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {mustRefreshJWT(t, keys, "u", "rt", upstream.URL)},
				}
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "temporarily_unavailable",
		},
		{
			name: "upstream_unreachable",
			setup: func(t *testing.T) (*Handler, url.Values) {
				return New(keys, http.DefaultClient, 0), url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {mustRefreshJWT(t, keys, "u", "rt", "http://127.0.0.1:1")},
				}
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "temporarily_unavailable",
		},
		{
			name: "upstream_no_access_token",
			setup: func(t *testing.T) (*Handler, url.Values) {
				upstream, _ := stubUpstream(t, http.StatusOK, `{"token_type":"Bearer","expires_in":60}`)
				return New(keys, http.DefaultClient, 0), url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {mustRefreshJWT(t, keys, "u", "rt", upstream.URL)},
				}
			},
			wantStatus: http.StatusBadGateway,
			wantCode:   "server_error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, form := tc.setup(t)
			form.Set("grant_type", form.Get("grant_type"))
			req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, tc.wantStatus, rec.Code, "body=%s", rec.Body)
			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tc.wantCode, body["error"])
		})
	}
}

// TestRefreshRejectsBadTokenURL pins the SSRF guard: a refresh JWT
// pointing at a non-loopback http URL or a non-http(s) scheme is
// rejected with invalid_grant before any upstream call fires.
func TestRefreshRejectsBadTokenURL(t *testing.T) {
	keys := mustKeys(t)
	cases := []string{
		"http://internal.svc:8080/token", // non-loopback http
		"file:///etc/passwd",             // non-http scheme
		"gopher://example.com/0",
	}
	for _, tokenURL := range cases {
		t.Run(tokenURL, func(t *testing.T) {
			refresh := mustRefreshJWT(t, keys, "u", "rt", tokenURL)
			h := New(keys, http.DefaultClient, 0)
			status, body := post(t, h, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refresh},
			})
			require.Equal(t, http.StatusBadRequest, status)
			require.Equal(t, "invalid_grant", body["error"])
		})
	}
}

func TestValidateTokenURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://oauth2.googleapis.com/token", false},
		{"http://127.0.0.1:8080/token", false},
		{"http://localhost/token", false},
		{"http://[::1]:9000/token", false},
		{"http://internal.svc:8080/token", true},
		{"http://10.0.0.1/token", true},
		{"file:///etc/passwd", true},
		{"gopher://example.com/0", true},
		{"https:///nopath", true}, // empty host
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			err := validateTokenURL(tc.url)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMethodNotAllowed: the handler is POST-only (RFC 6749).
func TestMethodNotAllowed(t *testing.T) {
	h := New(mustKeys(t), http.DefaultClient, 0)
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	require.Equal(t, "POST", rec.Header().Get("Allow"))
}

// TestRefreshTTLAppliesOnRotation: when --refresh-ttl is set, a
// rotated refresh JWT carries the matching exp.
func TestRefreshTTLAppliesOnRotation(t *testing.T) {
	upstream, _ := stubUpstream(t, http.StatusOK, `{"access_token":"new-at","expires_in":3600,"refresh_token":"rt-rotated"}`)
	keys := mustKeys(t)
	refresh := mustRefreshJWT(t, keys, "u", "rt-orig", upstream.URL)

	h := New(keys, http.DefaultClient, 7*24*time.Hour)
	_, body := post(t, h, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	rotated := body["refresh_token"].(string)

	// Verify is enough — if exp is rejected the verifier would
	// 401, so a successful verify says it parsed.
	got, err := auth.VerifyRefreshToken(keys, rotated)
	require.NoError(t, err)
	require.Equal(t, "rt-rotated", got.Creds.RefreshToken)
}
