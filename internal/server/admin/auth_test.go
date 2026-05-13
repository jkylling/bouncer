package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/auth"
)

// TestAuthMiddlewareBuildsCallerFromHeader pins the happy path: a
// valid Bearer JWT is verified, the resulting Caller is stashed in
// the request context, and the downstream handler reads it back.
func TestAuthMiddlewareBuildsCallerFromHeader(t *testing.T) {
	keys := mustKeys(t)
	tok, err := auth.IssueAccessToken(keys, "alice", auth.AccessCreds{AccessToken: "x"}, time.Hour, true)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var seen auth.Caller
	h := AuthMiddleware(keys)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = auth.CallerFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen.Subject != "alice" || seen.Role != auth.RoleAdmin {
		t.Errorf("Caller = %+v, want {alice, admin}", seen)
	}
}

// TestAuthMiddlewareCookieFallback: the admin UI presents the JWT
// via cookie, not header. The middleware must accept it.
func TestAuthMiddlewareCookieFallback(t *testing.T) {
	keys := mustKeys(t)
	tok, _ := auth.IssueAccessToken(keys, "bob", auth.AccessCreds{AccessToken: "x"}, time.Hour, false)

	var seen auth.Caller
	h := AuthMiddleware(keys)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = auth.CallerFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.AddCookie(&http.Cookie{Name: AdminCookieName, Value: tok})
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen.Subject != "bob" || seen.Role != auth.RoleUser {
		t.Errorf("Caller = %+v, want {bob, user}", seen)
	}
}

// TestAuthMiddlewareAnonymousOnNoCreds: open routes still serve
// when no Authorization or cookie is present. The middleware does
// not reject; that's the per-route helper's job.
func TestAuthMiddlewareAnonymousOnNoCreds(t *testing.T) {
	var seen auth.Caller
	h := AuthMiddleware(mustKeys(t))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = auth.CallerFromContext(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/anything", nil))
	if seen.IsAuthenticated() {
		t.Errorf("Caller = %+v, want anonymous", seen)
	}
}

// TestAuthMiddlewareAnonymousOnBadJWT: a malformed/expired/wrong-key
// JWT degrades to anonymous rather than rejecting. The per-route
// helper decides whether anonymous is acceptable; an open endpoint
// shouldn't 401 because someone happened to send a stale cookie.
func TestAuthMiddlewareAnonymousOnBadJWT(t *testing.T) {
	var seen auth.Caller
	h := AuthMiddleware(mustKeys(t))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = auth.CallerFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen.IsAuthenticated() {
		t.Errorf("Caller = %+v, want anonymous on bad JWT", seen)
	}
}

// Per-route admin/auth gating moved out of this package — see
// TestInternalPolicyMiddleware in internal_policy_test.go for the
// equivalent end-to-end coverage against each embedded policy set.
