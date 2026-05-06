package admin

import (
	"encoding/json"
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

func TestRequireAuthenticated(t *testing.T) {
	called := false
	wrapped := RequireAuthenticated(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	// Anonymous: 401.
	rec := httptest.NewRecorder()
	wrapped(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status = %d, want 401", rec.Code)
	}
	if called {
		t.Error("anonymous reached the handler")
	}
	assertDenialJSON(t, rec.Result())

	// Authenticated: passes through.
	called = false
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	ctx := auth.WithCaller(req.Context(), auth.Caller{Subject: "a", Role: auth.RoleUser})
	wrapped(rec, req.WithContext(ctx))
	if !called {
		t.Error("user did not reach the handler")
	}
}

func TestRequireAdmin(t *testing.T) {
	called := false
	wrapped := RequireAdmin(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	// Anonymous: 401, not 403, so the caller knows to authenticate.
	rec := httptest.NewRecorder()
	wrapped(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status = %d, want 401", rec.Code)
	}
	if called {
		t.Error("anonymous reached admin handler")
	}

	// Non-admin user: 403.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	ctx := auth.WithCaller(req.Context(), auth.Caller{Subject: "u", Role: auth.RoleUser})
	wrapped(rec, req.WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Errorf("user status = %d, want 403", rec.Code)
	}
	if called {
		t.Error("user reached admin handler")
	}

	// Admin: passes through.
	called = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	ctx = auth.WithCaller(req.Context(), auth.Caller{Subject: "a", Role: auth.RoleAdmin})
	wrapped(rec, req.WithContext(ctx))
	if !called {
		t.Error("admin did not reach the handler")
	}
}

// assertDenialJSON spot-checks that the response body is the
// admin.WriteDenial shape — a JSON object with `next_steps`.
func assertDenialJSON(t *testing.T, resp *http.Response) {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["next_steps"].(map[string]any); !ok {
		t.Errorf("body missing next_steps: %+v", body)
	}
}
