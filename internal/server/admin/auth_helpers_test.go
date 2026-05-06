package admin

import (
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
)

// testRouter returns a chi.Router with the auth middleware
// already wired against keys. Centralised so every per-test mount
// point picks up the same gate the production Router does — a
// future tweak to the middleware lands in one place.
func testRouter(keys *auth.ServerKeys) chi.Router {
	r := chi.NewRouter()
	r.Use(AuthMiddleware(keys))
	return r
}

// adminBearer issues an admin access JWT against keys and returns
// the `Bearer <jwt>` header value. Used by tests that need to
// reach admin-tier endpoints.
func adminBearer(t *testing.T, keys *auth.ServerKeys) string {
	t.Helper()
	tok, err := auth.IssueAccessToken(keys, "test-admin",
		auth.AccessCreds{AccessToken: "x"}, time.Hour, true)
	if err != nil {
		t.Fatalf("issue admin: %v", err)
	}
	return "Bearer " + tok
}

// userBearer issues a non-admin access JWT for the named subject.
// Used by tests that need to reach authenticated-tier endpoints
// without admin, or that exercise subject-scoping.
func userBearer(t *testing.T, keys *auth.ServerKeys, subject string) string {
	t.Helper()
	tok, err := auth.IssueAccessToken(keys, subject,
		auth.AccessCreds{AccessToken: "x"}, time.Hour, false)
	if err != nil {
		t.Fatalf("issue user: %v", err)
	}
	return "Bearer " + tok
}
