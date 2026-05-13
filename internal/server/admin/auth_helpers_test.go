package admin

import (
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
)

// testRouter returns a chi.Router with both the auth middleware and
// the internal-policy middleware wired against keys, using the
// `simple` embedded policy set (the closest match to the
// pre-migration access control). Centralised so every per-test mount
// point picks up the same gate the production Router does — a
// future tweak to the middleware lands in one place.
func testRouter(keys *auth.ServerKeys) chi.Router {
	r := chi.NewRouter()
	r.Use(AuthMiddleware(keys))
	rt, err := LoadInternalRuntime(PolicySetSimple)
	if err != nil {
		panic("testRouter: load internal runtime: " + err.Error())
	}
	r.Use(InternalPolicyMiddleware(rt))
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
