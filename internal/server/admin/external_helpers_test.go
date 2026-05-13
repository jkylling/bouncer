package admin_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/server/admin"
)

// newTestKeys returns a deterministic ServerKeys built from the dev
// stub secret. Every external admin_test test that needs to issue or
// verify a JWT goes through this so they share one signing key.
func newTestKeys(t *testing.T) *auth.ServerKeys {
	t.Helper()
	keys, err := auth.FromSecret(auth.DevStubSecret())
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}
	return keys
}

// authedRouter returns a chi.Router with admin.AuthMiddleware
// already wired. Mirrors the internal testRouter helper but for the
// external (`admin_test`) package.
func authedRouter(keys *auth.ServerKeys) chi.Router {
	r := chi.NewRouter()
	r.Use(admin.AuthMiddleware(keys))
	return r
}

// adminBearer issues an admin JWT against keys and returns the
// `Bearer <jwt>` header value.
func adminBearer(t *testing.T, keys *auth.ServerKeys) string {
	t.Helper()
	tok, err := auth.IssueAccessToken(keys, "test-admin",
		auth.AccessCreds{AccessToken: "x"}, time.Hour, true)
	if err != nil {
		t.Fatalf("issue admin: %v", err)
	}
	return "Bearer " + tok
}

// authedGet does http.Get with a Bearer header attached. Mirrors
// http.Get's (resp, err) shape so callsites can keep their existing
// error checks.
func authedGet(t *testing.T, url, bearer string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", bearer)
	return http.DefaultClient.Do(req)
}
