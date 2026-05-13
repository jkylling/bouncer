package admin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/server/admin"
)

// TestLoadInternalRuntime_AllSets verifies every embedded set
// compiles cleanly. This is the canary for a typo in the YAML or a
// regression in the embedded API spec — boot would fail loudly, but
// it's nicer to fail at unit-test time than only when the binary runs.
func TestLoadInternalRuntime_AllSets(t *testing.T) {
	for _, set := range []admin.PolicySet{
		admin.PolicySetDemo,
		admin.PolicySetSimple,
		admin.PolicySetProduction,
	} {
		t.Run(string(set), func(t *testing.T) {
			rt, err := admin.LoadInternalRuntime(set)
			require.NoError(t, err)
			require.NotNil(t, rt)
		})
	}
}

// TestLoadInternalRuntime_RejectsUnknownSet pins the validate gate
// so a flag typo (--internal-policies=demoo) fails at boot rather
// than silently picking a default.
func TestLoadInternalRuntime_RejectsUnknownSet(t *testing.T) {
	_, err := admin.LoadInternalRuntime("nope")
	require.Error(t, err)
}

// internalMiddlewareCase exercises one (set, role, method, path)
// tuple against the internal-policy middleware and asserts the
// expected outcome (200 = passed through, 401/403/303 = denied).
type internalMiddlewareCase struct {
	name       string
	set        admin.PolicySet
	role       auth.Role
	method     string
	path       string
	accept     string // optional Accept header
	wantStatus int
}

func TestInternalPolicyMiddleware(t *testing.T) {
	cases := []internalMiddlewareCase{
		// simple: open routes work for everyone
		{name: "simple/open/anon/whoami", set: admin.PolicySetSimple,
			role: auth.RoleAnonymous, method: "GET", path: "/_api/whoami",
			wantStatus: http.StatusOK},
		{name: "simple/open/admin/login", set: admin.PolicySetSimple,
			role: auth.RoleAnonymous, method: "POST", path: "/_api/admin/login",
			wantStatus: http.StatusOK},

		// simple: authenticated routes
		{name: "simple/auth/anon/policies-list-html",
			set: admin.PolicySetSimple, role: auth.RoleAnonymous,
			method: "GET", path: "/_api/policies",
			wantStatus: http.StatusUnauthorized},
		{name: "simple/auth/anon/ui-tokens",
			set: admin.PolicySetSimple, role: auth.RoleAnonymous,
			method: "GET", path: "/_admin",
			wantStatus: http.StatusSeeOther},
		{name: "simple/auth/user/policies-list",
			set: admin.PolicySetSimple, role: auth.RoleUser,
			method: "GET", path: "/_api/policies",
			wantStatus: http.StatusOK},

		// simple: admin-only routes
		{name: "simple/admin/anon/issue-tokens",
			set: admin.PolicySetSimple, role: auth.RoleAnonymous,
			method: "POST", path: "/_api/issue/tokens",
			wantStatus: http.StatusUnauthorized},
		{name: "simple/admin/user/issue-tokens",
			set: admin.PolicySetSimple, role: auth.RoleUser,
			method: "POST", path: "/_api/issue/tokens",
			wantStatus: http.StatusForbidden},
		{name: "simple/admin/admin/issue-tokens",
			set: admin.PolicySetSimple, role: auth.RoleAdmin,
			method: "POST", path: "/_api/issue/tokens",
			wantStatus: http.StatusOK},

		// demo: every non-admin endpoint is open
		{name: "demo/open/anon/policies-list",
			set: admin.PolicySetDemo, role: auth.RoleAnonymous,
			method: "GET", path: "/_api/policies",
			wantStatus: http.StatusOK},
		{name: "demo/admin/anon/issue-tokens",
			set: admin.PolicySetDemo, role: auth.RoleAnonymous,
			method: "POST", path: "/_api/issue/tokens",
			wantStatus: http.StatusUnauthorized},
		{name: "demo/admin/admin/issue-tokens",
			set: admin.PolicySetDemo, role: auth.RoleAdmin,
			method: "POST", path: "/_api/issue/tokens",
			wantStatus: http.StatusOK},

		// production: nearly everything is admin-only
		{name: "production/open/anon/login",
			set: admin.PolicySetProduction, role: auth.RoleAnonymous,
			method: "POST", path: "/_api/admin/login",
			wantStatus: http.StatusOK},
		{name: "production/admin/anon/whoami",
			set: admin.PolicySetProduction, role: auth.RoleAnonymous,
			method: "GET", path: "/_api/whoami",
			wantStatus: http.StatusUnauthorized},
		{name: "production/admin/user/whoami",
			set: admin.PolicySetProduction, role: auth.RoleUser,
			method: "GET", path: "/_api/whoami",
			wantStatus: http.StatusForbidden},
		{name: "production/admin/admin/whoami",
			set: admin.PolicySetProduction, role: auth.RoleAdmin,
			method: "GET", path: "/_api/whoami",
			wantStatus: http.StatusOK},

		// outside the internal prefix → middleware passes through
		{name: "outside-prefix/anon/oauth-token",
			set: admin.PolicySetSimple, role: auth.RoleAnonymous,
			method: "POST", path: "/token",
			wantStatus: http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runMiddlewareCase(t, tc)
		})
	}
}

// runMiddlewareCase wires the middleware around an always-200
// handler and confirms the (status, possibly Location) pair.
func runMiddlewareCase(t *testing.T, tc internalMiddlewareCase) {
	t.Helper()
	rt, err := admin.LoadInternalRuntime(tc.set)
	require.NoError(t, err)

	hit := false
	final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	})
	h := admin.InternalPolicyMiddleware(rt)(final)

	r := httptest.NewRequest(tc.method, tc.path, nil)
	if tc.accept != "" {
		r.Header.Set("Accept", tc.accept)
	}
	r = r.WithContext(auth.WithCaller(r.Context(),
		auth.Caller{Subject: subjectFor(tc.role), Role: tc.role}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, tc.wantStatus, w.Code, "status mismatch")
	if tc.wantStatus == http.StatusOK {
		assert.True(t, hit, "expected handler to run")
	} else {
		assert.False(t, hit, "expected denial, handler should not run")
	}
	if tc.wantStatus == http.StatusSeeOther {
		assert.True(t, strings.HasPrefix(w.Header().Get("Location"), admin.LoginUIPath),
			"redirect should target the login UI, got %q", w.Header().Get("Location"))
	}
}

func subjectFor(r auth.Role) string {
	switch r {
	case auth.RoleAdmin:
		return "admin"
	case auth.RoleUser:
		return "user"
	default:
		return ""
	}
}
