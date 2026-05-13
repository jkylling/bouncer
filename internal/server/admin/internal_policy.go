package admin

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jkylling/bouncer/internal/auth"
	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	internalapis "github.com/jkylling/bouncer/internal/server/admin/internal_apis"
)

// InternalAPIName is the name the embedded internal-API spec
// registers under. Exposed so policy authoring (and tests) can
// target it without restating the literal.
const InternalAPIName = "bouncer-internal"

// InternalScopeAdmin is the scope stamped on the *pb.Principal for
// admin callers; InternalScopeUser is the scope every authenticated
// caller carries (admin included). Anonymous callers get an empty
// scope list.
const (
	InternalScopeAdmin = "admin"
	InternalScopeUser  = "user"
)

// PolicySet re-exports internal_apis.PolicySet so callers
// (cmd/bouncer flag plumbing, server.Config) don't have to import
// the embed package alongside admin.
type PolicySet = internalapis.PolicySet

const (
	PolicySetDemo       = internalapis.PolicySetDemo
	PolicySetSimple     = internalapis.PolicySetSimple
	PolicySetProduction = internalapis.PolicySetProduction
)

// LoadInternalRuntime parses the embedded internal-API spec, builds
// a runtime, and replays the chosen policy set into it. Returns the
// ready-to-evaluate runtime; Build errors and policy-compile errors
// surface to the caller so a typo in the embedded YAML fails at
// boot rather than per-request.
func LoadInternalRuntime(set PolicySet) (*runtime.Runtime, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	var spec models.API
	if err := yaml.Unmarshal(internalapis.APISpec, &spec); err != nil {
		return nil, fmt.Errorf("decode embedded api.yaml: %w", err)
	}
	if spec.Name != InternalAPIName {
		return nil, fmt.Errorf("embedded api.yaml name %q != %q", spec.Name, InternalAPIName)
	}
	builder := runtime.NewBuilder()
	if err := builder.AddAPI(&spec); err != nil {
		return nil, fmt.Errorf("register embedded api: %w", err)
	}
	rt, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build embedded runtime: %w", err)
	}
	policiesYAML, err := internalapis.Policies(set)
	if err != nil {
		return nil, err
	}
	policies, err := decodeInternalPolicies(policiesYAML)
	if err != nil {
		return nil, fmt.Errorf("decode embedded policies %q: %w", set, err)
	}
	for i := range policies {
		if err := rt.AddPolicy(&policies[i]); err != nil {
			return nil, fmt.Errorf("add embedded policy %q: %w", policies[i].Name, err)
		}
	}
	return rt, nil
}

// decodeInternalPolicies parses a multi-document policy YAML the
// same way the file store does (one Policy per `---`-separated
// document, KnownFields strict).
func decodeInternalPolicies(body []byte) ([]models.Policy, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	dec.KnownFields(true)
	var out []models.Policy
	for {
		var p models.Policy
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// InternalPolicyMiddleware gates every /_admin and /_api request
// through rt. AuthMiddleware must run before this so the verified
// Caller is in ctx; the middleware turns Caller into a *pb.Principal,
// asks the runtime for a decision, and either lets the request
// through or renders the right denial shape:
//
//   - anonymous + denied + HTML page         -> 303 redirect to /login
//   - anonymous + denied + JSON / non-HTML   -> 401
//   - authenticated + denied                 -> 403
//
// Requests outside /_admin and /_api fall through unchanged.
func InternalPolicyMiddleware(rt *runtime.Runtime) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isInternalPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			caller := auth.CallerFromContext(r.Context())
			principal := principalFor(caller)
			req := &pb.Request{
				Method:       strings.ToUpper(r.Method),
				Path:         r.URL.Path,
				PathSegments: compiled.SplitPath(r.URL.Path),
			}
			apiName, decision, err := rt.Evaluate(r.Context(), nopResolver, req, principal)
			if err != nil {
				slog.ErrorContext(r.Context(), "internal policy eval",
					"method", r.Method, "path", r.URL.Path, "err", err)
				WriteDenial(w, http.StatusInternalServerError,
					"internal policy evaluation error")
				return
			}
			// apiName == "" means the path didn't match any prefix in
			// the internal runtime (a /_api or /_admin path the spec
			// hasn't enumerated). Treated as "no policy applies":
			// fail closed, but match today's UX — anonymous callers
			// on HTML routes still get the login redirect.
			if apiName == "" || decision != models.Permit {
				writeInternalDenial(w, r, caller)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// nopResolver satisfies runtime.PhysicalAPIResolver for the internal
// runtime. The internal API has no `meta:` blocks, so no bind ever
// triggers a side call; the resolver exists only to satisfy the
// signature.
func nopResolver(name string) (compiled.PhysicalAPI, error) {
	return nil, fmt.Errorf("internal runtime: no physical API for %q", name)
}

// isInternalPath reports whether path falls inside the bouncer-internal
// API's routed surface. Mirrors the path_prefixes declared in the
// embedded api.yaml — matched here as a literal so the data plane
// can short-circuit before building a *pb.Request.
// Static files (/_admin/static/*) are excluded — they bypass policy gating.
func isInternalPath(path string) bool {
	// Static assets never require policy evaluation
	if hasSegmentedPrefix(path, "/_admin/static") {
		return false
	}
	return hasSegmentedPrefix(path, "/_admin") ||
		hasSegmentedPrefix(path, "/_api") ||
		hasSegmentedPrefix(path, "/install")
}

// hasSegmentedPrefix matches path against prefix segment-wise so
// "/_admin" claims "/_admin/policies" but not "/_administrator".
// Mirrors the runtime's prefix routing without pulling the runtime
// helper out of an internal package.
func hasSegmentedPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

// principalFor maps the verified Caller onto a *pb.Principal the
// runtime can evaluate. Admin implies user (admin is a strict
// superset of authenticated), so admins pick up both scopes.
func principalFor(c auth.Caller) *pb.Principal {
	switch c.Role {
	case auth.RoleAdmin:
		return &pb.Principal{
			Subject: c.Subject,
			Kind:    "admin",
			Scopes:  []string{InternalScopeAdmin, InternalScopeUser},
		}
	case auth.RoleUser:
		return &pb.Principal{
			Subject: c.Subject,
			Kind:    "user",
			Scopes:  []string{InternalScopeUser},
		}
	default:
		return &pb.Principal{Kind: "anonymous"}
	}
}

// writeInternalDenial renders the policy-driven denial in the same
// shape the per-route wrappers used to. The distinction matches the
// pre-migration UX:
//
//   - anonymous + UI-shell route (/_admin/...) -> 303 redirect to login
//   - anonymous + JSON route (/_api/...)        -> 401 with denial body
//   - authenticated-but-denied                  -> 403 with denial body
//
// The `/_admin` vs `/_api` split is the same one the chi router
// makes anyway: `/_admin/*` serves HTML shells, `/_api/*` serves
// JSON. No need to inspect Accept — the path tells us.
func writeInternalDenial(w http.ResponseWriter, r *http.Request, c auth.Caller) {
	if !c.IsAuthenticated() {
		if isUIPath(r.URL.Path) {
			redirectToLogin(w, r)
			return
		}
		WriteDenial(w, http.StatusUnauthorized,
			"this endpoint requires a valid Bearer JWT — see next_steps.docs for how to issue one")
		return
	}
	WriteDenial(w, http.StatusForbidden,
		"the active internal-policy set does not permit this caller on this endpoint")
}

// isUIPath reports whether path falls inside the HTML-shell surface
// (`/_admin/...`) where browser navigation expects a 303 redirect to
// the login page on an anonymous deny.
func isUIPath(path string) bool {
	return hasSegmentedPrefix(path, "/_admin")
}

// redirectToLogin matches RedirectAnonymousToLogin's old behaviour:
// 303 to /_admin/login with `?next=<original-path>` so the post-login
// flow bounces back to where the operator started.
func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	nextRaw := r.URL.Path
	if r.URL.RawQuery != "" {
		nextRaw += "?" + r.URL.RawQuery
	}
	dest := LoginUIPath + "?next=" + url.QueryEscape(nextRaw)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
