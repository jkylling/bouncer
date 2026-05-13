package admin

import (
	"net/http"
	"strings"

	"github.com/jkylling/bouncer/internal/auth"
)

// AdminCookieName is the cookie under which the password-driven
// login flow stashes the issued admin JWT. HttpOnly + SameSite=Strict
// + (in production) Secure — the login handler sets the right
// attributes when it Set-Cookies. Exported so the cookie name is
// consistent across the login handler, the auth middleware, and any
// future CSRF/logout work.
const AdminCookieName = "bouncer_admin"

// AuthMiddleware verifies an inbound JWT (Authorization header
// preferred, then cookie) and stashes the resulting auth.Caller in
// the request context. It does NOT reject — open routes serve an
// anonymous Caller without complaint, and the
// InternalPolicyMiddleware running after this middleware decides
// per-route whether anonymous / user / admin callers are permitted.
//
// keys is required; the middleware is a no-op (anonymous Caller)
// when keys is nil — useful in tests that only exercise open
// routes.
func AuthMiddleware(keys *auth.ServerKeys) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := auth.Caller{}
			if keys != nil {
				if jwt := bearerOrCookie(r); jwt != "" {
					if tok, err := auth.VerifyAccessToken(keys, jwt); err == nil {
						caller = auth.Caller{Subject: tok.Subject, Role: roleFor(tok.Admin)}
					}
				}
			}
			ctx := auth.WithCaller(r.Context(), caller)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerOrCookie pulls the JWT from the Authorization header
// (Bearer scheme) if present, otherwise from the admin cookie. Any
// Authorization header — including non-Bearer schemes such as Basic
// or Negotiate — suppresses the cookie path; otherwise a request
// crafted to carry both a non-Bearer header (e.g. service-to-service
// auth injected by a reverse proxy) and a stolen admin cookie would
// silently authenticate as the cookie holder.
func bearerOrCookie(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		const prefix = "Bearer "
		if !strings.HasPrefix(h, prefix) {
			return "" // non-Bearer scheme: do not fall back to cookie
		}
		return strings.TrimSpace(h[len(prefix):])
	}
	if c, err := r.Cookie(AdminCookieName); err == nil {
		return c.Value
	}
	return ""
}

// roleFor maps the JWT's admin claim to the corresponding Role.
// Centralised so the user-vs-admin promotion lives in one place.
func roleFor(admin bool) auth.Role {
	if admin {
		return auth.RoleAdmin
	}
	return auth.RoleUser
}
