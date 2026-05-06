package admin

import (
	"net/http"
	"net/url"
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
// anonymous Caller without complaint, and the per-route helpers
// (RequireAdmin / RequireAuthenticated) gate the rest. The split
// keeps the open/auth/admin tier visible at the route level rather
// than buried in middleware logic.
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

// RequireAuthenticated wraps next with a guard that 401s anonymous
// callers. The denial body still carries next_steps so an unauthed
// agent gets the discovery surface for free.
func RequireAuthenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := auth.CallerFromContext(r.Context())
		if !c.IsAuthenticated() {
			WriteDenial(w, http.StatusUnauthorized,
				"this endpoint requires a valid Bearer JWT — see next_steps.docs for how to issue one")
			return
		}
		next(w, r)
	}
}

// RequireAdmin wraps next with a guard that 403s callers who lack
// the admin role. Anonymous callers get 401 (so they know to
// authenticate) rather than 403 (which would invite probing for a
// password). Authenticated-but-non-admin callers get 403.
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := auth.CallerFromContext(r.Context())
		switch c.Role {
		case auth.RoleAdmin:
			next(w, r)
		case auth.RoleAnonymous:
			WriteDenial(w, http.StatusUnauthorized,
				"this endpoint requires an admin Bearer JWT — see next_steps.docs for how to obtain one")
		default:
			WriteDenial(w, http.StatusForbidden,
				"this endpoint requires the admin role — your JWT does not carry the `admin: true` claim")
		}
	}
}

// RedirectAnonymousToLogin wraps an HTML-shell handler with a
// browser-friendly login redirect: anonymous callers get a 303 to
// the login page with `?next=<original-path>` so they bounce back
// after signing in. Authenticated callers (admin or otherwise) pass
// through. Use this on the UI shell handlers — the JSON API guards
// (RequireAdmin / RequireAuthenticated) keep returning 401/403 for
// machine clients without disturbing this redirect for browsers.
func RedirectAnonymousToLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := auth.CallerFromContext(r.Context())
		if c.IsAuthenticated() {
			next(w, r)
			return
		}
		// RequestURI carries the path + query as the browser sent
		// it; URL.Path alone would lose any query the user had
		// open. encoded via url.QueryEscape so a stray `&` doesn't
		// land in the wrong place.
		nextRaw := r.URL.Path
		if r.URL.RawQuery != "" {
			nextRaw += "?" + r.URL.RawQuery
		}
		dest := LoginUIPath + "?next=" + url.QueryEscape(nextRaw)
		http.Redirect(w, r, dest, http.StatusSeeOther)
	}
}
