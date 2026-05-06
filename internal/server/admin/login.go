package admin

import (
	_ "embed"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/jkylling/bouncer/internal/auth"
)

// Login endpoint paths. The pair (`login`, `logout`) sits under
// `/_api/admin/...` so it shares the JSON-API namespace with the rest
// of the control plane and the route gate at `/_api/...` keeps the
// surface easy to enumerate.
const (
	LoginPath   = "/_api/admin/login"
	LogoutPath  = "/_api/admin/logout"
	LoginUIPath = "/_admin/login"
)

// loginHTML is the embedded password-prompt UI. Same admin_ui/
// directory as the other pages so the embed path stays stable.
//
//go:embed admin_ui/login.html
var loginHTML []byte

// AdminLoginSubject is the `sub` claim stamped onto JWTs issued via
// the password login flow. A constant (rather than per-operator
// identity) because the password is shared infrastructure: the JWT
// only encodes "this caller proved knowledge of the operator
// password", not who they are individually.
const AdminLoginSubject = "admin"

// loginTTL is the lifetime of admin sessions issued by the password
// login flow. 12h covers a long working day without making a stolen
// laptop/cookie a year-long incident.
const loginTTL = 12 * time.Hour

// maxLoginBodyBytes caps the JSON body the login handler reads. The
// payload is a single password field — 1 KiB is plenty.
const maxLoginBodyBytes int64 = 1 << 10

// MountLogin attaches the password-login + logout routes and the
// HTML login page. passwordHash is the bcrypt hash of the operator
// password; an empty hash leaves the login endpoint serving 503
// ("login not configured") so an operator who hasn't set
// --admin-password-hash gets a clear signal rather than a silent
// "no one can ever authenticate" outcome.
func MountLogin(r chi.Router, keys *auth.ServerKeys, passwordHash string) {
	page := htmlHandler(loginHTML)
	r.Post(LoginPath, loginHandler(keys, passwordHash))
	r.Post(LogoutPath, logoutHandler())
	r.Get(LoginUIPath, page)
	r.Get(LoginUIPath+"/", page)
}

// LoginRequest is the JSON body POST /_api/admin/login expects.
type LoginRequest struct {
	Password string `json:"password"`
}

// LoginResponse is the JSON body POST /_api/admin/login returns on
// success. The `Token` field duplicates what the cookie carries so a
// CLI / curl flow that does not store cookies can use the JWT
// directly via the `Authorization: Bearer ...` header.
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// loginHandler returns the POST /_api/admin/login handler. bcrypt
// compares the body password against passwordHash; on match it
// issues an admin access JWT, sets it on AdminCookieName, and
// returns the JWT + expiry. On mismatch a generic 401 leaks no
// configuration detail.
//
// bcrypt is intentionally slow (~50ms) so brute force is CPU-bound.
func loginHandler(keys *auth.ServerKeys, passwordHash string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if passwordHash == "" {
			writeJSONError(w, "login not configured (no --admin-password-hash)", http.StatusServiceUnavailable)
			return
		}

		var body LoginRequest
		if err := decodeJSONBody(w, r, maxLoginBodyBytes, &body); err != nil {
			writeMappedError(r.Context(), w, "login", err, nil)
			return
		}

		if !verifyPassword(passwordHash, body.Password) {
			writeJSONError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		tok, err := auth.IssueAccessToken(keys, AdminLoginSubject,
			auth.AccessCreds{AccessToken: "x"}, loginTTL, true)
		if err != nil {
			writeJSONError(w, "issue token", http.StatusInternalServerError)
			return
		}
		expiresAt := time.Now().Add(loginTTL)
		setAdminCookie(w, r, tok, expiresAt, 0)
		writeJSON(w, LoginResponse{Token: tok, ExpiresAt: expiresAt})
	}
}

// logoutHandler clears the admin cookie. The JWT itself remains
// valid until its `exp` (we have no revocation list) — this only
// drops the browser's session.
func logoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setAdminCookie(w, r, "", time.Unix(0, 0), -1)
		w.WriteHeader(http.StatusNoContent)
	}
}

// setAdminCookie writes the admin session cookie with the canonical
// attribute set (HttpOnly + SameSite=Strict + Path=/, Secure on TLS
// listeners only). maxAge < 0 clears the cookie; otherwise the
// browser uses Expires.
//
// Centralised so a future tweak to one attribute (Path, SameSite)
// stays in lockstep between login and logout — RFC 6265 requires
// matching attributes for clear-cookie to actually clear.
func setAdminCookie(w http.ResponseWriter, r *http.Request, value string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     AdminCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		// Mark Secure when the request reaches us over TLS *or*
		// when an upstream reverse proxy reports it terminated TLS
		// for us via X-Forwarded-Proto: https. The latter is the
		// common production shape (TLS at the edge, plain HTTP to
		// the bouncer pod) and would otherwise leave the cookie
		// usable over plaintext. A spoofed header here only causes
		// the browser to *over*-restrict (refuse to send the
		// cookie on plain HTTP), which is a safer failure mode.
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode,
	})
}

// verifyPassword wraps bcrypt.CompareHashAndPassword with a guard
// against an empty cleartext password — bcrypt happily compares ""
// against a hash and returns "wrong password", but treating it as
// an outright reject is more defensive and avoids paying the bcrypt
// cost on a trivially-bogus body.
func verifyPassword(hash, password string) bool {
	if password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
