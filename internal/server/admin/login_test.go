package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/jkylling/bouncer/internal/auth"
)

// loginServer wires the login endpoints with a hash for "hunter2".
// Returns the test server and the bcrypt hash so individual tests
// can also exercise the no-hash branch by re-mounting if needed.
func loginServer(t *testing.T, hash string) (*httptest.Server, *auth.ServerKeys) {
	t.Helper()
	keys := mustKeys(t)
	r := testRouter(keys)
	MountLogin(r, keys, hash)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, keys
}

// hashPwd returns a bcrypt hash at the cheapest cost so tests stay
// fast. Cost 4 is the minimum bcrypt accepts; production hashes
// land at DefaultCost (10).
func hashPwd(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return string(h)
}

func postLogin(t *testing.T, base, password string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(LoginRequest{Password: password})
	resp, err := http.Post(base+LoginPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

func TestLoginGoodPasswordIssuesAdminJWT(t *testing.T) {
	hash := hashPwd(t, "hunter2")
	ts, keys := loginServer(t, hash)
	resp := postLogin(t, ts.URL, "hunter2")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var got LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if got.Token == "" {
		t.Fatal("empty token")
	}
	tok, err := auth.VerifyAccessToken(keys, got.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !tok.Admin || tok.Subject != AdminLoginSubject {
		t.Errorf("token = %+v, want admin/admin", tok)
	}

	// Cookie present, with the right attributes.
	cookies := resp.Cookies()
	var c *http.Cookie
	for _, ck := range cookies {
		if ck.Name == AdminCookieName {
			c = ck
			break
		}
	}
	if c == nil {
		t.Fatal("no admin cookie")
	}
	if !c.HttpOnly {
		t.Error("cookie not HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if c.Value != got.Token {
		t.Error("cookie value != response Token")
	}
}

func TestLoginBadPasswordReturns401(t *testing.T) {
	ts, _ := loginServer(t, hashPwd(t, "hunter2"))
	resp := postLogin(t, ts.URL, "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLoginEmptyPasswordReturns401(t *testing.T) {
	ts, _ := loginServer(t, hashPwd(t, "hunter2"))
	resp := postLogin(t, ts.URL, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLoginNotConfiguredReturns503(t *testing.T) {
	ts, _ := loginServer(t, "")
	resp := postLogin(t, ts.URL, "anything")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLoginInvalidJSONReturns400(t *testing.T) {
	ts, _ := loginServer(t, hashPwd(t, "hunter2"))
	resp, err := http.Post(ts.URL+LoginPath, "application/json", strings.NewReader("{not-json"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLogoutClearsCookie(t *testing.T) {
	ts, _ := loginServer(t, hashPwd(t, "hunter2"))
	resp, err := http.Post(ts.URL+LogoutPath, "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	var c *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == AdminCookieName {
			c = ck
			break
		}
	}
	if c == nil {
		t.Fatal("no admin cookie set")
	}
	if c.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want < 0 (clear)", c.MaxAge)
	}
}

// TestLoginUIServesHTML pins the password-prompt page: 200, text/html,
// and that the page references the login endpoint so a browser-side
// rewire would surface here.
func TestLoginUIServesHTML(t *testing.T) {
	ts, _ := loginServer(t, hashPwd(t, "hunter2"))
	resp, err := http.Get(ts.URL + LoginUIPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (login page must be open)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), LoginPath) {
		t.Errorf("login page does not reference %q — form will post to the wrong URL", LoginPath)
	}
}

// TestLoginCookieAuthenticatesSubsequentRequest is the integration
// pin: a cookie issued via /login authenticates a /_api request
// without any Authorization header. Catches a regression where the
// cookie shape diverges from what the auth middleware expects.
func TestLoginCookieAuthenticatesSubsequentRequest(t *testing.T) {
	keys := mustKeys(t)
	r := testRouter(keys)
	MountLogin(r, keys, hashPwd(t, "hunter2"))
	// A trivial probe that 200s only when the auth middleware
	// promoted the caller to admin via the login cookie. Mounted at
	// `/probe` (outside the /_api / /_admin internal-policy surface)
	// so the only gate it exercises is the cookie → Caller path the
	// auth middleware itself owns.
	r.Get("/probe", func(w http.ResponseWriter, req *http.Request) {
		if !auth.CallerFromContext(req.Context()).IsAdmin() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	// Login.
	body, _ := json.Marshal(LoginRequest{Password: "hunter2"})
	resp, err := client.Post(ts.URL+LoginPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}

	// Hit the admin probe with no Authorization header — the cookie
	// in the jar should carry the JWT.
	resp, err = client.Get(ts.URL + "/probe")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("probe status = %d, want 200 (cookie should authenticate)", resp.StatusCode)
	}
}
