package auth

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mustKeys(t *testing.T, b byte) *ServerKeys {
	t.Helper()
	var secret [32]byte
	for i := range secret {
		secret[i] = b
	}
	keys, err := FromSecret(secret)
	if err != nil {
		t.Fatalf("from secret: %v", err)
	}
	return keys
}

func TestAccessRoundtrip(t *testing.T) {
	keys := mustKeys(t, 7)
	creds := AccessCreds{AccessToken: "ya29.upstream"}
	tok, err := IssueAccessToken(keys, "u", creds, time.Hour, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := VerifyAccessToken(keys, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "u" {
		t.Errorf("subject = %q, want u", got.Subject)
	}
	if !reflect.DeepEqual(got.Creds, creds) {
		t.Errorf("creds = %#v, want %#v", got.Creds, creds)
	}
}

// TestAdminClaimRoundtrips pins the admin-claim contract: a token
// issued with admin=true verifies with Admin=true; a token issued
// without admin=false defaults to Admin=false. The auth middleware
// promotes Admin to RoleAdmin downstream.
func TestAdminClaimRoundtrips(t *testing.T) {
	keys := mustKeys(t, 7)
	creds := AccessCreds{AccessToken: "x"}

	tok, err := IssueAccessToken(keys, "u", creds, time.Hour, true)
	if err != nil {
		t.Fatalf("issue admin: %v", err)
	}
	got, err := VerifyAccessToken(keys, tok)
	if err != nil {
		t.Fatalf("verify admin: %v", err)
	}
	if !got.Admin {
		t.Errorf("Admin = false, want true on admin token")
	}

	tok, err = IssueAccessToken(keys, "u", creds, time.Hour, false)
	if err != nil {
		t.Fatalf("issue non-admin: %v", err)
	}
	got, err = VerifyAccessToken(keys, tok)
	if err != nil {
		t.Fatalf("verify non-admin: %v", err)
	}
	if got.Admin {
		t.Errorf("Admin = true, want false on plain token")
	}

	// Same shape on the refresh flavour so a chain of rotations
	// preserves admin status.
	rtTok, err := IssueRefreshToken(keys, "u",
		RefreshCreds{RefreshToken: "rt", TokenURL: "https://x"}, 0, true)
	if err != nil {
		t.Fatalf("issue refresh admin: %v", err)
	}
	rt, err := VerifyRefreshToken(keys, rtTok)
	if err != nil {
		t.Fatalf("verify refresh admin: %v", err)
	}
	if !rt.Admin {
		t.Errorf("refresh Admin = false, want true")
	}
}

func TestRefreshRoundtrip(t *testing.T) {
	keys := mustKeys(t, 8)
	creds := RefreshCreds{RefreshToken: "1//0g.refresh", TokenURL: "https://oauth2.googleapis.com/token"}
	tok, err := IssueRefreshToken(keys, "u", creds, 0, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := VerifyRefreshToken(keys, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "u" {
		t.Errorf("subject = %q, want u", got.Subject)
	}
	if !reflect.DeepEqual(got.Creds, creds) {
		t.Errorf("creds = %#v, want %#v", got.Creds, creds)
	}
}

// TestRefreshRejectsMissingTokenURL: a malformed refresh blob with
// no token_url would leave the /token handler with no upstream to
// call. Surface the issue at verify time instead of in the handler.
func TestRefreshRejectsMissingTokenURL(t *testing.T) {
	keys := mustKeys(t, 9)
	creds := RefreshCreds{RefreshToken: "rt"}
	tok, err := IssueRefreshToken(keys, "u", creds, 0, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = VerifyRefreshToken(keys, tok)
	if err == nil || !strings.Contains(err.Error(), "token_url") {
		t.Fatalf("error = %v, want one mentioning token_url", err)
	}
}

// TestAccessRejectsRefreshJWT: an attacker who swaps a refresh JWT
// into the Authorization header must not be admitted as an access
// token. Domain separation by encryption key (HKDF info "encrypt/access"
// vs "encrypt/refresh") and the typ check together enforce this:
// even before typ is inspected, AEAD-Open of a refresh blob under
// the access key fails.
func TestAccessRejectsRefreshJWT(t *testing.T) {
	keys := mustKeys(t, 10)
	rt, err := IssueRefreshToken(keys, "u", RefreshCreds{RefreshToken: "rt", TokenURL: "https://x"}, 0, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := VerifyAccessToken(keys, rt); err == nil {
		t.Fatal("expected access verify to reject refresh JWT")
	}
}

// TestRefreshRejectsAccessJWT: mirror — an access JWT presented to
// the refresh path must not decrypt under the refresh key, and the
// typ guard would catch any tag-collision happenstance.
func TestRefreshRejectsAccessJWT(t *testing.T) {
	keys := mustKeys(t, 11)
	at, err := IssueAccessToken(keys, "u", AccessCreds{AccessToken: "at"}, time.Hour, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := VerifyRefreshToken(keys, at); err == nil {
		t.Fatal("expected refresh verify to reject access JWT")
	}
}

func TestRejectsWrongKey(t *testing.T) {
	a := mustKeys(t, 1)
	b := mustKeys(t, 2)
	tok, err := IssueAccessToken(a, "u", AccessCreds{AccessToken: "at"}, time.Hour, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := VerifyAccessToken(b, tok); err == nil {
		t.Fatalf("expected verify error with wrong key")
	}
}

func TestRejectsExpired(t *testing.T) {
	keys := mustKeys(t, 4)
	// Issue a token whose `exp` is comfortably outside the verifier's
	// leeway so we don't depend on wall-clock sleeps.
	tok, err := IssueAccessToken(keys, "u", AccessCreds{AccessToken: "at"}, -2*time.Minute, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := VerifyAccessToken(keys, tok); err == nil {
		t.Fatalf("expected verify error for expired token")
	}
}

// TestRefreshIgnoresMissingExp pins the design choice that a
// refresh JWT with no exp claim is admitted by default. Operators
// who want time-bound refresh use --refresh-ttl.
func TestRefreshIgnoresMissingExp(t *testing.T) {
	keys := mustKeys(t, 5)
	tok, err := IssueRefreshToken(keys, "u", RefreshCreds{RefreshToken: "rt", TokenURL: "https://x"}, 0, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := VerifyRefreshToken(keys, tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestVerifyRejectsEmptyEnc pins a JWT with all the
// signing/iss/aud bits in order but an empty `enc` claim must fail
// loudly with a clear error rather than fall through to the AEAD
// decrypt and surface a generic "decrypt" failure.
func TestVerifyRejectsEmptyEnc(t *testing.T) {
	keys := mustKeys(t, 9)
	now := time.Now()
	claims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
			Subject:   "u",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Typ: typAccess,
		Enc: "",
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(keys.Signing)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err = VerifyAccessToken(keys, signed)
	if err == nil {
		t.Fatal("expected error for empty enc claim")
	}
	if !strings.Contains(err.Error(), "enc") {
		t.Fatalf("error = %v, want one mentioning enc", err)
	}
}
