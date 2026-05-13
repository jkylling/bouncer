// Package auth implements the proxy's two-token JWT scheme.
//
// Two JWT shapes share the package's Ed25519 signing key but use
// distinct ChaCha20-Poly1305 encryption keys derived via HKDF info
// strings:
//
//   - Access JWT: typ="access", short-lived, carries an upstream
//     access token. Presented as `Authorization: Bearer …` on every
//     data-plane request. HKDF info "encrypt/access".
//   - Refresh JWT: typ="refresh", long-lived (default no exp),
//     carries an upstream refresh token + the upstream's /token URL.
//     Presented to the proxy's POST /token endpoint *only*. HKDF
//     info "encrypt/refresh".
//
// The two distinct encryption keys give the JWT types domain
// separation: a tampered access blob cannot decrypt as a refresh
// blob (or vice versa), and a confused-deputy attack that swaps
// `typ` on a wire fails AEAD before any logic ever sees the
// plaintext.
//
// Both keys are HKDF-derived from one 32-byte server secret using
// salt "bouncer" — so the operator still owns exactly one secret.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/jkylling/bouncer/internal/auth/z85"
)

const (
	hkdfSalt = "bouncer"

	// jwtIssuer / jwtAudience pin the iss/aud claims so a token
	// signed by an unrelated process that happens to share the HKDF
	// input would still be rejected. Both sides (issue + verify)
	// live in this package so the values are coupled at compile time.
	jwtIssuer   = "bouncer"
	jwtAudience = "bouncer"

	// jwtLeeway is the clock-skew tolerance applied to nbf/exp. 30s
	// matches the typical NTP drift between cloud hosts and is small
	// enough that an attacker cannot meaningfully extend a stolen
	// token's lifetime. Mirrored by AccessLeeway so the /token
	// handler can shrink the access TTL by exactly the same window
	// the verifier admits past `exp`, and never issue a JWT whose
	// embedded upstream token would expire inside the leeway.
	jwtLeeway = 30 * time.Second

	// JWT `typ` claim values. Pinned as constants so a typo is a
	// compile error rather than a silent verifier bypass.
	typAccess  = "access"
	typRefresh = "refresh"

	// HKDF info strings for the per-token-type encryption keys. The
	// distinct values give the two blob types domain separation —
	// a refresh blob cannot decrypt under the access key and vice
	// versa, so a confused-deputy attempt to present one as the
	// other fails AEAD with no further logic involved.
	hkdfInfoEncryptAccess      = "encrypt/access"
	hkdfInfoEncryptRefresh     = "encrypt/refresh"
	hkdfInfoEncryptConnections = "encrypt/connections"
	hkdfInfoSign               = "sign"
)

// AccessLeeway is the access-JWT shrink factor exported for the
// /token handler. Matches jwtLeeway exactly: the verifier admits a
// JWT for `exp + AccessLeeway`, so an access JWT that should never
// outlive its embedded upstream token must be born with `TTL =
// upstream_expires_in - AccessLeeway`. Centralising the constant
// keeps the issuer and verifier from drifting apart.
const AccessLeeway = jwtLeeway

// ServerKeys bundles the per-server signing and encryption keys
// derived from one 32-byte secret. Lengths are pinned at the type
// level so a truncation bug (e.g. forgetting to expand the HKDF
// reader fully) fails to compile rather than at AEAD-init time.
type ServerKeys struct {
	Signing            ed25519.PrivateKey
	Verifying          ed25519.PublicKey
	EncryptAccess      [chacha20poly1305.KeySize]byte
	EncryptRefresh     [chacha20poly1305.KeySize]byte
	EncryptConnections [chacha20poly1305.KeySize]byte
}

// FromSecret derives a fresh `ServerKeys` from a 32-byte input
// secret using HKDF-SHA256 with the package salt and per-purpose
// info strings.
func FromSecret(secret [32]byte) (*ServerKeys, error) {
	var signSeed [ed25519.SeedSize]byte
	if err := hkdfDerive(secret[:], hkdfInfoSign, signSeed[:]); err != nil {
		return nil, err
	}
	keys := &ServerKeys{}
	if err := hkdfDerive(secret[:], hkdfInfoEncryptAccess, keys.EncryptAccess[:]); err != nil {
		return nil, err
	}
	if err := hkdfDerive(secret[:], hkdfInfoEncryptRefresh, keys.EncryptRefresh[:]); err != nil {
		return nil, err
	}
	if err := hkdfDerive(secret[:], hkdfInfoEncryptConnections, keys.EncryptConnections[:]); err != nil {
		return nil, err
	}
	keys.Signing = ed25519.NewKeyFromSeed(signSeed[:])
	keys.Verifying = keys.Signing.Public().(ed25519.PublicKey)
	return keys, nil
}

func hkdfDerive(ikm []byte, info string, out []byte) error {
	r := hkdf.New(sha256.New, ikm, []byte(hkdfSalt), []byte(info))
	if _, err := io.ReadFull(r, out); err != nil {
		return fmt.Errorf("hkdf expand %q: %w", info, err)
	}
	return nil
}

// AccessCreds is the plaintext payload of an access JWT.
//
// Both fields are optional, but at least one must be set — the
// proxy refuses tokens with no upstream credential to forward. The
// forward path injects whichever the issued token carries:
//
//   - `AccessToken` rides as `Authorization: Bearer <token>` (the
//     usual case; OAuth2-bearer upstreams).
//   - Each `Headers` entry is set with `http.Header.Set` (later
//     entries with the same name overwrite earlier ones).
//
// Cookies are sent as a single `Cookie: name=value; name2=value2`
// header — operators who need them add a `Cookie` row to Headers.
// One row per browser session is the typical case (Slack:
// `Cookie: d=xoxd-…` alongside an `xoxc-` bearer); for multiple
// cookies, write them merged in one `Cookie` value.
type AccessCreds struct {
	AccessToken string   `json:"access_token,omitempty"`
	Headers     []Header `json:"headers,omitempty"`
}

// Header is one fixed name/value pair stamped on the outgoing
// forwarded request. `Name` is the canonical HTTP header name;
// `Value` is the literal value. Used for upstreams that need
// `Origin` / `Referer` (Slack browser sessions), `X-API-Key`
// (most API-key upstreams), `Cookie` (any cookie-based session),
// or any other operator-supplied static header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RefreshCreds is the plaintext payload of a refresh JWT. TokenURL
// rides inside the blob (rather than as a server-side registry) so
// the proxy stays multi-provider without per-deployment state — a
// Google refresh JWT and a Microsoft refresh JWT are
// interchangeable as far as the proxy is concerned.
//
// Headers carries static request headers the proxy should propagate
// into every access JWT issued from this refresh. The headers are
// *not* applied to the OAuth2 token-exchange call itself (that's a
// server-to-server exchange that uses client_id/client_secret in
// the body); they ride through the rotation so the access JWT is
// shaped the same way an operator would shape a hand-issued one.
// Empty list is the common case (OAuth2 bearer flows need no
// extras); the field exists for upstreams that pair a refreshable
// bearer with a fixed per-call header (X-Tenant-ID, etc.).
type RefreshCreds struct {
	RefreshToken string   `json:"refresh_token"`
	TokenURL     string   `json:"token_url"`
	Headers      []Header `json:"headers,omitempty"`
}

// AccessToken / RefreshToken are the verified, decrypted forms of
// the two JWT shapes. The Subject is preserved so logs / spans can
// reference the holder without re-parsing the JWT. Admin reflects
// the `admin` claim — the data plane ignores it; admin/control-plane
// endpoints consult it via the auth middleware.
type AccessToken struct {
	Subject string
	Creds   AccessCreds
	Admin   bool
}

type RefreshToken struct {
	Subject string
	Creds   RefreshCreds
	Admin   bool
	// ExpiresAt is the original token's exp, or the zero time when it
	// was issued without one. The /token handler reads this on
	// rotation so a chain of rotations cannot extend lifetime past
	// the first issued token's exp.
	ExpiresAt time.Time
}

// jwtClaims embeds jwt.RegisteredClaims for the standard sub/iat/exp
// fields and adds our private `typ`, `enc`, and `admin` claims.
// `typ` selects the token shape at verify time; `enc` is the
// z85-encoded encrypted payload; `admin` flags a token that may
// reach the admin/control-plane endpoints.
type jwtClaims struct {
	jwt.RegisteredClaims
	Typ   string `json:"typ"`
	Enc   string `json:"enc"`
	Admin bool   `json:"admin,omitempty"`
}

// IssueAccessToken signs a typ="access" JWT containing the encrypted
// access credentials. ttl controls the `exp` claim. admin marks the
// token as authorised for admin/control-plane endpoints; the
// data-plane forwards do not consult it.
func IssueAccessToken(keys *ServerKeys, subject string, creds AccessCreds, ttl time.Duration, admin bool) (string, error) {
	return signEncrypted(keys, subject, typAccess, keys.EncryptAccess[:], creds, &ttl, admin)
}

// IssueRefreshToken signs a typ="refresh" JWT containing the
// encrypted refresh credentials. ttl=0 omits the `exp` claim, giving
// a non-expiring refresh token (the default — operators that want
// time-bound refresh pass --refresh-ttl). admin propagates to every
// access JWT issued from this refresh, so operator status survives
// the rotation cycle.
func IssueRefreshToken(keys *ServerKeys, subject string, creds RefreshCreds, ttl time.Duration, admin bool) (string, error) {
	var ttlPtr *time.Duration
	if ttl > 0 {
		ttlPtr = &ttl
	}
	return signEncrypted(keys, subject, typRefresh, keys.EncryptRefresh[:], creds, ttlPtr, admin)
}

// signEncrypted is the shared issue path: AEAD-seal the payload,
// build the claims, Ed25519-sign. Generic over the payload type so
// the two Issue* helpers share one code path while keeping their
// API surface type-safe.
func signEncrypted[T any](keys *ServerKeys, subject, typ string, encKey []byte, creds T, ttl *time.Duration, admin bool) (string, error) {
	enc, err := encryptCreds(encKey, creds)
	if err != nil {
		return "", err
	}
	now := time.Now()
	rc := jwt.RegisteredClaims{
		Issuer:    jwtIssuer,
		Audience:  jwt.ClaimStrings{jwtAudience},
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
	}
	if ttl != nil {
		rc.ExpiresAt = jwt.NewNumericDate(now.Add(*ttl))
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwtClaims{
		RegisteredClaims: rc,
		Typ:              typ,
		Enc:              z85.Encode(enc),
		Admin:            admin,
	})
	signed, err := tok.SignedString(keys.Signing)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// VerifyAccessToken parses, signature-checks, expiry-checks, and
// decrypts an access JWT.
func VerifyAccessToken(keys *ServerKeys, token string) (*AccessToken, error) {
	var creds AccessCreds
	subject, admin, err := verifyAndDecrypt(keys, token, typAccess, keys.EncryptAccess[:], true, &creds)
	if err != nil {
		return nil, err
	}
	return &AccessToken{Subject: subject, Creds: creds, Admin: admin}, nil
}

// VerifyRefreshToken parses, signature-checks (and expiry-checks if
// the token has an `exp`), and decrypts a refresh JWT. A refresh JWT
// without `exp` is allowed by design — the default-issued shape has
// no expiry and is the normal case.
func VerifyRefreshToken(keys *ServerKeys, token string) (*RefreshToken, error) {
	var creds RefreshCreds
	subject, admin, err := verifyAndDecrypt(keys, token, typRefresh, keys.EncryptRefresh[:], false, &creds)
	if err != nil {
		return nil, err
	}
	if creds.TokenURL == "" {
		return nil, fmt.Errorf("missing token_url in refresh blob")
	}
	rt := &RefreshToken{Subject: subject, Creds: creds, Admin: admin}
	if exp := tokenExpiry(token); !exp.IsZero() {
		rt.ExpiresAt = exp
	}
	return rt, nil
}

// tokenExpiry re-parses token solely to extract the registered `exp`
// claim — verifyAndDecrypt erases it when it inflates the typed
// payload. Returns the zero time when no exp is set or parsing fails
// (the caller already verified the token, so a parse failure here is
// only possible if the JWT layout changed mid-call).
func tokenExpiry(token string) time.Time {
	var rc jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &rc); err != nil {
		return time.Time{}
	}
	if rc.ExpiresAt == nil {
		return time.Time{}
	}
	return rc.ExpiresAt.Time
}

// verifyAndDecrypt is the shared verify path. expirationRequired
// distinguishes access (must have exp) from refresh (exp optional).
// Returns (subject, admin, error) — the admin flag is the verified
// `admin` claim on the JWT, which the auth middleware promotes to
// the Caller's role.
func verifyAndDecrypt[T any](keys *ServerKeys, token, wantTyp string, encKey []byte, expirationRequired bool, out *T) (string, bool, error) {
	opts := []jwt.ParserOption{
		jwt.WithLeeway(jwtLeeway),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(jwtAudience),
	}
	if expirationRequired {
		opts = append(opts, jwt.WithExpirationRequired())
	}
	parsed, err := jwt.ParseWithClaims(token, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Method.Alg())
		}
		return keys.Verifying, nil
	}, opts...)
	if err != nil {
		return "", false, err
	}
	if !parsed.Valid {
		return "", false, fmt.Errorf("token invalid")
	}
	c := parsed.Claims.(*jwtClaims)
	if c.Typ != wantTyp {
		return "", false, fmt.Errorf("typ %q, want %q", c.Typ, wantTyp)
	}
	// An absent `enc` means the token has no payload to decrypt.
	// z85.Decode("") returns a zero-length slice without error, so
	// without this guard we'd fall through to decryptCreds on an
	// empty blob and surface a confusing AEAD error instead of a
	// clear "missing enc".
	if c.Enc == "" {
		return "", false, fmt.Errorf("missing enc claim")
	}
	encBytes, err := z85.Decode(c.Enc)
	if err != nil {
		return "", false, fmt.Errorf("decode enc: %w", err)
	}
	if err := decryptCreds(encKey, encBytes, out); err != nil {
		return "", false, err
	}
	return c.Subject, c.Admin, nil
}

func encryptCreds[T any](key []byte, creds T) ([]byte, error) {
	pt, err := json.Marshal(creds)
	if err != nil {
		return nil, fmt.Errorf("marshal creds: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, pt, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func decryptCreds[T any](key, blob []byte, out *T) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("aead init: %w", err)
	}
	if len(blob) < aead.NonceSize() {
		return fmt.Errorf("ciphertext too short")
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return fmt.Errorf("aead decrypt: %w", err)
	}
	if err := json.Unmarshal(pt, out); err != nil {
		return fmt.Errorf("unmarshal creds: %w", err)
	}
	return nil
}
