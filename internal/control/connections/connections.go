// Package connections persists upstream service credentials the
// proxy will use to mint agent JWTs. Each connection captures the
// triple (client_id, client_secret, refresh_token) that the existing
// `issue-token --credentials-file` flow already consumes — the
// wizard's "Paste credentials" affordance is the same shape, just
// reached over HTTP.
//
// Today the store is a JSON file per provider under
// `<data-dir>/connections/`. The data-dir already requires operator
// trust (it carries secret.hex and the bcrypt password hash), so a
// second layer of encryption-at-rest would add complexity without
// changing the trust model. A future change can swap the Store
// implementation for one backed by the per-instance secret without
// changing this package's surface.
package connections

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Sentinel errors. Handlers map these onto HTTP statuses.
var (
	ErrInvalid     = errors.New("invalid connection")
	ErrUnknown     = errors.New("unknown provider")
	ErrNotFound    = errors.New("connection not found")
	ErrPersistence = errors.New("connection persistence error")
)

// SupportedProviders is the closed list of upstream services bouncer
// can hold credentials for. Operator-supplied provider names are
// validated against this list — a typo on the wire becomes ErrUnknown
// rather than a stray file on disk.
var SupportedProviders = []string{"google", "slack.api"}

// Credentials carries the upstream OAuth2 triple. Shape matches the
// JSON `bouncer issue-token --credentials-file` reads so an operator
// can hand the same blob to either path. `client_secret` and
// `refresh_token` are sensitive; never echo them on read endpoints —
// only `client_id` is safe to surface.
//
// Many of the new bring-your-own-token variants don't populate this
// triple (an access-token-only variant leaves ClientID / Secret /
// RefreshToken empty). The MCP-side refresh path tolerates a zero
// Credentials struct by falling back to the inline-fields path.
type Credentials struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
}

// Connection is the on-disk record. CreatedAt lets the UI show "last
// connected"; the secret fields are stored inline and zeroed before
// returning from List / Get.
//
// Variant + Fields are the new variant-aware shape: Variant is the
// bundle's TokenVariant.ID the operator chose; Fields is the
// per-variant input map (keyed by TokenField.Name). The legacy
// Credentials triple is kept populated when a known field name
// matches so the existing OAuth2-refresh code path keeps working
// without conditional plumbing.
type Connection struct {
	Provider    string            `json:"provider"`
	Variant     string            `json:"variant,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
	Credentials Credentials       `json:"credentials"`
	CreatedAt   time.Time         `json:"created_at"`
}

// providerNamePattern guards the provider against path-traversal
// since it becomes a filename component. Belt-and-braces alongside
// the SupportedProviders allow-list.
var providerNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,30}$`)

// Store is a small, mutex-guarded file store. Each provider's
// connection lives in its own JSON file so an operator-side `cat
// google.json` works without parsing a registry.
type Store struct {
	mu  sync.Mutex
	dir string
}

// NewStore returns a Store backed by dir. Creates the directory on
// first write. Pass `<data-dir>/connections` in production wiring.
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// Put validates and persists a connection from the legacy OAuth2-
// triple shape. Atomically replaces the previous one for the same
// provider via a temp-file + rename. The returned record has its
// secret fields zeroed so callers can echo it to clients.
//
// New callers should prefer PutVariant — it accepts the variant ID
// and arbitrary fields and writes both the variant-aware shape and
// the legacy triple in one pass.
func (s *Store) Put(provider string, creds Credentials) (Connection, error) {
	return s.put(provider, "", nil, creds)
}

// PutVariant validates and persists a connection chosen against a
// declared bundle variant. variant is the TokenVariant.ID; fields is
// the per-variant input map (keyed by TokenField.Name). Known field
// names (client_id, client_secret, refresh_token, token_url) are
// also written to the legacy Credentials triple so the existing
// OAuth2-refresh path keeps working unchanged.
func (s *Store) PutVariant(provider, variant string, fields map[string]string) (Connection, error) {
	creds := Credentials{
		ClientID:     fields["client_id"],
		ClientSecret: fields["client_secret"],
		RefreshToken: fields["refresh_token"],
		TokenURL:     fields["token_url"],
	}
	return s.put(provider, variant, fields, creds)
}

func (s *Store) put(provider, variant string, fields map[string]string, creds Credentials) (Connection, error) {
	if !isSupported(provider) {
		return Connection{}, fmt.Errorf("%w: %q", ErrUnknown, provider)
	}
	if !providerNamePattern.MatchString(provider) {
		return Connection{}, fmt.Errorf("%w: provider name", ErrInvalid)
	}
	// Variant submissions can carry only the variant-typed fields
	// (e.g. an access_token-only variant). Legacy submissions still
	// require the full triple — that path's validation is kept.
	if variant == "" {
		if err := validateCreds(creds); err != nil {
			return Connection{}, err
		}
	} else {
		if len(fields) == 0 {
			return Connection{}, fmt.Errorf("%w: at least one field is required", ErrInvalid)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return Connection{}, fmt.Errorf("%w: mkdir: %v", ErrPersistence, err)
	}
	rec := Connection{
		Provider:    provider,
		Variant:     variant,
		Fields:      fields,
		Credentials: creds,
		CreatedAt:   time.Now().UTC(),
	}
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return Connection{}, fmt.Errorf("%w: encode: %v", ErrPersistence, err)
	}
	tmp := filepath.Join(s.dir, provider+".json.tmp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return Connection{}, fmt.Errorf("%w: write tmp: %v", ErrPersistence, err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, provider+".json")); err != nil {
		return Connection{}, fmt.Errorf("%w: rename: %v", ErrPersistence, err)
	}
	return public(rec), nil
}

// List returns every persisted connection with secrets zeroed.
func (s *Store) List() ([]Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: readdir: %v", ErrPersistence, err)
	}
	out := make([]Connection, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		rec, err := readFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue // skip unreadable / corrupt records
		}
		out = append(out, public(rec))
	}
	return out, nil
}

// Get returns the full record (with secrets) for a single provider.
// Used by token-issuance code paths that need to forward the
// refresh_token to upstream; never exposed over the HTTP API.
func (s *Store) Get(provider string) (Connection, error) {
	if !isSupported(provider) {
		return Connection{}, fmt.Errorf("%w: %q", ErrUnknown, provider)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := readFile(filepath.Join(s.dir, provider+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return Connection{}, ErrNotFound
	}
	if err != nil {
		return Connection{}, fmt.Errorf("%w: read: %v", ErrPersistence, err)
	}
	return rec, nil
}

// Delete removes a provider's connection. Missing returns ErrNotFound.
func (s *Store) Delete(provider string) error {
	if !isSupported(provider) {
		return fmt.Errorf("%w: %q", ErrUnknown, provider)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.dir, provider+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: remove: %v", ErrPersistence, err)
	}
	return nil
}

func readFile(path string) (Connection, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Connection{}, err
	}
	var rec Connection
	if err := json.Unmarshal(body, &rec); err != nil {
		return Connection{}, err
	}
	return rec, nil
}

// public returns a copy of rec with secret fields zeroed. ClientID
// stays — it's not a secret on its own and lets the UI render
// "connected as ....apps.googleusercontent.com" when desired. The
// variant-typed Fields map is dropped wholesale: we don't know which
// keys map to secrets without the bundle's TokenField schema, so the
// safe default is to omit them from public-facing reads.
func public(rec Connection) Connection {
	rec.Credentials.ClientSecret = ""
	rec.Credentials.RefreshToken = ""
	rec.Fields = nil
	return rec
}

func isSupported(provider string) bool {
	for _, p := range SupportedProviders {
		if p == provider {
			return true
		}
	}
	return false
}

func validateCreds(c Credentials) error {
	switch {
	case c.ClientID == "":
		return fmt.Errorf("%w: client_id required", ErrInvalid)
	case c.ClientSecret == "":
		return fmt.Errorf("%w: client_secret required", ErrInvalid)
	case c.RefreshToken == "":
		return fmt.Errorf("%w: refresh_token required", ErrInvalid)
	}
	return nil
}
