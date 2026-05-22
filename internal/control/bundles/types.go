// Package bundles owns the on-disk schema, network fetching, and
// boot-time loading of vendored "apis" bundles under <apis-dir>/.
//
// A bundle is a directory holding a `bouncer.yaml` manifest, a
// `source.yaml` install record, and the API YAML specs the manifest
// points at. Optional `README.md` is served as documentation.
package bundles

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ManifestFile = "bouncer.yaml"
	SourceFile   = "source.yaml"
	ReadmeFile   = "README.md"
	APIsSubdir   = "apis"

	// SchemaVersion is the only manifest format the loader accepts.
	SchemaVersion = 1
)

// BundleDir is the on-disk dir for a bundle inside apisDir, keyed by
// the manifest's name.
func BundleDir(apisDir, name string) string {
	return filepath.Join(apisDir, name)
}

// Manifest is the parsed shape of bouncer.yaml. Unknown fields are
// rejected at decode so an upstream change can't ride in silently.
//
// A bundle that only carries API specs is legal — Service is optional.
// When set, the Service block declares the canonical slug used by the
// services view and the tokens screen, plus the `token:` form variants
// the operator fills in.
type Manifest struct {
	SchemaVersion   int    `yaml:"schema_version"`
	Name            string `yaml:"name"`
	Version         string `yaml:"version"`
	Description     string `yaml:"description,omitempty"`
	MinProxyVersion string `yaml:"min_proxy_version,omitempty"`
	MaxProxyVersion string `yaml:"max_proxy_version,omitempty"`
	// APIs lists bundle-root-relative paths. Each entry is either a
	// YAML file or a directory (loaded by globbing *.yaml/*.yml,
	// non-recursively).
	APIs []string `yaml:"apis"`

	// Service declares the per-service metadata: the canonical slug,
	// a human title, and the `token:` form variants the operator can
	// pick from on the tokens screen.
	Service *Service `yaml:"service,omitempty"`

	// Token is the list of bring-your-own-token variants the tokens
	// screen renders. Each variant declares the fields the operator
	// types; non-refresh variants map each field onto an outgoing
	// header, refresh variants emit a refresh JWT.
	Token []TokenVariant `yaml:"token,omitempty"`
}

// Service is the per-service metadata block.
type Service struct {
	Slug        string `yaml:"slug"`
	Title       string `yaml:"title"`
	Description string `yaml:"description,omitempty"`
}

// TokenVariant is one bring-your-own-token shape the tokens screen
// renders. ID is the URL-friendly key; Title / Description describe
// the variant in the UI. Fields is the form schema.
//
// Refresh, when non-nil, marks this variant as emitting a refresh JWT
// (instead of an access JWT). The fields are then read as the
// refresh-token credential bundle (refresh_token / client_id /
// client_secret) rather than mapped onto outgoing headers.
type TokenVariant struct {
	ID          string         `yaml:"id"`
	Title       string         `yaml:"title"`
	Description string         `yaml:"description,omitempty"`
	Refresh     *RefreshConfig `yaml:"refresh,omitempty"`
	Fields      []TokenField   `yaml:"fields"`
}

// RefreshConfig declares the upstream OAuth2 token endpoint a refresh
// variant rotates against. TokenURL rides inside the refresh JWT so a
// Google refresh JWT and a Microsoft refresh JWT are interchangeable
// at the proxy.
type RefreshConfig struct {
	TokenURL string `yaml:"token_url"`
}

// TokenField is one input in a token variant's form. Kind drives the
// rendered control: `text` for a plain input, `secret` for a
// password-masked input, `multiline` for a textarea.
//
// For non-refresh variants, each field maps onto one outgoing header
// on the forwarded request. Header defaults to `Authorization`,
// Template defaults to `Bearer {{.}}` (the OAuth2-bearer norm). For
// refresh variants the field name picks the credential slot
// (refresh_token / client_id / client_secret); Header/Template are
// ignored.
type TokenField struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label,omitempty"`
	Kind        string `yaml:"kind,omitempty"` // text | secret | multiline
	Placeholder string `yaml:"placeholder,omitempty"`
	Help        string `yaml:"help,omitempty"`
	Required    bool   `yaml:"required,omitempty"`
	Header      string `yaml:"header,omitempty"`
	Template    string `yaml:"template,omitempty"`
}

// serviceSlug is the allowed shape for Service.Slug.
var serviceSlug = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// idPattern is the allowed shape for TokenVariant.ID and TokenField.Name.
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func (m *Manifest) Validate() error {
	if m.SchemaVersion == 0 {
		return fmt.Errorf("schema_version is required")
	}
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version %d not supported (this binary speaks %d)", m.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("version is required")
	}
	if len(m.APIs) == 0 {
		return fmt.Errorf("apis: at least one entry is required")
	}
	for i, p := range m.APIs {
		if err := validateRelPath(p); err != nil {
			return fmt.Errorf("apis[%d]: %w", i, err)
		}
	}
	if m.Service != nil {
		if err := m.Service.Validate(); err != nil {
			return fmt.Errorf("service: %w", err)
		}
	}
	if len(m.Token) > 0 && m.Service == nil {
		return fmt.Errorf("token requires a service: block")
	}
	seenVariant := map[string]bool{}
	for i, v := range m.Token {
		if err := v.validate(); err != nil {
			return fmt.Errorf("token[%d]: %w", i, err)
		}
		if seenVariant[v.ID] {
			return fmt.Errorf("token[%d]: duplicate id %q", i, v.ID)
		}
		seenVariant[v.ID] = true
	}
	return nil
}

func (s *Service) Validate() error {
	if !serviceSlug.MatchString(s.Slug) {
		return fmt.Errorf("slug %q must match %s", s.Slug, serviceSlug)
	}
	if strings.TrimSpace(s.Title) == "" {
		return fmt.Errorf("title is required")
	}
	return nil
}

func (v *TokenVariant) validate() error {
	if !idPattern.MatchString(v.ID) {
		return fmt.Errorf("id %q must match %s", v.ID, idPattern)
	}
	if strings.TrimSpace(v.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if len(v.Fields) == 0 {
		return fmt.Errorf("fields: at least one is required")
	}
	if v.Refresh != nil && strings.TrimSpace(v.Refresh.TokenURL) == "" {
		return fmt.Errorf("refresh.token_url is required")
	}
	seen := map[string]bool{}
	for i, f := range v.Fields {
		if err := f.validate(); err != nil {
			return fmt.Errorf("fields[%d]: %w", i, err)
		}
		if seen[f.Name] {
			return fmt.Errorf("fields[%d]: duplicate name %q", i, f.Name)
		}
		seen[f.Name] = true
	}
	return nil
}

func (f *TokenField) validate() error {
	if !idPattern.MatchString(f.Name) {
		return fmt.Errorf("name %q must match %s", f.Name, idPattern)
	}
	switch f.Kind {
	case "", "text", "secret", "multiline":
	default:
		return fmt.Errorf("kind %q must be one of text|secret|multiline", f.Kind)
	}
	return nil
}

func validateRelPath(p string) error {
	if p == "" {
		return fmt.Errorf("path is empty")
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must be relative", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("path %q escapes the bundle directory", p)
		}
	}
	return nil
}

// SourceRecord is the parsed shape of source.yaml — the only
// generated-by-tooling file inside a bundle.
type SourceRecord struct {
	Ref         string            `yaml:"ref"`
	ResolvedSHA string            `yaml:"resolved_sha"`
	FetchedAt   time.Time         `yaml:"fetched_at"`
	APIRenames  map[string]string `yaml:"api_renames,omitempty"`
}

func (s *SourceRecord) Validate() error {
	if strings.TrimSpace(s.Ref) == "" {
		return fmt.Errorf("ref is required")
	}
	if strings.TrimSpace(s.ResolvedSHA) == "" {
		return fmt.Errorf("resolved_sha is required")
	}
	for from, to := range s.APIRenames {
		if strings.TrimSpace(from) == "" {
			return fmt.Errorf("api_renames: empty key")
		}
		if strings.TrimSpace(to) == "" {
			return fmt.Errorf("api_renames[%s]: empty rename target", from)
		}
	}
	return nil
}

func LoadManifest(path string) (*Manifest, error) {
	var m Manifest
	if err := decodeYAML(path, &m); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

func LoadSource(path string) (*SourceRecord, error) {
	var s SourceRecord
	if err := decodeYAML(path, &s); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// WriteSource writes s atomically (temp file + rename). The temp name
// uses a random suffix so a pre-planted symlink at a predictable name
// can't redirect the write.
func WriteSource(path string, s *SourceRecord) error {
	if err := s.Validate(); err != nil {
		return err
	}
	raw, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal source.yaml: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".source-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp source.yaml: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	return nil
}

// decodeYAML opens path with KnownFields(true) so a typo'd field
// fails at load with line context instead of a silent zero default.
func decodeYAML(path string, into any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		if err == io.EOF {
			return fmt.Errorf("%s: empty document", path)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
