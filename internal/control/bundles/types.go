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
	"strconv"
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
// Service / OAuth / Token / Policies are all optional: a bundle that
// only carries API specs is still legal. When Service is present it
// declares the canonical slug for the service (`google`, `slack`, …),
// which is the key the connection store, the MCP layer, and the UI
// all use to refer to the same upstream.
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

	// Service declares the per-service metadata: the canonical slug
	// used everywhere else in bouncer, plus the MCP-staging artifact
	// (prompt, credential, env) the proxy uses to power
	// the `/{slug}-token` MCP prompt and `get_{slug}_token` tool. The
	// fields under `service:` describe the shared landing pad — what
	// the agent ends up reading on disk — not the specific input the
	// operator typed. Different `token:` variants converge on the
	// same credential file shape because every variant produces a
	// bouncer-issued bearer.
	Service *Service `yaml:"service,omitempty"`

	// OAuth, when set, drives the "Sign in with X" affordance on the
	// service-detail page. The redirect_path defaults to
	// `/_api/services/{slug}/oauth/callback` when omitted.
	OAuth *OAuthConfig `yaml:"oauth,omitempty"`

	// Token is the list of bring-your-own-token variants the UI
	// renders on the service-detail page. Each variant declares the
	// fields the operator types (label / kind / required) so the form
	// can be generated automatically from the manifest.
	Token []TokenVariant `yaml:"token,omitempty"`

	// Policies is the list of suggested policies the bundle ships.
	// The Service Policies tab lists each entry; Apply persists
	// through the existing policies.Service.Create path.
	Policies []SuggestedPolicy `yaml:"policies,omitempty"`
}

// Service is the per-service metadata block. Slug is the canonical
// key (matched against the connection store, the MCP prompt name,
// and the /_api/services/{slug} route). Title and Description drive
// the service-list and service-detail UI. The MCP-staging fields
// (Prompt, Credential, Env) are optional: a bundle whose
// service does not need a per-machine credential file (e.g. one
// that's purely OAuth-mediated) can omit them.
type Service struct {
	Slug        string `yaml:"slug"`
	Title       string `yaml:"title"`
	Description string `yaml:"description,omitempty"`

	// MCP-staging metadata. When all MCP-side fields are unset,
	// the proxy skips the /{slug}-token MCP prompt + tool wiring for
	// this service. When any is set, all required ones must be set;
	// the loader rejects half-configured records.
	Prompt     string            `yaml:"prompt,omitempty"`
	Credential CredentialSpec    `yaml:"credential,omitempty"`
	Env        map[string]string `yaml:"env,omitempty"`
}

// OAuthConfig is the dance config consumed by the service-detail
// "Sign in" tab. The tab is only enabled when the env vars named
// here are set on the bouncer process — otherwise we have no client
// secret to dial out with and the operator must use a bring-your-
// own-token variant instead.
type OAuthConfig struct {
	AuthorizeURL    string   `yaml:"authorize_url"`
	TokenURL        string   `yaml:"token_url"`
	Scopes          []string `yaml:"scopes,omitempty"`
	ClientIDEnv     string   `yaml:"client_id_env"`
	ClientSecretEnv string   `yaml:"client_secret_env"`
	// RedirectPath is the bouncer-side callback path the operator
	// must register with the upstream OAuth provider. Defaults to
	// `/_api/services/{slug}/oauth/callback` when omitted; the
	// loader rewrites the empty value to the default at validate
	// time.
	RedirectPath string `yaml:"redirect_path,omitempty"`
}

// TokenVariant is one bring-your-own-token shape the UI renders on
// the service-detail "Configure" tab. ID is the URL-friendly key
// (used by /_api/services/{slug}/connect to pick the variant);
// Title and Description describe the variant in the UI. Fields is
// the form schema.
type TokenVariant struct {
	ID          string       `yaml:"id"`
	Title       string       `yaml:"title"`
	Description string       `yaml:"description,omitempty"`
	Fields      []TokenField `yaml:"fields"`
}

// TokenField is one input in a token variant's form. Kind drives the
// rendered control: `text` for a plain input, `secret` for a
// password-masked input, `multiline` for a textarea (long pasted
// blobs like cookie strings). Required guards the submit; the
// backend re-validates.
type TokenField struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label,omitempty"`
	Kind        string `yaml:"kind,omitempty"` // text | secret | multiline
	Placeholder string `yaml:"placeholder,omitempty"`
	Help        string `yaml:"help,omitempty"`
	Required    bool   `yaml:"required,omitempty"`
}

// SuggestedPolicy is one hand-edited policy file the bundle ships.
// File is bundle-root-relative (typically `policies/<id>.yaml`). The
// CEL inside is taken verbatim — no templating in this iteration —
// so policies typically encode hard-coded identifiers (label IDs,
// hostnames). DefaultEnabled flags policies that should land
// pre-selected in the "Apply all defaults" affordance.
type SuggestedPolicy struct {
	ID             string `yaml:"id"`
	Title          string `yaml:"title"`
	Description    string `yaml:"description,omitempty"`
	File           string `yaml:"file"`
	DefaultEnabled bool   `yaml:"default_enabled,omitempty"`
}

// CredentialSpec is the on-disk shape of a staged credential.
//
// Template is a Go text/template body. Available vars at render time:
//
//	{{ .AccessToken }} — encrypted bouncer-issued bearer
//	{{ .Path }}        — resolved absolute credential-file path
//	{{ .Service }}     — the service slug
type CredentialSpec struct {
	Path     string `yaml:"path"`
	Mode     string `yaml:"mode"`
	Template string `yaml:"template"`
}

// serviceSlug is the allowed shape for Service.Slug. It's the
// suffix of the MCP prompt name (`/{slug}-token`), so it has to
// be slash-command friendly.
var serviceSlug = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// tokenVariantID is the allowed shape for TokenVariant.ID and
// SuggestedPolicy.ID. Same alphabet as the service slug so URL
// segments stay predictable.
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
	// OAuth and Token require a Service block — they're meaningless
	// without a slug to key on.
	if (m.OAuth != nil || len(m.Token) > 0) && m.Service == nil {
		return fmt.Errorf("oauth / token require a service: block")
	}
	if m.OAuth != nil {
		if err := m.OAuth.validate(m.Service.Slug); err != nil {
			return fmt.Errorf("oauth: %w", err)
		}
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
	seenPolicy := map[string]bool{}
	for i, p := range m.Policies {
		if err := p.validate(); err != nil {
			return fmt.Errorf("policies[%d]: %w", i, err)
		}
		if seenPolicy[p.ID] {
			return fmt.Errorf("policies[%d]: duplicate id %q", i, p.ID)
		}
		seenPolicy[p.ID] = true
	}
	return nil
}

// Validate enforces the contract documented on Service. Called as
// part of Manifest.Validate. The MCP-staging fields are validated
// only when *any* of them is set; an all-empty MCP block is fine
// (bundle just doesn't register an MCP prompt for this service).
func (s *Service) Validate() error {
	if !serviceSlug.MatchString(s.Slug) {
		return fmt.Errorf("slug %q must match %s", s.Slug, serviceSlug)
	}
	if strings.TrimSpace(s.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if s.hasMCPStaging() {
		if err := validateRelPath(s.Prompt); err != nil {
			return fmt.Errorf("prompt: %w", err)
		}
		if err := s.Credential.Validate(); err != nil {
			return fmt.Errorf("credential: %w", err)
		}
		for k := range s.Env {
			if strings.TrimSpace(k) == "" {
				return fmt.Errorf("env: empty key")
			}
		}
	}
	return nil
}

// hasMCPStaging reports whether the operator opted into MCP token
// staging by setting any of the MCP fields. An all-empty MCP block
// is a no-op; a partially-filled block is a config error caught by
// Validate.
func (s *Service) hasMCPStaging() bool {
	return s.Prompt != "" ||
		s.Credential.Path != "" ||
		s.Credential.Mode != "" ||
		s.Credential.Template != "" ||
		len(s.Env) > 0
}

func (o *OAuthConfig) validate(slug string) error {
	if strings.TrimSpace(o.AuthorizeURL) == "" {
		return fmt.Errorf("authorize_url is required")
	}
	if strings.TrimSpace(o.TokenURL) == "" {
		return fmt.Errorf("token_url is required")
	}
	if strings.TrimSpace(o.ClientIDEnv) == "" {
		return fmt.Errorf("client_id_env is required")
	}
	if strings.TrimSpace(o.ClientSecretEnv) == "" {
		return fmt.Errorf("client_secret_env is required")
	}
	if o.RedirectPath == "" {
		o.RedirectPath = "/_api/services/" + slug + "/oauth/callback"
	}
	if !strings.HasPrefix(o.RedirectPath, "/") {
		return fmt.Errorf("redirect_path %q must start with /", o.RedirectPath)
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

func (p *SuggestedPolicy) validate() error {
	if !idPattern.MatchString(p.ID) {
		return fmt.Errorf("id %q must match %s", p.ID, idPattern)
	}
	if strings.TrimSpace(p.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if err := validateRelPath(p.File); err != nil {
		return fmt.Errorf("file: %w", err)
	}
	return nil
}

func (c *CredentialSpec) Validate() error {
	if strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("path is required")
	}
	if strings.TrimSpace(c.Mode) == "" {
		return fmt.Errorf("mode is required")
	}
	if _, err := strconv.ParseUint(c.Mode, 8, 32); err != nil {
		return fmt.Errorf("mode %q must be an octal literal", c.Mode)
	}
	if strings.TrimSpace(c.Template) == "" {
		return fmt.Errorf("template is required")
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
