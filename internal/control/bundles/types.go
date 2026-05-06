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
}

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
