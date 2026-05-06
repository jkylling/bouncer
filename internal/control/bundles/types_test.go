package bundles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestLoadManifestHappyPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: acme
version: 1.4.0
description: stripe + github
min_proxy_version: 0.5.0
max_proxy_version: 1.x
apis:
  - apis/stripe.yaml
  - apis/github.yaml
`)
	m, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Name != "acme" || m.Version != "1.4.0" {
		t.Fatalf("got %+v", m)
	}
	if len(m.APIs) != 2 || m.APIs[0] != "apis/stripe.yaml" {
		t.Fatalf("apis = %v", m.APIs)
	}
}

func TestLoadManifestRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: acme
version: 1.0.0
apis: [apis/a.yaml]
unknown_field: oops
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("want unknown_field error, got %v", err)
	}
}

func TestLoadManifestRejectsBadSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 99
name: acme
version: 1.0.0
apis: [apis/a.yaml]
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("want schema_version error, got %v", err)
	}
}

func TestLoadManifestRejectsEmptyAPIs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: acme
version: 1.0.0
apis: []
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "apis") {
		t.Fatalf("want apis error, got %v", err)
	}
}

func TestLoadManifestRejectsEscapingPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: acme
version: 1.0.0
apis: ['../escape.yaml']
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "escape") {
		t.Fatalf("want escape error, got %v", err)
	}
}

func TestSourceRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SourceFile)
	want := &SourceRecord{
		Ref:         "github.com/foo/bar@v1.4.0",
		ResolvedSHA: "7a3c1f4abcd",
		FetchedAt:   time.Date(2026, 5, 4, 12, 34, 56, 0, time.UTC),
		APIRenames:  map[string]string{"gmail": "foo-gmail"},
	}
	if err := WriteSource(path, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadSource(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Ref != want.Ref || got.ResolvedSHA != want.ResolvedSHA {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if got.APIRenames["gmail"] != "foo-gmail" {
		t.Fatalf("renames = %v", got.APIRenames)
	}
	if !got.FetchedAt.Equal(want.FetchedAt) {
		t.Fatalf("fetched_at = %v want %v", got.FetchedAt, want.FetchedAt)
	}
}

func TestLoadSourceRejectsMissingFields(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, SourceFile), `ref: ""
resolved_sha: 7a3c1f4
fetched_at: 2026-05-04T12:34:56Z
`)
	_, err := LoadSource(filepath.Join(dir, SourceFile))
	if err == nil || !strings.Contains(err.Error(), "ref") {
		t.Fatalf("want ref error, got %v", err)
	}
}
