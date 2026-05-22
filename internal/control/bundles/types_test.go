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

func TestLoadManifestWithService(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-gws
version: 0.1.0
apis:
  - apis/
service:
  slug: google
  title: Google Workspace
  description: Gmail, Drive, Calendar, Docs, Sheets.
`)
	m, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Service == nil {
		t.Fatal("Service is nil")
	}
	if m.Service.Slug != "google" || m.Service.Title != "Google Workspace" {
		t.Fatalf("got %+v", m.Service)
	}
}

func TestLoadManifestServiceOmittedOK(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-bare
version: 0.1.0
apis:
  - apis/x.yaml
`)
	m, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Service != nil {
		t.Fatalf("expected nil Service, got %+v", m.Service)
	}
}

func TestLoadManifestServiceRejectsBadSlug(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-x
version: 0.1.0
apis: [apis/a.yaml]
service:
  slug: "Bad Slug"
  title: bad
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "slug") {
		t.Fatalf("want slug error, got %v", err)
	}
}

func TestLoadManifestWithTokenVariants(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-gws
version: 0.1.0
apis: [apis/a.yaml]
service:
  slug: google
  title: Google
token:
  - id: access_token
    title: Access token
    description: paste an access token
    fields:
      - name: access_token
        label: Access token
        kind: secret
        required: true
  - id: refresh_token
    title: Refresh token
    refresh:
      token_url: https://oauth2.googleapis.com/token
    fields:
      - name: client_id
        kind: text
        required: true
      - name: client_secret
        kind: secret
        required: true
      - name: refresh_token
        kind: secret
        required: true
`)
	m, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(m.Token) != 2 {
		t.Fatalf("variants = %d", len(m.Token))
	}
	if m.Token[0].ID != "access_token" || m.Token[1].ID != "refresh_token" {
		t.Fatalf("got %+v", m.Token)
	}
	if m.Token[1].Refresh == nil || m.Token[1].Refresh.TokenURL == "" {
		t.Fatalf("refresh missing on variant 1: %+v", m.Token[1])
	}
	if len(m.Token[1].Fields) != 3 {
		t.Fatalf("refresh fields = %d", len(m.Token[1].Fields))
	}
}

func TestLoadManifestTokenWithCustomHeader(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-slack
version: 0.1.0
apis: [apis/a.yaml]
service:
  slug: slack
  title: Slack
token:
  - id: browser_cookies
    title: Browser cookies
    fields:
      - name: access_token
        kind: secret
      - name: cookie_d
        kind: secret
        header: Cookie
        template: "d={{.}}"
`)
	m, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Token[0].Fields[1].Header != "Cookie" || m.Token[0].Fields[1].Template != "d={{.}}" {
		t.Fatalf("custom header field = %+v", m.Token[0].Fields[1])
	}
}

func TestLoadManifestTokenRefreshRequiresTokenURL(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-x
version: 0.1.0
apis: [apis/a.yaml]
service:
  slug: google
  title: Google
token:
  - id: r
    title: R
    refresh: {}
    fields:
      - name: refresh_token
        kind: secret
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "token_url") {
		t.Fatalf("want token_url error, got %v", err)
	}
}

func TestLoadManifestTokenRequiresService(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-x
version: 0.1.0
apis: [apis/a.yaml]
token:
  - id: a
    title: A
    fields:
      - name: x
        kind: text
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("want service error, got %v", err)
	}
}

func TestLoadManifestTokenRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-x
version: 0.1.0
apis: [apis/a.yaml]
service:
  slug: google
  title: Google
token:
  - id: a
    title: A
    fields:
      - name: x
        kind: text
  - id: a
    title: B
    fields:
      - name: y
        kind: text
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate error, got %v", err)
	}
}

func TestLoadManifestTokenRejectsBadFieldKind(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ManifestFile), `schema_version: 1
name: bouncer-x
version: 0.1.0
apis: [apis/a.yaml]
service:
  slug: google
  title: Google
token:
  - id: a
    title: A
    fields:
      - name: x
        kind: cucumber
`)
	_, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("want kind error, got %v", err)
	}
}

func TestSourceRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SourceFile)
	want := &SourceRecord{
		Ref:         "github.com/foo/bar@v1.4.0",
		ResolvedSHA: "7a3c1f4abcd",
		FetchedAt:   time.Date(2026, 5, 4, 12, 34, 56, 0, time.UTC),
		APIRenames:  map[string]string{"google.gmail": "foo-gmail"},
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
	if got.APIRenames["google.gmail"] != "foo-gmail" {
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
