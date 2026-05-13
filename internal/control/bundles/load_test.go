package bundles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBundle(t *testing.T, apisDir, name, manifest string, apis map[string]string, source string) string {
	t.Helper()
	dir := filepath.Join(apisDir, name)
	if err := os.MkdirAll(filepath.Join(dir, APIsSubdir), 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), []byte(manifest), 0o600); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, SourceFile), []byte(source), 0o600); err != nil {
		t.Fatalf("source: %v", err)
	}
	for fname, body := range apis {
		if err := os.WriteFile(filepath.Join(dir, APIsSubdir, fname), []byte(body), 0o600); err != nil {
			t.Fatalf("write api: %v", err)
		}
	}
	return dir
}

func TestLoadAllLooseTopLevel(t *testing.T) {
	apis := t.TempDir()
	if err := os.WriteFile(filepath.Join(apis, "gmail.yaml"), []byte("name: google.gmail\nbase_url: https://x\npath_prefixes: [/gmail]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAll(LoadOptions{APIsDir: apis})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 || got[0].Spec.Name != "google.gmail" {
		t.Fatalf("got = %+v", got)
	}
	if got[0].BundleDir != "" {
		t.Fatalf("loose spec should have empty BundleDir; got %q", got[0].BundleDir)
	}
}

func TestLoadAllBundleAppliesRename(t *testing.T) {
	apis := t.TempDir()
	writeBundle(t, apis, "pack",
		`schema_version: 1
name: pack
version: 1.0.0
apis:
  - apis/gmail.yaml
`,
		map[string]string{"gmail.yaml": "name: gmail\nbase_url: https://x\npath_prefixes: [/gmail]\n"},
		`ref: github.com/acme/pack@v1.0.0
resolved_sha: 7a3c1f4abcdef0123456789abcdef0123456789a
fetched_at: 2026-05-04T12:00:00Z
api_renames:
  gmail: acme-gmail
`)
	got, err := LoadAll(LoadOptions{APIsDir: apis})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 || got[0].Spec.Name != "acme-gmail" {
		t.Fatalf("got = %+v", got)
	}
	if got[0].BundleDir == "" {
		t.Fatal("expected BundleDir to be populated")
	}
}

func TestLoadAllRejectsDuplicateNames(t *testing.T) {
	apis := t.TempDir()
	_ = os.WriteFile(filepath.Join(apis, "g.yaml"), []byte("name: gmail\nbase_url: https://x\npath_prefixes: [/g1]\n"), 0o600)

	writeBundle(t, apis, "pack",
		`schema_version: 1
name: pack
version: 1.0.0
apis:
  - apis/gmail.yaml
`,
		map[string]string{"gmail.yaml": "name: gmail\nbase_url: https://x\npath_prefixes: [/g2]\n"},
		`ref: github.com/acme/pack@v1.0.0
resolved_sha: 7a3c1f4abcdef0123456789abcdef0123456789a
fetched_at: 2026-05-04T12:00:00Z
`)
	_, err := LoadAll(LoadOptions{APIsDir: apis})
	if err == nil || !strings.Contains(err.Error(), "declared twice") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "g.yaml") || !strings.Contains(err.Error(), "gmail.yaml") {
		t.Fatalf("err missing source paths: %v", err)
	}
}

func TestLoadAllMissingManifestEntryFails(t *testing.T) {
	apis := t.TempDir()
	writeBundle(t, apis, "pack",
		`schema_version: 1
name: pack
version: 1.0.0
apis:
  - apis/missing.yaml
`,
		map[string]string{}, // no apis files
		`ref: github.com/acme/pack@v1.0.0
resolved_sha: 7a3c1f4abcdef0123456789abcdef0123456789a
fetched_at: 2026-05-04T12:00:00Z
`)
	_, err := LoadAll(LoadOptions{APIsDir: apis})
	if err == nil {
		t.Fatal("expected error for missing apis file")
	}
}

func TestLoadAllEmptyDirsAreNoOp(t *testing.T) {
	got, err := LoadAll(LoadOptions{APIsDir: filepath.Join(t.TempDir(), "missing")})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %v", got)
	}
}

// Pins the scratch-dir guard: a `.tmp.*` left by a crashed install
// must not break boot, even if it has a manifest inside.
func TestLoadAllSkipsDotPrefixedDirs(t *testing.T) {
	apis := t.TempDir()
	scratch := filepath.Join(apis, ".tmp.broken")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratch, ManifestFile), []byte("not-a-manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAll(LoadOptions{APIsDir: apis})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got = %+v, want empty", got)
	}
}
