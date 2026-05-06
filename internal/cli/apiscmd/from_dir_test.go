package apiscmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// stageBundleDir builds a minimal bundle on disk: apis.yaml manifest,
// apis/ subdir with one spec, and a fake .git/ to confirm the
// .git-skip in copyTree fires. Returns the directory path.
func stageBundleDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, bundles.ManifestFile),
		[]byte("schema_version: 1\nname: pack\nversion: 1.0.0\napis: [apis/a.yaml]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, bundles.APIsSubdir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bundles.APIsSubdir, "a.yaml"),
		[]byte("name: gmail\nbase_url: https://x\npath_prefixes: [/g]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunAddFromDirInstallsBundle(t *testing.T) {
	src := stageBundleDir(t)
	vendored := t.TempDir()

	const refStr = "github.com/jkylling/bouncer-gws@dev"
	if err := runAddFromDir(src, refStr, "", vendored, map[string]string{"gmail": "acme-gmail"}, true); err != nil {
		t.Fatalf("from-dir: %v", err)
	}

	finalDir := bundles.BundleDir(vendored, "pack")

	// Manifest + spec made it through.
	if _, err := os.Stat(filepath.Join(finalDir, bundles.ManifestFile)); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(finalDir, bundles.APIsSubdir, "a.yaml")); err != nil {
		t.Fatalf("api spec missing: %v", err)
	}
	// .git/ was skipped on copy.
	if _, err := os.Stat(filepath.Join(finalDir, ".git")); !os.IsNotExist(err) {
		t.Fatalf(".git was copied (err = %v)", err)
	}
	// source.yaml synthesized with the user-supplied ref + rename.
	got, err := bundles.LoadSource(filepath.Join(finalDir, bundles.SourceFile))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	if got.Ref != refStr {
		t.Errorf("Ref = %q, want %q", got.Ref, refStr)
	}
	if got.ResolvedSHA != "dev" {
		t.Errorf("ResolvedSHA = %q, want dev", got.ResolvedSHA)
	}
	if got.APIRenames["gmail"] != "acme-gmail" {
		t.Errorf("rename not applied: %v", got.APIRenames)
	}
}

func TestRunAddFromDirRefusesIfInstalled(t *testing.T) {
	src := stageBundleDir(t)
	vendored := t.TempDir()
	const refStr = "github.com/jkylling/bouncer-gws@dev"

	if err := runAddFromDir(src, refStr, "", vendored, nil, true); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if err := runAddFromDir(src, refStr, "", vendored, nil, true); err == nil {
		t.Fatal("second install: want error")
	}
}

func TestRunAddFromDirRequiresRef(t *testing.T) {
	src := stageBundleDir(t)
	if err := runAddFromDir(src, "", "", t.TempDir(), nil, true); err == nil {
		t.Fatal("missing --ref: want error")
	}
}

func TestRunAddFromDirRejectsMissingManifest(t *testing.T) {
	dir := t.TempDir() // no apis.yaml
	if err := runAddFromDir(dir, "github.com/x/y@v1", "", t.TempDir(), nil, true); err == nil {
		t.Fatal("missing manifest: want error")
	}
}
