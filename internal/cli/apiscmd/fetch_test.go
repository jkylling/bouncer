package apiscmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// TestFetchPackThenInstallFromTarball drives the full air-gap loop:
// pack a fetched bundle into a tarball via writeBundleTarball, then
// install it back via runAddFromTarball, with no network in between.
// Mirrors the operator workflow `apis fetch ... | scp ... | apis add
// --from-tarball ...`.
func TestFetchPackThenInstallFromTarball(t *testing.T) {
	staging := t.TempDir()
	if err := os.WriteFile(filepath.Join(staging, bundles.ManifestFile),
		[]byte("schema_version: 1\nname: pack\nversion: 1.0.0\napis: [apis/a.yaml]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(staging, bundles.APIsSubdir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, bundles.APIsSubdir, "a.yaml"),
		[]byte("name: gmail\nbase_url: https://x\npath_prefixes: [/g]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := &bundles.SourceRecord{
		Ref:         "github.com/acme/pack@v1.0.0",
		ResolvedSHA: "7a3c1f4abcdef0123456789abcdef0123456789a",
	}
	if err := bundles.WriteSource(filepath.Join(staging, bundles.SourceFile), src); err != nil {
		t.Fatal(err)
	}

	ref, _ := bundles.ParseRef(src.Ref)
	tarball := filepath.Join(t.TempDir(), "pack.tgz")
	if err := writeBundleTarball(tarball, staging, ref, src.ResolvedSHA); err != nil {
		t.Fatalf("pack: %v", err)
	}
	if _, err := os.Stat(tarball); err != nil {
		t.Fatalf("tarball missing: %v", err)
	}

	vendored := t.TempDir()
	if err := runAddFromTarball(tarball, "", "", vendored, map[string]string{"gmail": "acme-gmail"}, true); err != nil {
		t.Fatalf("from-tarball: %v", err)
	}
	finalDir := bundles.BundleDir(vendored, "pack")
	if _, err := os.Stat(filepath.Join(finalDir, bundles.ManifestFile)); err != nil {
		t.Fatalf("not installed: %v", err)
	}
	_ = ref
	got, err := bundles.LoadSource(filepath.Join(finalDir, bundles.SourceFile))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	if got.APIRenames["gmail"] != "acme-gmail" {
		t.Fatalf("rename not applied: %v", got.APIRenames)
	}
	if !got.FetchedAt.After(src.FetchedAt) && !got.FetchedAt.Equal(src.FetchedAt) {
		t.Fatalf("fetched_at not refreshed: %v", got.FetchedAt)
	}
}

func TestRunAddFromTarballRefusesIfInstalled(t *testing.T) {
	staging := t.TempDir()
	_ = os.WriteFile(filepath.Join(staging, bundles.ManifestFile),
		[]byte("schema_version: 1\nname: pack\nversion: 1.0.0\napis: [apis/a.yaml]\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(staging, bundles.APIsSubdir), 0o755)
	_ = os.WriteFile(filepath.Join(staging, bundles.APIsSubdir, "a.yaml"), []byte("name: gmail\n"), 0o600)
	sha := "7a3c1f4abcdef0123456789abcdef0123456789a"
	_ = bundles.WriteSource(filepath.Join(staging, bundles.SourceFile), &bundles.SourceRecord{
		Ref: "github.com/acme/pack@v1.0.0", ResolvedSHA: sha,
	})
	ref, _ := bundles.ParseRef("github.com/acme/pack@v1.0.0")
	tarball := filepath.Join(t.TempDir(), "pack.tgz")
	if err := writeBundleTarball(tarball, staging, ref, sha); err != nil {
		t.Fatal(err)
	}
	vendored := t.TempDir()
	if err := runAddFromTarball(tarball, "", "", vendored, nil, true); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if err := runAddFromTarball(tarball, "", "", vendored, nil, true); err == nil {
		t.Fatal("second install: want error")
	}
}

func TestFetchEndToEnd(t *testing.T) {
	sha := "7a3c1f4abcdef0123456789abcdef0123456789a"
	bundle := gzipBundle(t, "pack-7a3c1f4", map[string]string{
		"bouncer.yaml": "schema_version: 1\nname: pack\nversion: 1.0.0\napis: [apis/a.yaml]\n",
		"apis/a.yaml":  "name: gmail\nbase_url: https://x\npath_prefixes: [/g]\n",
	})
	srv := fakeServer(t, sha, bundle)

	ref, _ := bundles.ParseRef("github.com/acme/pack@v1.0.0")
	out := filepath.Join(t.TempDir(), "pack.tgz")
	f := bundles.NewFetcher(bundles.FetcherOpts{APIBase: srv.URL, CodeloadBase: srv.URL})

	resolved, err := f.ResolveSHA(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	body, err := f.Download(context.Background(), ref, resolved)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()

	work := t.TempDir()
	if err := bundles.ExtractTarGz(body, work); err != nil {
		t.Fatal(err)
	}
	src := &bundles.SourceRecord{Ref: ref.String(), ResolvedSHA: resolved, FetchedAt: nowUTCSecond()}
	if err := bundles.WriteSource(filepath.Join(work, bundles.SourceFile), src); err != nil {
		t.Fatal(err)
	}
	if err := writeBundleTarball(out, work, ref, resolved); err != nil {
		t.Fatal(err)
	}

	roundTrip := t.TempDir()
	if err := bundles.ExtractTarGz(mustOpen(t, out), roundTrip); err != nil {
		t.Fatal(err)
	}
	got, err := bundles.LoadSource(filepath.Join(roundTrip, bundles.SourceFile))
	if err != nil {
		t.Fatal(err)
	}
	if got.ResolvedSHA != sha {
		t.Fatalf("sha = %q", got.ResolvedSHA)
	}
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestRunAddFromTarballHonoursRefOverride checks --ref overrides the
// embedded ref. Useful when a tarball was hand-built from a fork
// whose source.yaml carries the wrong identity.
func TestRunAddFromTarballHonoursRefOverride(t *testing.T) {
	staging := t.TempDir()
	_ = os.WriteFile(filepath.Join(staging, bundles.ManifestFile),
		[]byte("schema_version: 1\nname: pack\nversion: 1.0.0\napis: [apis/a.yaml]\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(staging, bundles.APIsSubdir), 0o755)
	_ = os.WriteFile(filepath.Join(staging, bundles.APIsSubdir, "a.yaml"), []byte("name: gmail\n"), 0o600)
	sha := "7a3c1f4abcdef0123456789abcdef0123456789a"
	_ = bundles.WriteSource(filepath.Join(staging, bundles.SourceFile), &bundles.SourceRecord{
		Ref: "github.com/acme/pack@v1.0.0", ResolvedSHA: sha,
	})
	ref, _ := bundles.ParseRef("github.com/acme/pack@v1.0.0")
	tarball := filepath.Join(t.TempDir(), "pack.tgz")
	if err := writeBundleTarball(tarball, staging, ref, sha); err != nil {
		t.Fatal(err)
	}

	vendored := t.TempDir()
	if err := runAddFromTarball(tarball, "github.com/foo/forked@v0.1.0", "", vendored, nil, true); err != nil {
		t.Fatalf("override: %v", err)
	}
	// The on-disk path is keyed by manifest name (still "pack");
	// only the recorded source.yaml#ref reflects the override.
	finalDir := bundles.BundleDir(vendored, "pack")
	if _, err := os.Stat(filepath.Join(finalDir, bundles.ManifestFile)); err != nil {
		t.Fatalf("override install missing: %v", err)
	}
	rec, err := bundles.LoadSource(filepath.Join(finalDir, bundles.SourceFile))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	if rec.Ref != "github.com/foo/forked@v0.1.0" {
		t.Fatalf("source.yaml ref = %q, want override", rec.Ref)
	}
}
