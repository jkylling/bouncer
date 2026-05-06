package apiscmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// writeMinimalSrc lays out a one-API bundle on disk: apis.yaml +
// apis/<name>.yaml. Returns the source dir so each test can hand
// the path to runPack.
func writeMinimalSrc(t *testing.T, name, version, apiFile string) string {
	t.Helper()
	dir := t.TempDir()
	manifest := "schema_version: 1\nname: " + name + "\nversion: " + version + "\napis: [apis/" + apiFile + "]\n"
	mustWrite(t, filepath.Join(dir, bundles.ManifestFile), manifest)
	mustWrite(t, filepath.Join(dir, bundles.APIsSubdir, apiFile),
		"name: stub\nbase_url: https://example.invalid\npath_prefixes: [/stub]\n")
	return dir
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestPackHappyPath drives the full round-trip: lay out a bundle on
// disk, pack it, extract via the same ExtractTarGz the install path
// uses, confirm the manifest survives byte-for-byte and the prefix
// is "<name>-<version>".
func TestPackHappyPath(t *testing.T) {
	src := writeMinimalSrc(t, "bouncer-svc", "1.2.3", "stub.yaml")
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")

	if err := runPack([]string{src, "--output", out, "--ref", "github.com/me/bouncer-svc@v1.2.3"}); err != nil {
		t.Fatalf("runPack: %v", err)
	}

	// Inspect the tarball directly to assert the prefix.
	prefix := readFirstPrefix(t, out)
	if prefix != "bouncer-svc-1.2.3" {
		t.Errorf("prefix = %q, want bouncer-svc-1.2.3", prefix)
	}

	// Round-trip through ExtractTarGz so we know `apis add
	// --from-tarball` will accept the output.
	dest := t.TempDir()
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if err := bundles.ExtractTarGz(f, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	mf, err := bundles.LoadManifest(filepath.Join(dest, bundles.ManifestFile))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if mf.Name != "bouncer-svc" || mf.Version != "1.2.3" {
		t.Errorf("manifest = %+v", mf)
	}
	api, err := os.ReadFile(filepath.Join(dest, bundles.APIsSubdir, "stub.yaml"))
	if err != nil {
		t.Fatalf("read api: %v", err)
	}
	if !strings.Contains(string(api), "name: stub") {
		t.Errorf("api body lost: %q", api)
	}
}

// TestPackRejectsBadManifest pins the up-front validation: a
// missing apis.yaml fails fast with a clear error rather than
// producing an unusable tarball.
func TestPackRejectsBadManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, bundles.APIsSubdir), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	err := runPack([]string{dir, "--output", out, "--ref", "github.com/me/x@v1"})
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("err = %v, want one mentioning manifest", err)
	}
}

// TestPackRejectsMissingListedAPI pins that the manifest's apis
// list is checked against disk: a typo'd or forgotten file is
// caught at pack time, not at install time on the consumer.
func TestPackRejectsMissingListedAPI(t *testing.T) {
	dir := t.TempDir()
	manifest := "schema_version: 1\nname: x\nversion: 0.1\napis: [apis/missing.yaml]\n"
	mustWrite(t, filepath.Join(dir, bundles.ManifestFile), manifest)
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	err := runPack([]string{dir, "--output", out, "--ref", "github.com/me/x@v1"})
	if err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Fatalf("err = %v, want one naming the missing file", err)
	}
}

// TestPackRequiresOutput pins the flag-validation path so a typo
// fails loud instead of silently writing nowhere.
func TestPackRequiresOutput(t *testing.T) {
	src := writeMinimalSrc(t, "x", "0.1", "stub.yaml")
	err := runPack([]string{src, "--ref", "github.com/me/x@v0.1"})
	if err == nil || !strings.Contains(err.Error(), "--output") {
		t.Fatalf("err = %v, want one mentioning --output", err)
	}
}

// TestPackRequiresRef pins the corresponding ref-validation path:
// the install record needs a ref, so omitting --ref must fail loud.
func TestPackRequiresRef(t *testing.T) {
	src := writeMinimalSrc(t, "x", "0.1", "stub.yaml")
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	err := runPack([]string{src, "--output", out})
	if err == nil || !strings.Contains(err.Error(), "--ref") {
		t.Fatalf("err = %v, want one mentioning --ref", err)
	}
}

// TestPackEmbedsSourceYAML pins the install-record contract:
// `apis add --from-tarball` requires source.yaml inside the
// tarball. The pack output stamps it with the supplied ref + a
// 40-hex content-derived SHA so installs work without the operator
// re-supplying --ref.
func TestPackEmbedsSourceYAML(t *testing.T) {
	src := writeMinimalSrc(t, "stamped", "0.1.0", "stub.yaml")
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := runPack([]string{src, "--output", out, "--ref", "github.com/me/stamped@v0.1.0"}); err != nil {
		t.Fatalf("runPack: %v", err)
	}

	dest := t.TempDir()
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if err := bundles.ExtractTarGz(f, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	rec, err := bundles.LoadSource(filepath.Join(dest, bundles.SourceFile))
	if err != nil {
		t.Fatalf("source.yaml: %v", err)
	}
	if rec.Ref != "github.com/me/stamped@v0.1.0" {
		t.Errorf("ref = %q", rec.Ref)
	}
	if !bundles.IsFullSHA(rec.ResolvedSHA) {
		t.Errorf("resolved_sha = %q, want 40-hex", rec.ResolvedSHA)
	}
}

// readFirstPrefix returns the directory name of the first non-pax
// entry in the tarball. The pack output starts with the prefix dir
// itself (TypeDir, "<prefix>/"), so this is a one-entry read.
func readFirstPrefix(t *testing.T, tarballPath string) string {
	t.Helper()
	raw, err := os.ReadFile(tarballPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatal("empty tarball")
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		// Skip pax global headers which some tar writers prepend.
		if hdr.Typeflag == tar.TypeXGlobalHeader || hdr.Typeflag == tar.TypeXHeader {
			continue
		}
		return strings.TrimSuffix(hdr.Name, "/")
	}
}
