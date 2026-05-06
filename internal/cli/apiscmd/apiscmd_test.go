package apiscmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// installFixture lays a minimal valid bundle directly under apisDir
// (apisDir/<bundleName>/) — bypassing the fetcher — so list/remove
// can be tested without a fake GitHub server. slug is recorded in
// source.yaml#ref so upgrade/list-by-ref still resolve the way they
// would for a real install; sha lands in source.yaml#resolved_sha.
func installFixture(t *testing.T, apisDir, slug, sha, manifestVersion string, renames map[string]string) string {
	t.Helper()
	bundleName := filepath.Base(slug) // e.g. github.com/acme/pack -> pack
	dir := bundles.BundleDir(apisDir, bundleName)
	if err := os.MkdirAll(filepath.Join(dir, bundles.APIsSubdir), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "schema_version: 1\nname: " + bundleName + "\nversion: " + manifestVersion + "\napis: [apis/a.yaml]\n"
	if err := os.WriteFile(filepath.Join(dir, bundles.ManifestFile), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	src := &bundles.SourceRecord{
		Ref:         slug + "@v" + manifestVersion,
		ResolvedSHA: sha,
		APIRenames:  renames,
	}
	if err := bundles.WriteSource(filepath.Join(dir, bundles.SourceFile), src); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bundles.APIsSubdir, "a.yaml"), []byte("name: gmail\nbase_url: https://x\npath_prefixes: [/g]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestParseRenamesHappyPath(t *testing.T) {
	got, err := parseRenames([]string{"gmail=acme-gmail", "drive=acme-drive"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got["gmail"] != "acme-gmail" || got["drive"] != "acme-drive" {
		t.Fatalf("got = %v", got)
	}
}

func TestParseRenamesRejectsMalformed(t *testing.T) {
	cases := []string{"foo", "=bar", "foo=", "  =   "}
	for _, c := range cases {
		_, err := parseRenames([]string{c})
		if err == nil {
			t.Fatalf("expected error for %q", c)
		}
	}
}

func TestParseRenamesRejectsDuplicate(t *testing.T) {
	_, err := parseRenames([]string{"gmail=a", "gmail=b"})
	if err == nil || !strings.Contains(err.Error(), "already mapped") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanInstalledBundles(t *testing.T) {
	root := t.TempDir()
	installFixture(t, root, "github.com/acme/pack", "7a3c1f4abcdef0123456789abcdef0123456789a", "1.0.0", nil)
	installFixture(t, root, "github.com/foo/bar", "0000000000000000000000000000000000000001", "0.5.0", map[string]string{"gmail": "foo-gmail"})
	got, err := scanInstalledBundles(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d bundles, want 2", len(got))
	}
	// Sorted lexicographically by bundle name: bar < pack.
	if got[0].Name != "bar" {
		t.Fatalf("first row = %+v", got[0])
	}
	if got[0].RenameCount != 1 {
		t.Fatalf("first row renames = %d", got[0].RenameCount)
	}
	if got[1].Name != "pack" {
		t.Fatalf("second row = %+v", got[1])
	}
}

func TestScanInstalledBundlesEmptyRoot(t *testing.T) {
	got, err := scanInstalledBundles(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bundles, want 0", len(got))
	}
}

func TestRunRemoveDeletesByName(t *testing.T) {
	root := t.TempDir()
	dir := installFixture(t, root, "github.com/acme/pack", "7a3c1f4abcdef0123456789abcdef0123456789a", "1.0.0", nil)
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	if err := runRemove([]string{"--apis-dir", root, "pack"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("dir should be gone")
	}
}

func TestRunRemoveErrorsWhenNameNotInstalled(t *testing.T) {
	err := runRemove([]string{"--apis-dir", t.TempDir(), "pack"})
	if err == nil || !strings.Contains(err.Error(), "no bundle") {
		t.Fatalf("err = %v", err)
	}
}

// TestRunRemoveRejectsTraversal pins the containment guard: a name
// like "../etc" must not let RemoveAll escape the apis dir.
func TestRunRemoveRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	err := runRemove([]string{"--apis-dir", root, "../escape"})
	if err == nil || !strings.Contains(err.Error(), "path separators") {
		t.Fatalf("err = %v", err)
	}
}

// fakeServer wraps the bundles fetcher's expected endpoints in one
// httptest server so add can be exercised without the real internet.
func fakeServer(t *testing.T, sha string, body []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sha))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func gzipBundle(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{
			Name:     prefix + "/" + name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(body)),
		})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// TestFetcherInstallViaCmd exercises the dispatcher path used by
// runAdd, but bypasses runAdd's hard-coded production endpoints by
// driving Fetcher.Install directly. This pins the wiring contract:
// the package's add path uses bundles.NewFetcher, which builds a
// Fetcher whose APIBase/CodeloadBase fields can be overridden.
// Drilling further through runAdd would require either an env var
// or a function-pointer indirection to swap the URL — out of scope
// for v1; the standalone Fetcher tests already cover that surface.
func TestFetcherInstallViaCmd(t *testing.T) {
	sha := "7a3c1f4abcdef0123456789abcdef0123456789a"
	srv := fakeServer(t, sha, gzipBundle(t, "pack-7a3c1f4", map[string]string{
		"bouncer.yaml": "schema_version: 1\nname: pack\nversion: 1.0.0\napis: [apis/a.yaml]\n",
		"apis/a.yaml":  "name: gmail\nbase_url: https://x\npath_prefixes: [/g]\n",
	}))
	root := t.TempDir()
	f := bundles.NewFetcher(bundles.FetcherOpts{APIBase: srv.URL, CodeloadBase: srv.URL})
	ref, _ := bundles.ParseRef("github.com/acme/pack@v1.0.0")
	if _, err := f.Install(context.Background(), root, ref, nil); err != nil {
		t.Fatalf("install: %v", err)
	}
	rows, err := scanInstalledBundles(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rows) != 1 || rows[0].APICount != 1 {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestRunDispatchesUnknown(t *testing.T) {
	err := execute(Command(), []string{"nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("err = %v", err)
	}
}
