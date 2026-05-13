package apiscmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

func TestSummariseManifestDiffReportsAddRemoveAndVersion(t *testing.T) {
	old := &bundles.Manifest{Version: "1.0.0", APIs: []string{"a.yaml", "b.yaml"}}
	new_ := &bundles.Manifest{Version: "1.1.0", APIs: []string{"a.yaml", "c.yaml"}}
	got := summariseManifestDiff(old, new_)
	wants := []string{"version: 1.0.0 -> 1.1.0", "added apis: c.yaml", "removed apis: b.yaml"}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func TestSummariseManifestDiffEmptyWhenIdentical(t *testing.T) {
	m := &bundles.Manifest{Version: "1.0.0", APIs: []string{"a.yaml"}}
	if got := summariseManifestDiff(m, m); got != "" {
		t.Fatalf("want empty diff, got %q", got)
	}
}

// upgradeFakeServer responds with a configurable SHA + tarball, like
// fakeServer in apiscmd_test.go but with the SHA selectable per test.
func upgradeFakeServer(t *testing.T, sha string, body []byte) *httptest.Server {
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

// TestUpgradeOneLiveSwapsBundle drives upgradeOne against a fake
// codeload server and asserts the on-disk directory is renamed to the
// new SHA, the old directory is gone, and renames are preserved.
func TestUpgradeOneLiveSwapsBundle(t *testing.T) {
	root := t.TempDir()
	oldSHA := "0000000000000000000000000000000000000001"
	newSHA := "1111111111111111111111111111111111111111"
	oldDir := installFixture(t, root, "github.com/acme/pack", oldSHA, "1.0.0", map[string]string{"google.gmail": "acme-gmail"})

	newBundle := gzipBundle(t, "pack-1111111", map[string]string{
		"bouncer.yaml": "schema_version: 1\nname: pack\nversion: 1.1.0\napis: [apis/a.yaml]\n",
		"apis/a.yaml":  "name: google.gmail\nbase_url: https://x\npath_prefixes: [/g]\n",
	})
	srv := upgradeFakeServer(t, newSHA, newBundle)
	f := bundles.NewFetcher(bundles.FetcherOpts{APIBase: srv.URL, CodeloadBase: srv.URL})

	row := installedBundle{
		Ref:         "github.com/acme/pack@v1.0.0",
		ResolvedSHA: oldSHA,
		Path:        oldDir,
	}
	ref, _ := bundles.ParseRef(row.Ref)
	var out bytes.Buffer
	if err := upgradeOne(context.Background(), f, root, ref, row, false, &out); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	// Path stays at apis/<bundle-name>/; the swap happens in place.
	// "Old dir should be gone" no longer applies — we'd be checking
	// the same path that's now the new install. Instead verify the
	// new manifest version landed.
	if _, err := os.Stat(filepath.Join(oldDir, bundles.ManifestFile)); err != nil {
		t.Fatalf("manifest missing post-upgrade: %v", err)
	}
	mf, err := bundles.LoadManifest(filepath.Join(oldDir, bundles.ManifestFile))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if mf.Version != "1.1.0" {
		t.Errorf("manifest version = %q, want 1.1.0", mf.Version)
	}
	src, err := bundles.LoadSource(filepath.Join(oldDir, bundles.SourceFile))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	if src.ResolvedSHA != newSHA {
		t.Fatalf("source sha = %q", src.ResolvedSHA)
	}
	if src.APIRenames["google.gmail"] != "acme-gmail" {
		t.Fatalf("renames lost: %v", src.APIRenames)
	}
	if !strings.Contains(out.String(), "upgraded") {
		t.Fatalf("stdout = %q", out.String())
	}
}

// TestUpgradeOneNoOpWhenSHAUnchanged verifies the dry-run / no-op
// path: when the resolved SHA matches the installed one, nothing on
// disk is touched.
func TestUpgradeOneNoOpWhenSHAUnchanged(t *testing.T) {
	root := t.TempDir()
	sha := "0000000000000000000000000000000000000001"
	oldDir := installFixture(t, root, "github.com/acme/pack", sha, "1.0.0", nil)
	srv := upgradeFakeServer(t, sha, nil)
	f := bundles.NewFetcher(bundles.FetcherOpts{APIBase: srv.URL, CodeloadBase: srv.URL})

	row := installedBundle{
		Ref:         "github.com/acme/pack@v1.0.0",
		ResolvedSHA: sha,
		Path:        oldDir,
	}
	ref, _ := bundles.ParseRef(row.Ref)
	var out bytes.Buffer
	if err := upgradeOne(context.Background(), f, root, ref, row, false, &out); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !strings.Contains(out.String(), "up to date") {
		t.Fatalf("stdout = %q", out.String())
	}
	if _, err := os.Stat(oldDir); err != nil {
		t.Fatalf("dir should still exist: %v", err)
	}
}

func TestUpgradeOneDryRunDoesNotWrite(t *testing.T) {
	root := t.TempDir()
	oldSHA := "0000000000000000000000000000000000000001"
	newSHA := "2222222222222222222222222222222222222222"
	oldDir := installFixture(t, root, "github.com/acme/pack", oldSHA, "1.0.0", nil)

	newBundle := gzipBundle(t, "pack-2222222", map[string]string{
		"bouncer.yaml": "schema_version: 1\nname: pack\nversion: 2.0.0\napis: [apis/a.yaml, apis/b.yaml]\n",
		"apis/a.yaml":  "name: google.gmail\n",
		"apis/b.yaml":  "name: google.drive\n",
	})
	srv := upgradeFakeServer(t, newSHA, newBundle)
	f := bundles.NewFetcher(bundles.FetcherOpts{APIBase: srv.URL, CodeloadBase: srv.URL})

	row := installedBundle{
		Ref:         "github.com/acme/pack@v1.0.0",
		ResolvedSHA: oldSHA,
		Path:        oldDir,
	}
	ref, _ := bundles.ParseRef(row.Ref)
	var out bytes.Buffer
	if err := upgradeOne(context.Background(), f, root, ref, row, true, &out); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if _, err := os.Stat(oldDir); err != nil {
		t.Fatalf("old dir gone after dry-run: %v", err)
	}
	if !strings.Contains(out.String(), "version: 1.0.0 -> 2.0.0") {
		t.Fatalf("stdout = %q", out.String())
	}
	if !strings.Contains(out.String(), "added apis: apis/b.yaml") {
		t.Fatalf("stdout = %q", out.String())
	}
}
