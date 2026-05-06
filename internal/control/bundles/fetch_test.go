package bundles

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
)

// fakeBundle returns a gzipped tarball with codeload's
// `<repo>-<sha>/` top-level prefix.
func fakeBundle(t *testing.T, prefix string, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name:     prefix + "/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}); err != nil {
		t.Fatalf("write dir hdr: %v", err)
	}
	for name, body := range entries {
		full := prefix + "/" + name
		if err := tw.WriteHeader(&tar.Header{
			Name:     full,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(body)),
		}); err != nil {
			t.Fatalf("write file hdr %s: %v", full, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gz: %v", err)
	}
	return buf.Bytes()
}

// Pins the codeload-private-repo case: a `pax_global_header` entry
// before the real root must not become the captured prefix.
func TestExtractTarGzSkipsPaxGlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "pax_global_header",
		Typeflag: tar.TypeXGlobalHeader,
		Size:     0,
	}); err != nil {
		t.Fatalf("write pax: %v", err)
	}
	prefix := "repo-7a3c1f4"
	if err := tw.WriteHeader(&tar.Header{
		Name:     prefix + "/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}); err != nil {
		t.Fatalf("write dir: %v", err)
	}
	body := "schema_version: 1\nname: x\nversion: 1.0.0\napis: [apis/a.yaml]\n"
	if err := tw.WriteHeader(&tar.Header{
		Name:     prefix + "/" + ManifestFile,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(body)),
	}); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gz: %v", err)
	}

	dir := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dir); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ManifestFile)); err != nil {
		t.Fatalf("manifest not at staged-dir root: %v", err)
	}
}

func TestExtractTarGzStripsTopPrefix(t *testing.T) {
	body := fakeBundle(t, "repo-7a3c1f4", map[string]string{
		"bouncer.yaml":        "schema_version: 1\nname: x\nversion: 1.0.0\napis: [apis/a.yaml]\n",
		"apis/a.yaml":         "name: gmail\n",
		"policies/sample.yml": "name: foo\n",
	})
	dir := t.TempDir()
	if err := ExtractTarGz(bytes.NewReader(body), dir); err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{ManifestFile, "apis/a.yaml", "policies/sample.yml"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Fatalf("expected %s extracted: %v", want, err)
		}
	}
}

func TestExtractTarGzRejectsAbsoluteEntry(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "repo-x/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "repo-x/../../etc/evil", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4})
	_, _ = tw.Write([]byte("evil"))
	_ = tw.Close()
	_ = gz.Close()
	if err := ExtractTarGz(&buf, t.TempDir()); err == nil {
		t.Fatal("expected error for path-escaping entry")
	}
}

// installFakeServer serves both the api (commits) and codeload
// (tar.gz) endpoints from one httptest server.
func installFakeServer(t *testing.T, sha string, bundle []byte) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(sha))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/tar.gz/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(bundle)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.URL
}

func TestFetcherInstallEndToEnd(t *testing.T) {
	sha := "7a3c1f4abcdef0123456789abcdef0123456789a"
	bundle := fakeBundle(t, "api-pack-7a3c1f4", map[string]string{
		"bouncer.yaml": "schema_version: 1\nname: api-pack\nversion: 1.0.0\napis: [apis/a.yaml]\n",
		"apis/a.yaml":  "name: gmail\n",
	})
	_, base := installFakeServer(t, sha, bundle)
	apisDir := t.TempDir()
	f := NewFetcher(FetcherOpts{APIBase: base, CodeloadBase: base})
	ref, err := ParseRef("github.com/acme/api-pack@v1.0.0")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	got, err := f.Install(context.Background(), apisDir, ref, map[string]string{"gmail": "acme-gmail"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	// Bundle name from manifest drives the install path.
	wantSuffix := "api-pack"
	if !strings.HasSuffix(got, filepath.FromSlash(wantSuffix)) {
		t.Fatalf("got dir %q, want suffix %q", got, wantSuffix)
	}
	if _, err := os.Stat(filepath.Join(got, ManifestFile)); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	src, err := LoadSource(filepath.Join(got, SourceFile))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	if src.Ref != ref.String() || src.ResolvedSHA != sha {
		t.Fatalf("source = %+v", src)
	}
	if src.APIRenames["gmail"] != "acme-gmail" {
		t.Fatalf("renames = %v", src.APIRenames)
	}
}

func TestFetcherInstallRefusesExisting(t *testing.T) {
	sha := "7a3c1f4abcdef0123456789abcdef0123456789a"
	bundle := fakeBundle(t, "api-pack-7a3c1f4", map[string]string{
		"bouncer.yaml": "schema_version: 1\nname: api-pack\nversion: 1.0.0\napis: [apis/a.yaml]\n",
		"apis/a.yaml":  "name: gmail\n",
	})
	_, base := installFakeServer(t, sha, bundle)
	vendored := t.TempDir()
	f := NewFetcher(FetcherOpts{APIBase: base, CodeloadBase: base})
	ref, _ := ParseRef("github.com/acme/api-pack@v1.0.0")

	if _, err := f.Install(context.Background(), vendored, ref, nil); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if _, err := f.Install(context.Background(), vendored, ref, nil); err == nil {
		t.Fatal("second install: want error, got nil")
	}
}

func TestFetcherResolveSHAReturnsAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	f := NewFetcher(FetcherOpts{APIBase: srv.URL})
	_, err := f.ResolveSHA(context.Background(), Ref{Host: "github.com", Owner: "a", Repo: "b", Version: "v9"})
	if err == nil || !strings.Contains(err.Error(), "Not Found") {
		t.Fatalf("err = %v, want Not Found", err)
	}
}

func TestFetcherSendsTokenWhenSet(t *testing.T) {
	gotAuth := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("7a3c1f4abcdef0123456789abcdef0123456789a"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	f := NewFetcher(FetcherOpts{APIBase: srv.URL, Token: "secret-token"})
	if _, err := f.ResolveSHA(context.Background(), Ref{Host: "github.com", Owner: "a", Repo: "b", Version: "main"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("auth header = %q", gotAuth)
	}
}

func TestFetcherResolveSHAShortCircuitsFullSHA(t *testing.T) {
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { hits++ })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	f := NewFetcher(FetcherOpts{APIBase: srv.URL})
	sha := "7a3c1f4abcdef0123456789abcdef0123456789a"
	got, err := f.ResolveSHA(context.Background(), Ref{Host: "github.com", Owner: "a", Repo: "b", Version: sha})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != sha {
		t.Fatalf("got = %q, want %q", got, sha)
	}
	if hits != 0 {
		t.Fatal("expected no HTTP roundtrip for full SHA")
	}
}
