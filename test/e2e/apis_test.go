//go:build e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeGitHub is a tiny stand-in for the two GitHub endpoints the
// fetcher uses: the commits API (resolves a ref to a SHA) and the
// codeload tarball download. The tests run the bouncer binary as a
// subprocess and point it here via the BOUNCER_GITHUB_API_BASE /
// BOUNCER_GITHUB_CODELOAD_BASE env hooks; the real github.com is
// never contacted.
//
// The fixture knows about exactly one bundle at a time. Tests that
// need multiple SHAs (upgrade) update the fields between calls.
type fakeGitHub struct {
	// SHA the /repos/.../commits/<ref> endpoint returns. Setter is the
	// "this is the version you'd resolve to right now" knob.
	SHA atomic.Value // string

	// Tarball returned by codeload. Same shape as a real codeload
	// archive: a single top-level "<repo>-<sha>/" directory, then the
	// bundle layout below it.
	Tarball atomic.Value // []byte

	// Hits is bumped each time the codeload endpoint is hit. Lets a
	// test assert "no network roundtrip happened" for paths that
	// should short-circuit (e.g. apis fetch then add --from-tarball).
	Hits atomic.Int32
}

// newFakeGitHubServer wires up a single httptest.Server that handles
// both endpoints. The mux routes everything starting with /repos/ to
// the SHA endpoint and everything else to the tarball endpoint —
// crude, but the URL shape codeload + GitHub use makes it
// unambiguous, and the test never points anything else at this URL.
func newFakeGitHubServer(t *testing.T) (*fakeGitHub, *httptest.Server) {
	t.Helper()
	fg := &fakeGitHub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		v, _ := fg.SHA.Load().(string)
		if v == "" {
			http.Error(w, "no SHA configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(v))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fg.Hits.Add(1)
		body, _ := fg.Tarball.Load().([]byte)
		if body == nil {
			http.Error(w, "no tarball configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return fg, srv
}

// makeBundleTarball builds a gzipped tar shaped like a codeload
// archive: single top-level "<repo>-<sha>/" prefix, then
// bouncer.yaml + apis/<file> entries. Used by tests to feed the
// fakeGitHub server.
func makeBundleTarball(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name:     prefix + "/" + name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
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

// minimalBundleFiles returns the smallest set of files a bundle can
// ship and still pass manifest validation: one bouncer.yaml + one
// named API spec under apis/. Tests that don't care about the spec
// contents reuse this to keep test bodies focused on the behaviour
// under test.
func minimalBundleFiles(name, version string) map[string]string {
	return map[string]string{
		"bouncer.yaml": "schema_version: 1\nname: " + name + "\nversion: " + version + "\napis: [apis/a.yaml]\n",
		"apis/a.yaml": "name: stub-" + name + "\n" +
			"base_url: https://example.invalid\n" +
			"path_prefixes: [/" + name + "]\n",
	}
}

// fakeGHEnv builds the env overlay the apis subcommands need to
// redirect their network calls at a stub server. Returned as a
// map[string]string so tests can compose with their own overlays
// (e.g. BOUNCER_VENDORED_APIS_DIR).
func fakeGHEnv(serverURL string) map[string]string {
	return map[string]string{
		"BOUNCER_GITHUB_API_BASE":      serverURL,
		"BOUNCER_GITHUB_CODELOAD_BASE": serverURL,
		// Anonymous is fine — the stub doesn't check Authorization
		// — but the binary's GITHUB_TOKEN path would otherwise pick
		// up an inherited value from the developer's shell.
		"GITHUB_TOKEN": "",
	}
}

// TestApisHelp pins the new top-level subcommand banner. A future
// refactor that drops apis from cmd/bouncer's dispatcher would
// fail this; the help is also the operator's only discovery surface
// for the verb names.
func TestApisHelp(t *testing.T) {
	res := run(t, "apis", "--help")
	if res.Err != nil {
		t.Fatalf("apis --help: %v\nstderr: %s", res.Err, res.Stderr)
	}
	// `--help` writes to stdout so it can be piped into less / grep
	// (apiscmd.go); the no-args banner goes to stderr.
	for _, verb := range []string{"add", "list", "remove", "upgrade", "fetch", "pack", "verify"} {
		if !strings.Contains(res.Stdout, verb) {
			t.Errorf("help banner missing verb %q: stdout=%q", verb, res.Stdout)
		}
	}
}

// TestApisVerifyAcceptsValidBundle exercises the verb end-to-end
// through the live binary on a minimal valid bundle. The pack test
// next to this one already lays out a similar shape; verify just
// runs the parse + runtime-build chain.
func TestApisVerifyAcceptsValidBundle(t *testing.T) {
	src := t.TempDir()
	mustWriteFile(t, filepath.Join(src, "bouncer.yaml"),
		"schema_version: 1\nname: stub-verify\nversion: 0.1.0\napis: [apis/a.yaml]\n")
	mustWriteFile(t, filepath.Join(src, "apis", "a.yaml"),
		"name: stub-verify\nbase_url: https://example.invalid\npath_prefixes: [/stub-verify]\n")

	res := run(t, "apis", "verify", src)
	if res.Err != nil {
		t.Fatalf("apis verify: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "ok stub-verify@0.1.0") {
		t.Errorf("stdout doesn't echo bundle identity: %q", res.Stdout)
	}
}

// TestApisVerifyRejectsBrokenBundle pins the failure path on the
// live binary: a malformed CEL filter trips runtime.Build and the
// process exits non-zero.
func TestApisVerifyRejectsBrokenBundle(t *testing.T) {
	src := t.TempDir()
	mustWriteFile(t, filepath.Join(src, "bouncer.yaml"),
		"schema_version: 1\nname: stub-broken\nversion: 0.1.0\napis: [apis/a.yaml]\n")
	mustWriteFile(t, filepath.Join(src, "apis", "a.yaml"),
		"name: stub-broken\nbase_url: https://example.invalid\npath_prefixes: [/stub-broken]\n"+
			"actions:\n- name: ping\n  method: GET\n  path: /stub-broken/ping\n  filter: \"((( bad cel\"\n")

	res := run(t, "apis", "verify", src)
	if res.Err == nil {
		t.Fatalf("apis verify: expected non-zero exit, got success\nstdout: %s", res.Stdout)
	}
}

// TestApisPackRoundTripsThroughAdd drives the local-author flow:
// lay a bundle dir on disk, `apis pack` it into a tarball, then
// `apis add --from-tarball` to install. Pack and add are the two
// sides of an offline-author workflow; this pins they speak the
// same wire format.
func TestApisPackRoundTripsThroughAdd(t *testing.T) {
	src := t.TempDir()
	mustWriteFile(t, filepath.Join(src, "bouncer.yaml"),
		"schema_version: 1\nname: stub-pack\nversion: 0.1.0\napis: [apis/a.yaml]\n")
	mustWriteFile(t, filepath.Join(src, "apis", "a.yaml"),
		"name: stub-pack\nbase_url: https://example.invalid\npath_prefixes: [/stub-pack]\n")

	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	ref := "github.com/local/stub-pack@0.1.0"
	res := run(t, "apis", "pack", src, "--output", out, "--ref", ref)
	if res.Err != nil {
		t.Fatalf("apis pack: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("output tarball missing: %v", err)
	}

	// Install does NOT pass --ref — pack's source.yaml carries the
	// install record and `apis add --from-tarball` reads it.
	apisDir := t.TempDir()
	res = run(t, "apis", "add",
		"--from-tarball", out,
		"--apis-dir", apisDir,
		"--skip-allowlist")
	if res.Err != nil {
		t.Fatalf("apis add --from-tarball: %v\nstderr: %s", res.Err, res.Stderr)
	}

	// Confirm the install landed on disk under the bundle's manifest
	// name (apisDir/<name>/), not the old host/owner/repo@sha shape.
	if _, err := os.Stat(filepath.Join(apisDir, "stub-pack", "bouncer.yaml")); err != nil {
		t.Fatalf("expected installed bundle at apis/stub-pack: %v", err)
	}
}

// mustWriteFile is a small helper for the pack test — creates
// parent dirs and writes the body 0o644.
func mustWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestApisAddInstallsBundle drives the live happy path: stub GitHub,
// run `apis add <ref>`, confirm the on-disk layout. Bundles install
// at <apis-dir>/<bundle-name>/ — that's the path serve walks, so a
// regression here breaks the loader too.
func TestApisAddInstallsBundle(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const sha = "1111111111111111111111111111111111111111"
	fg.SHA.Store(sha)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+sha, minimalBundleFiles("pack", "1.0.0")))

	apisDir := t.TempDir()
	res := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--apis-dir", apisDir,
	)
	if res.Err != nil {
		t.Fatalf("apis add: %v\nstdout: %s\nstderr: %s", res.Err, res.Stdout, res.Stderr)
	}
	bundleDir := filepath.Join(apisDir, "pack")
	for _, rel := range []string{"bouncer.yaml", "source.yaml", filepath.Join("apis", "a.yaml")} {
		if _, err := os.Stat(filepath.Join(bundleDir, rel)); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}
	src := string(mustReadFile(t, filepath.Join(bundleDir, "source.yaml")))
	// yaml.v3 quotes all-digit strings to disambiguate them from
	// integers, so accept either bare or quoted form.
	if !strings.Contains(src, "resolved_sha: "+sha) && !strings.Contains(src, `resolved_sha: "`+sha+`"`) {
		t.Errorf("source.yaml missing resolved_sha:\n%s", src)
	}
}

// TestApisAddRespectsRename pins `--rename`: the operator should be
// able to dodge an upstream-name collision without forking the
// bundle. The runtime applies the rename at load time.
func TestApisAddRespectsRename(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const sha = "2222222222222222222222222222222222222222"
	fg.SHA.Store(sha)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+sha, minimalBundleFiles("pack", "1.0.0")))

	apisDir := t.TempDir()
	res := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--apis-dir", apisDir,
		"--rename", "stub-pack=acme-pack",
	)
	if res.Err != nil {
		t.Fatalf("apis add --rename: %v\nstderr: %s", res.Err, res.Stderr)
	}
	src := string(mustReadFile(t,
		filepath.Join(apisDir, "pack", "source.yaml")))
	if !strings.Contains(src, "stub-pack: acme-pack") {
		t.Errorf("source.yaml missing rename:\n%s", src)
	}
}

// TestApisListShowsInstalled exercises the operator's view of the
// apis dir: install one bundle, list, expect a row for it. The
// asserted columns (NAME / REF / SHA / FETCHED / APIS) are the
// contract scripts grep against in CI.
func TestApisListShowsInstalled(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const sha = "3333333333333333333333333333333333333333"
	fg.SHA.Store(sha)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+sha, minimalBundleFiles("pack", "1.0.0")))

	apisDir := t.TempDir()
	if r := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--apis-dir", apisDir,
	); r.Err != nil {
		t.Fatalf("seed install: %v\nstderr: %s", r.Err, r.Stderr)
	}

	res := runEnv(t, nil, "apis", "list", "--apis-dir", apisDir)
	if res.Err != nil {
		t.Fatalf("apis list: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "github.com/acme/pack@v1.0.0") {
		t.Errorf("list missing ref:\n%s", res.Stdout)
	}
	for _, header := range []string{"NAME", "REF", "SHA", "FETCHED", "APIS"} {
		if !strings.Contains(res.Stdout, header) {
			t.Errorf("list header missing %s:\n%s", header, res.Stdout)
		}
	}
}

// TestApisRemoveDeletesBundle pins the remove verb: install a bundle,
// remove it by name, confirm the on-disk dir is gone.
func TestApisRemoveDeletesBundle(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const sha = "4444444444444444444444444444444444444444"
	fg.SHA.Store(sha)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+sha, minimalBundleFiles("pack", "1.0.0")))

	apisDir := t.TempDir()
	if r := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--apis-dir", apisDir,
	); r.Err != nil {
		t.Fatalf("seed install: %v", r.Err)
	}
	bundleDir := filepath.Join(apisDir, "pack")
	if _, err := os.Stat(bundleDir); err != nil {
		t.Fatalf("seed missing: %v", err)
	}

	res := runEnv(t, nil, "apis", "remove", "pack", "--apis-dir", apisDir)
	if res.Err != nil {
		t.Fatalf("apis remove: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if _, err := os.Stat(bundleDir); err == nil {
		t.Error("bundle dir still exists after remove")
	}
}

// TestApisFetchThenFromTarball pins the air-gap loop. fetch packs to
// a tarball, then a clean install via --from-tarball completes
// without contacting the network — Hits is asserted to confirm.
func TestApisFetchThenFromTarball(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const sha = "5555555555555555555555555555555555555555"
	fg.SHA.Store(sha)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+sha, minimalBundleFiles("pack", "1.0.0")))

	tarball := filepath.Join(t.TempDir(), "pack.tgz")
	if r := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "fetch", "github.com/acme/pack@v1.0.0",
		"--output", tarball,
	); r.Err != nil {
		t.Fatalf("apis fetch: %v\nstderr: %s", r.Err, r.Stderr)
	}
	if _, err := os.Stat(tarball); err != nil {
		t.Fatalf("tarball missing: %v", err)
	}

	hitsBeforeInstall := fg.Hits.Load()
	apisDir := t.TempDir()
	res := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "--from-tarball", tarball,
		"--apis-dir", apisDir,
	)
	if res.Err != nil {
		t.Fatalf("apis add --from-tarball: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if got := fg.Hits.Load(); got != hitsBeforeInstall {
		t.Errorf("from-tarball hit codeload (%d -> %d)", hitsBeforeInstall, got)
	}
	if _, err := os.Stat(filepath.Join(apisDir, "pack", "bouncer.yaml")); err != nil {
		t.Errorf("from-tarball did not install: %v", err)
	}
}

// TestApisUpgradeDryRunReportsDiff drives the upgrade command's
// non-mutating path: install at v1, point the stub at v2, and
// confirm --dry-run prints the version delta without rewriting the
// apis dir.
func TestApisUpgradeDryRunReportsDiff(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const oldSHA = "6666666666666666666666666666666666666666"
	const newSHA = "7777777777777777777777777777777777777777"
	fg.SHA.Store(oldSHA)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+oldSHA, minimalBundleFiles("pack", "1.0.0")))

	apisDir := t.TempDir()
	if r := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--apis-dir", apisDir,
	); r.Err != nil {
		t.Fatalf("seed install: %v\nstderr: %s", r.Err, r.Stderr)
	}

	// Roll the stub forward.
	fg.SHA.Store(newSHA)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+newSHA, minimalBundleFiles("pack", "2.0.0")))

	res := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "upgrade", "pack",
		"--apis-dir", apisDir,
		"--dry-run",
	)
	if res.Err != nil {
		t.Fatalf("apis upgrade --dry-run: %v\nstderr: %s", res.Err, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "version: 1.0.0 -> 2.0.0") {
		t.Errorf("dry-run stdout missing version diff:\n%s", res.Stdout)
	}
	// Old bundle should still be on disk under the same path (in-
	// place upgrade is what live runs swap; dry-run mutates nothing).
	if _, err := os.Stat(filepath.Join(apisDir, "pack", "bouncer.yaml")); err != nil {
		t.Errorf("dry-run mutated disk: %v", err)
	}
}

// TestApisAddRejectsOutOfAllowlist pins the allowlist gate on the
// install path. Operators who configure bouncer.yaml#apis.allow-
// list can rely on `apis add` refusing to install anything else
// without the explicit --skip-allowlist override.
func TestApisAddRejectsOutOfAllowlist(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const sha = "8888888888888888888888888888888888888888"
	fg.SHA.Store(sha)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+sha, minimalBundleFiles("pack", "1.0.0")))

	dataDir := mustInit(t, initOpts{})
	allowlist := []byte("apis:\n  allowlist:\n    - github.com/jkylling/*\n")
	if err := os.WriteFile(filepath.Join(dataDir, "bouncer.yaml"), allowlist, 0o600); err != nil {
		t.Fatalf("write bouncer.yaml: %v", err)
	}
	hitsBefore := fg.Hits.Load()

	res := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--data-dir", dataDir,
	)
	if res.Err == nil {
		t.Fatalf("expected allowlist rejection, got success\nstdout: %s", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "allowlist") {
		t.Errorf("stderr missing allowlist reason: %s", res.Stderr)
	}
	if got := fg.Hits.Load(); got != hitsBefore {
		t.Errorf("allowlist gate fired *after* download (hits %d -> %d)", hitsBefore, got)
	}
	// Ditto: the apis dir must hold no bundle (subdir with a
	// bouncer.yaml). A rejection that leaves a half-installed bundle
	// is worse than a clean refusal.
	entries, err := os.ReadDir(filepath.Join(dataDir, "apis"))
	if err != nil {
		t.Fatalf("read apis: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dataDir, "apis", e.Name(), "bouncer.yaml")); err == nil {
			t.Errorf("apis dir holds bundle %q after reject", e.Name())
		}
	}
}

// TestServeLoadsBundle pins the loader half: install a bundle, boot
// serve --data-dir on the same dir, and confirm the bundled API is
// reachable as a routable upstream. We hit the bundle's path_prefix
// without a JWT and expect 401 — that proves the route reached the
// auth middleware (i.e. the API was loaded), without needing a real
// upstream.
func TestServeLoadsBundle(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const sha = "9999999999999999999999999999999999999999"
	fg.SHA.Store(sha)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+sha, minimalBundleFiles("pack", "1.0.0")))

	dataDir := mustInit(t, initOpts{})
	if r := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--data-dir", dataDir,
	); r.Err != nil {
		t.Fatalf("seed install: %v\nstderr: %s", r.Err, r.Stderr)
	}

	s := startServe(t, serveOpts{DataDir: dataDir})

	// /pack is the path_prefix the bundle declared. No JWT -> 401
	// from the auth middleware proves the route claimed the request.
	resp, _ := httpDo(t, httpClient(), http.MethodGet, s.BaseURL+"/pack/anything", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bundled route: status=%d, want 401 (route present, auth missing)", resp.StatusCode)
	}
}

// TestApisAddRefusesExisting pins idempotency: a second install of the
// same bundle should fail with a clear message. Without this guard
// an operator who re-runs `apis add` to "refresh" their tree would
// silently get a stale install on transient errors.
func TestApisAddRefusesExisting(t *testing.T) {
	fg, srv := newFakeGitHubServer(t)
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fg.SHA.Store(sha)
	fg.Tarball.Store(makeBundleTarball(t, "pack-"+sha, minimalBundleFiles("pack", "1.0.0")))

	apisDir := t.TempDir()
	if r := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--apis-dir", apisDir,
	); r.Err != nil {
		t.Fatalf("first install: %v", r.Err)
	}
	res := runEnv(t, fakeGHEnv(srv.URL),
		"apis", "add", "github.com/acme/pack@v1.0.0",
		"--apis-dir", apisDir,
	)
	if res.Err == nil {
		t.Fatal("second install: expected error")
	}
	if !strings.Contains(res.Stderr, "already exists") {
		t.Errorf("stderr = %q, want 'already exists'", res.Stderr)
	}
}

// silence unused-import lint when only used transitively.
var _ = json.Marshal
