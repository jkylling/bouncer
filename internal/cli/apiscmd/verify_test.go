package apiscmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// validBundle is a minimal one-API bundle that should pass every
// stage of `apis verify` — manifest, file presence, YAML parse,
// runtime build.
const validAPIBody = `name: stub
base_url: https://example.invalid
path_prefixes: [/stub]
actions:
- name: ping
  method: GET
  path: /stub/ping
`

// writeBundle lays out a bundle under t.TempDir() and returns the
// root. apis is a relpath → body map for files written under
// `apis/`; passing nil writes the default validAPIBody.
func writeBundle(t *testing.T, name, version string, apis map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if apis == nil {
		apis = map[string]string{"stub.yaml": validAPIBody}
	}
	listed := make([]string, 0, len(apis))
	for rel := range apis {
		listed = append(listed, rel)
	}
	manifest := "schema_version: 1\nname: " + name + "\nversion: " + version + "\napis:\n"
	for _, rel := range listed {
		manifest += "  - apis/" + rel + "\n"
	}
	mustWrite(t, filepath.Join(root, bundles.ManifestFile), manifest)
	for rel, body := range apis {
		mustWrite(t, filepath.Join(root, bundles.APIsSubdir, rel), body)
	}
	return root
}

// TestVerifyBundleHappyPath drives the bundle-mode chain end to end
// with a single valid API. A clean run is the loud success state;
// any error from runtime.Build would surface here.
func TestVerifyBundleHappyPath(t *testing.T) {
	root := writeBundle(t, "stub-bundle", "0.1.0", nil)
	if err := runVerify([]string{root}); err != nil {
		t.Fatalf("runVerify: %v", err)
	}
}

// TestVerifyBundleRejectsCELError pins the runtime-compile gate: a
// syntactically valid YAML with a malformed CEL action body must
// fail verify, not silently load.
func TestVerifyBundleRejectsCELError(t *testing.T) {
	bad := `name: stub
base_url: https://example.invalid
path_prefixes: [/stub]
actions:
- name: ping
  method: GET
  path: /stub/ping
  filter: "this is not valid CEL ((( "
`
	root := writeBundle(t, "stub", "0.1.0", map[string]string{"stub.yaml": bad})
	err := runVerify([]string{root})
	if err == nil {
		t.Fatal("runVerify: expected error on malformed CEL, got nil")
	}
}

// TestVerifyBundleRejectsUnknownYAMLField pins KnownFields(true):
// a typo'd field name (`conditon:` rather than `condition:` — though
// for actions a fake field still trips the same code path) fails at
// parse rather than silently dropping.
func TestVerifyBundleRejectsUnknownYAMLField(t *testing.T) {
	bad := `name: stub
base_url: https://example.invalid
path_prefixes: [/stub]
actions:
- name: ping
  metohd: GET
  path: /stub/ping
`
	root := writeBundle(t, "stub", "0.1.0", map[string]string{"stub.yaml": bad})
	err := runVerify([]string{root})
	if err == nil || !strings.Contains(err.Error(), "metohd") {
		t.Fatalf("err = %v, want one mentioning the typo'd field", err)
	}
}

// TestVerifyBundleRejectsMissingListedAPI pins the manifest-vs-disk
// check: the listing contract (every entry must resolve) is the
// same one `apis pack` enforces.
func TestVerifyBundleRejectsMissingListedAPI(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, bundles.ManifestFile),
		"schema_version: 1\nname: stub\nversion: 0.1\napis: [apis/missing.yaml]\n")
	err := runVerify([]string{root})
	if err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Fatalf("err = %v, want one naming the missing file", err)
	}
}

// TestVerifyApisDirHappyPath pins the bare-dir mode (operator's
// --apis-dir): no manifest, just every *.yaml in the dir loaded
// and built.
func TestVerifyApisDirHappyPath(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "stub.yaml"), validAPIBody)
	if err := runVerify([]string{dir}); err != nil {
		t.Fatalf("runVerify: %v", err)
	}
}

// TestVerifyApisDirRejectsEmptyDir pins the "no APIs found" case so
// an operator typo'ing the path doesn't get a silent success.
func TestVerifyApisDirRejectsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := runVerify([]string{dir})
	if err == nil || !strings.Contains(err.Error(), "no api YAML files") {
		t.Fatalf("err = %v, want one mentioning empty dir", err)
	}
}

// TestVerifyAutoDetectsMode pins the dispatch: presence of apis.yaml
// at the root selects bundle mode; absence selects bare-dir mode.
// The same dir loaded one way succeeds; loaded the other way
// fails — a cheap proxy for "the right code path ran".
func TestVerifyAutoDetectsMode(t *testing.T) {
	// Bundle root: valid bundle, NO file directly at root, so the
	// bare-dir loader would find nothing.
	root := writeBundle(t, "stub", "0.1.0", nil)
	if err := runVerify([]string{root}); err != nil {
		t.Fatalf("bundle mode: %v", err)
	}
	// And the apis/ subdir on its own is valid as a bare-dir input.
	if err := runVerify([]string{filepath.Join(root, bundles.APIsSubdir)}); err != nil {
		t.Fatalf("bare-dir mode on apis/: %v", err)
	}
}

// TestVerifyRequiresPositional pins flag-validation on the verb.
func TestVerifyRequiresPositional(t *testing.T) {
	err := runVerify(nil)
	if err == nil || !strings.Contains(err.Error(), "one directory argument") {
		t.Fatalf("err = %v, want one mentioning the positional", err)
	}
}

// TestVerifyRejectsNonDir pins fast-failure on a path that exists
// but isn't a directory. Friendlier than an opaque error halfway
// through manifest load.
func TestVerifyRejectsNonDir(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "not-a-dir-*.yaml")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	_ = f.Close()
	got := runVerify([]string{f.Name()})
	if got == nil || !strings.Contains(got.Error(), "not a directory") {
		t.Fatalf("err = %v, want one mentioning not-a-directory", got)
	}
}
