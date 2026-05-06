package models

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIYAMLLoads(t *testing.T) {
	apis, err := FromYAMLDir[API](filepath.Join("..", "..", "..", "testdata", "apis"))
	if err != nil {
		t.Fatalf("load apis: %v", err)
	}
	if len(apis) == 0 {
		t.Fatal("no apis loaded")
	}
	want := map[string]bool{"gmail": false, "drive": false, "calendar": false, "sheets": false, "docs": false}
	for _, a := range apis {
		if _, ok := want[a.Name]; ok {
			want[a.Name] = true
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("api %q missing", k)
		}
	}
}

func TestPolicyYAMLLoads(t *testing.T) {
	// Test fixture lives under testdata/policies; the bundled config/
	// ships API specs only.
	policies, err := FromYAMLDir[Policy](filepath.Join("..", "..", "..", "testdata", "policies"))
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("no policies loaded")
	}
}

// TestFromYAMLDirAcceptsBothExtensions pins a config split
// across `.yaml` and `.yml` files in the same directory must load both;
// previously `.yml` was silently skipped.
func TestFromYAMLDirAcceptsBothExtensions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("name: a\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte("name: b\n"), 0o600); err != nil {
		t.Fatalf("write yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.txt"), []byte("name: c\n"), 0o600); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	type doc struct {
		Name string `yaml:"name"`
	}
	got, err := FromYAMLDir[doc](dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	names := map[string]bool{}
	for _, d := range got {
		names[d.Name] = true
	}
	if !names["a"] || !names["b"] {
		t.Errorf("loaded names = %v, want a and b", names)
	}
	if names["c"] {
		t.Errorf("loaded names = %v, must not include c (.txt)", names)
	}
}

// TestFromYAMLDirRejectsUnknownFields pins a typo in a
// schema field name (the reviewer's example was `conditon:` for
// `condition:`) used to silently decode as the zero value and surface
// later as "policy never fires." With KnownFields(true) it fails at
// load with the offending field in the error message.
func TestFromYAMLDirRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("name: p\nconditon: 'true'\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := FromYAMLDir[Policy](dir)
	if err == nil {
		t.Fatal("expected load error for misspelled field")
	}
	if !strings.Contains(err.Error(), "conditon") {
		t.Fatalf("error = %v, want one mentioning conditon", err)
	}
}

// TestPolicyResultRejectsTypoAtLoadTime pins a misspelled
// `result:` value (`dney` instead of `deny`) fails at YAML decode
// rather than at the runtime policy boundary, with line context the
// operator can act on.
func TestPolicyResultRejectsTypoAtLoadTime(t *testing.T) {
	dir := t.TempDir()
	yaml := []byte("api: svc\nname: p\naction: 'true'\ncondition: 'true'\nresult: dney\n")
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), yaml, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := FromYAMLDir[Policy](dir)
	if err == nil {
		t.Fatal("expected load error for misspelled result")
	}
	if !strings.Contains(err.Error(), "dney") {
		t.Fatalf("error = %v, want one mentioning the typo'd value", err)
	}
}

// TestPolicyPrincipalRoundTrip pins that the new `principal:` field
// loads through the YAML loader unchanged, and that omitting it stays
// valid (the field is optional with a default-true compile-time
// behaviour layered on top).
func TestPolicyPrincipalRoundTrip(t *testing.T) {
	dir := t.TempDir()
	yaml := []byte("api: svc\nname: p\nprincipal: 'principal.subject == \"agent-1\"'\naction: 'true'\ncondition: 'true'\nresult: permit\n")
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), yaml, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := FromYAMLDir[Policy](dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("loaded %d policies, want 1", len(got))
	}
	if got[0].Principal != `principal.subject == "agent-1"` {
		t.Fatalf("principal = %q, want the YAML source", got[0].Principal)
	}
}

func TestPolicyPrincipalDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	yaml := []byte("api: svc\nname: p\naction: 'true'\ncondition: 'true'\nresult: permit\n")
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), yaml, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := FromYAMLDir[Policy](dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got[0].Principal != "" {
		t.Fatalf("principal = %q, want empty default", got[0].Principal)
	}
}

func TestActionAllBinds(t *testing.T) {
	a := Action{
		Bind:  "x{a: 1}",
		Binds: []string{"y{a: 2}", "z{a: 3}"},
	}
	got := a.AllBinds()
	if len(got) != 3 || got[0] != "x{a: 1}" || got[1] != "y{a: 2}" || got[2] != "z{a: 3}" {
		t.Fatalf("unexpected order: %v", got)
	}
}
