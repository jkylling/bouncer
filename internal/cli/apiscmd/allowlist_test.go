package apiscmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

func TestMatchAllowlistEmptyAllowsEverything(t *testing.T) {
	ref, _ := bundles.ParseRef("github.com/anyone/anything@v1")
	if !matchAllowlist(nil, ref) {
		t.Fatal("empty allowlist should match")
	}
}

func TestMatchAllowlistExactSlug(t *testing.T) {
	ref, _ := bundles.ParseRef("github.com/acme/pack@v1")
	if !matchAllowlist([]string{"github.com/acme/pack"}, ref) {
		t.Fatal("exact slug should match")
	}
	if matchAllowlist([]string{"github.com/acme/other"}, ref) {
		t.Fatal("different slug should not match")
	}
}

func TestMatchAllowlistOwnerWildcard(t *testing.T) {
	ref, _ := bundles.ParseRef("github.com/acme/pack@v1")
	if !matchAllowlist([]string{"github.com/acme/*"}, ref) {
		t.Fatal("owner wildcard should match")
	}
	other, _ := bundles.ParseRef("github.com/foo/pack@v1")
	if matchAllowlist([]string{"github.com/acme/*"}, other) {
		t.Fatal("owner wildcard should not match different owner")
	}
}

func TestLoadAllowlistMissingFileIsNoConstraint(t *testing.T) {
	got, err := loadAllowlist(t.TempDir())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

func TestLoadAllowlistReadsAuthProxyYAML(t *testing.T) {
	dir := t.TempDir()
	cfg := `apis:
  allowlist:
    - github.com/acme/*
    - github.com/jkylling/bouncer
`
	if err := os.WriteFile(filepath.Join(dir, allowlistFile), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadAllowlist(dir)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestEnforceAllowlistRejectsUnlisted(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, allowlistFile), []byte("apis:\n  allowlist: [github.com/acme/*]\n"), 0o600)
	ref, _ := bundles.ParseRef("github.com/foo/pack@v1")
	err := enforceAllowlist(dir, ref, false)
	if err == nil || !strings.Contains(err.Error(), "not in the apis.allowlist") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnforceAllowlistEmptyDataDirIsNoConstraint(t *testing.T) {
	ref, _ := bundles.ParseRef("github.com/foo/pack@v1")
	if err := enforceAllowlist("", ref, false); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestEnforceAllowlistSkipShortCircuits(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, allowlistFile), []byte("apis:\n  allowlist: [github.com/acme/*]\n"), 0o600)
	ref, _ := bundles.ParseRef("github.com/foo/pack@v1")
	if err := enforceAllowlist(dir, ref, true); err != nil {
		t.Fatalf("skip=true should bypass: %v", err)
	}
}
