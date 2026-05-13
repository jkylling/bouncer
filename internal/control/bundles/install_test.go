package bundles

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallRefsEmptyIsNoOp pins the cheapest path: passing no refs
// must not even touch the filesystem (root may not exist yet).
func TestInstallRefsEmptyIsNoOp(t *testing.T) {
	if err := InstallRefs(context.Background(), "/does/not/exist", nil, &bytes.Buffer{}); err != nil {
		t.Fatalf("InstallRefs nil: %v", err)
	}
}

// TestInstallRefsSkipsAlreadyVendored pins the load-bearing
// idempotency guarantee: a bundle already on disk under the same
// ref slug is skipped, not re-installed. This is what makes
// `serve --with-apis foo` safe to re-run on every restart.
func TestInstallRefsSkipsAlreadyVendored(t *testing.T) {
	root := t.TempDir()
	bundleDir := filepath.Join(root, "preexisting")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A bundle is recognised by its source.yaml#ref — the dir name
	// doesn't matter, only the recorded ref slug.
	src := "ref: github.com/acme/widgets@v1.0.0\nresolved_sha: " +
		strings.Repeat("a", 40) + "\n"
	if err := os.WriteFile(filepath.Join(bundleDir, SourceFile), []byte(src), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	var buf bytes.Buffer
	if err := InstallRefs(context.Background(), root, []string{"github.com/acme/widgets@v2.0.0"}, &buf); err != nil {
		t.Fatalf("InstallRefs: %v", err)
	}
	if !strings.Contains(buf.String(), "already installed, skipping") {
		t.Errorf("expected skip log; got: %q", buf.String())
	}
}
