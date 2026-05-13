package bundles

import (
	"os"
	"path/filepath"
	"testing"
)

// TestContentSHADeterministic pins the load-bearing property: hashing
// the same tree twice produces identical digests. Without this `apis
// pack` would write a fresh resolved_sha on every rerun.
func TestContentSHADeterministic(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.txt"), "hello")
	mustWrite(t, filepath.Join(dir, "sub", "b.txt"), "world")
	first, err := ContentSHA(dir)
	if err != nil {
		t.Fatalf("ContentSHA: %v", err)
	}
	second, err := ContentSHA(dir)
	if err != nil {
		t.Fatalf("ContentSHA: %v", err)
	}
	if first != second {
		t.Errorf("non-deterministic: %s vs %s", first, second)
	}
	if len(first) != 40 {
		t.Errorf("len=%d, want 40", len(first))
	}
}

// TestContentSHAIgnoresSourceFile pins the circularity guard: a
// source.yaml in the root must not be hashed since its content
// embeds the SHA we're computing.
func TestContentSHAIgnoresSourceFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.txt"), "x")
	before, _ := ContentSHA(dir)
	mustWrite(t, filepath.Join(dir, SourceFile), "ref: x\nresolved_sha: deadbeef\n")
	after, _ := ContentSHA(dir)
	if before != after {
		t.Errorf("source.yaml changed the SHA: %s -> %s", before, after)
	}
}

// TestWriteTarballRoundTrip pins that WriteTarball+ExtractTarGz form
// a valid loop — files written in, files extracted back out.
func TestWriteTarballRoundTrip(t *testing.T) {
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello")
	mustWrite(t, filepath.Join(src, "sub", "b.txt"), "world")
	out := filepath.Join(t.TempDir(), "bundle.tgz")
	if err := WriteTarball(out, src, "pack-1.0.0"); err != nil {
		t.Fatalf("WriteTarball: %v", err)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	dst := t.TempDir()
	if err := ExtractTarGz(f, dst); err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"a.txt", "sub/b.txt"} {
		if _, err := os.Stat(filepath.Join(dst, filepath.FromSlash(want))); err != nil {
			t.Errorf("%s missing after round-trip: %v", want, err)
		}
	}
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
