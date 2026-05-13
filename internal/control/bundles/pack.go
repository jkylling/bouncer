package bundles

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// WriteTarball packs srcDir into out (.tar.gz) under a top-level
// "<prefix>/" directory. `apis fetch` builds prefix as "<repo>-<sha>"
// so codeload's own tarball shape and ours are interchangeable; `apis
// pack` builds it as "<name>-<version>".
//
// File modes are normalised to 0o755/0o644 and mtimes left zero —
// tarballs are content-addressable install inputs, not artefacts, so
// preserving local stat bits would just inject nondeterminism.
func WriteTarball(out, srcDir, prefix string) error {
	tmp := out + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	committed := false
	defer func() {
		if !committed {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	walk := func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case rel == ".":
			return tw.WriteHeader(&tar.Header{Name: prefix + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		case info.IsDir():
			return tw.WriteHeader(&tar.Header{Name: prefix + "/" + rel + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		case !info.Mode().IsRegular():
			return fmt.Errorf("non-regular file in bundle: %s (mode %s)", rel, info.Mode())
		}
		hdr := &tar.Header{
			Name:     prefix + "/" + rel,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     info.Size(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	}
	if err := filepath.Walk(srcDir, walk); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, out); err != nil {
		return err
	}
	committed = true
	return nil
}

// ContentSHA returns a deterministic 40-hex digest over every regular
// file under root: each file contributes its relative path + NUL +
// bytes + NUL, the sorted concatenation is sha256'd and truncated to
// match git's display width. Identical trees (modulo file mode and
// mtime) hash identically across machines, so `apis pack` against an
// unchanged source tree produces an identical install record.
//
// SourceFile is excluded since its content embeds the SHA we're
// computing — including it would be circular.
func ContentSHA(root string) (string, error) {
	type entry struct {
		rel  string
		body []byte
	}
	var entries []entry
	walk := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if filepath.ToSlash(rel) == SourceFile {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{rel: filepath.ToSlash(rel), body: body})
		return nil
	}
	if err := filepath.Walk(root, walk); err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		_, _ = io.WriteString(h, e.rel)
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(e.body)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:40], nil
}
