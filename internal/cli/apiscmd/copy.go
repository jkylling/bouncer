package apiscmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// copyTree mirrors srcDir into dstDir, preserving file permissions.
// Used by from-tarball / from-dir to materialise extracted or
// in-place bundle content into the final vendored layout. We could
// rename the temp dir directly, but the temp dir lives under the
// system temp root (different filesystem on some hosts), where rename
// can fail with EXDEV — copying is the portable choice.
//
// `.git/` is skipped: a `--from-dir` install may point at a working
// tree, and we want bundle content, not repo metadata. Tarballs from
// `apis fetch` never contain `.git/`, so this is a no-op for them.
//
// Symlinks are refused outright. filepath.Walk uses Lstat, so info
// reflects the symlink itself; without an explicit guard the
// subsequent os.Open would follow the link and copy whatever its
// target points at. A bundle containing `evil -> /etc/passwd` would
// otherwise exfiltrate host files into the vendored install on
// `apis add --from-tarball`.
func copyTree(srcDir, dstDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle contains symlink %s: symlinks are not permitted", rel)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("bundle contains non-regular file %s (mode %s): only directories and regular files are permitted", rel, info.Mode())
		}
		dst := filepath.Join(dstDir, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, info.Mode().Perm())
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
