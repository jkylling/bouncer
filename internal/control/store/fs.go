package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// fsBackend is the concrete FSBackend rooted at a single directory
// on disk. Each domain's Subdir(namespace) sits as `<root>/<namespace>`,
// created on first request.
type fsBackend struct {
	root string
}

// OpenFS returns an FSBackend rooted at dir. The directory must
// exist; we don't auto-create it because a typo'd flag value
// silently writing to a fresh directory is exactly the failure mode
// most likely to confuse an operator. Use a separate `--init`
// command on top if you want auto-create semantics.
func OpenFS(dir string) (FSBackend, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("store/fs: root %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("store/fs: root %q is not a directory", dir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("store/fs: abs %q: %w", dir, err)
	}
	return &fsBackend{root: abs}, nil
}

// Subdir resolves <root>/<namespace>, creating the directory if it
// is missing. Idempotent: a second call after a successful create
// returns the same path. The namespace must be a single path
// component (no separators, no `..`, not absolute) — domains
// shouldn't be picking nested layouts inside someone else's root,
// and rejecting traversal here means a typo'd namespace can't
// write outside the root.
func (b *fsBackend) Subdir(namespace string) (string, error) {
	if !validNamespace(namespace) {
		return "", fmt.Errorf("store/fs: invalid namespace %q", namespace)
	}
	path := filepath.Join(b.root, namespace)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", fmt.Errorf("store/fs: mkdir %q: %w", path, err)
	}
	return path, nil
}

// validNamespace enforces the single-component rule. The check is
// intentionally strict: a namespace is just a label, not a path.
func validNamespace(ns string) bool {
	if ns == "" || ns == "." || ns == ".." {
		return false
	}
	if strings.ContainsAny(ns, `/\`) {
		return false
	}
	if filepath.IsAbs(ns) {
		return false
	}
	return true
}

// Close is a no-op — fsBackend holds no file descriptors.
func (b *fsBackend) Close() error { return nil }
