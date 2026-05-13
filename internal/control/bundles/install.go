package bundles

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultBranch is what bare refs (no @version) track. `apis upgrade`
// later re-resolves from the same starting point.
const DefaultBranch = "main"

// InstallRefs installs each ref into root, skipping any already
// vendored by slug. Idempotent so boot-time `--with-apis` is safe to
// re-run on every restart. w receives per-ref progress; pass
// io.Discard to silence.
func InstallRefs(ctx context.Context, root string, refs []string, w io.Writer) error {
	if len(refs) == 0 {
		return nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("apis dir: %w", err)
	}
	fetcher := NewFetcher(FetcherOpts{Token: os.Getenv("GITHUB_TOKEN")})
	for _, raw := range refs {
		ref, err := ParseRef(raw)
		if err != nil {
			return fmt.Errorf("--with-apis %q: %w", raw, err)
		}
		if ref.Version == "" {
			ref.Version = DefaultBranch
		}
		installed, err := refAlreadyInstalled(root, ref)
		if err != nil {
			return fmt.Errorf("--with-apis %q: %w", raw, err)
		}
		if installed {
			fmt.Fprintf(w, "with-apis: %s already installed, skipping\n", ref)
			continue
		}
		dest, err := fetcher.Install(ctx, root, ref, nil)
		if err != nil {
			return fmt.Errorf("--with-apis %s: %w", raw, err)
		}
		fmt.Fprintf(w, "with-apis: installed %s at %s\n", ref, dest)
	}
	return nil
}

// refAlreadyInstalled matches by slug, not SHA — a different SHA is
// an `apis upgrade` operation, not a re-install.
func refAlreadyInstalled(root string, ref Ref) (bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		src, err := LoadSource(filepath.Join(root, e.Name(), SourceFile))
		if err != nil {
			continue
		}
		installedRef, err := ParseRef(src.Ref)
		if err != nil {
			continue
		}
		if installedRef.Slug() == ref.Slug() {
			return true, nil
		}
	}
	return false, nil
}
