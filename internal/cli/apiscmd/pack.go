package apiscmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

const packLong = `Pack a local bundle directory into a tarball.

Validates that <dir> shapes as a bundle (apis.yaml manifest plus
every listed API YAML), then packs it into the proxy's tarball
format under --output. The local-author equivalent of "apis fetch":
no network round-trip, no ref resolution.

The tarball includes a source.yaml stamped with --ref and a
deterministic content-derived SHA (sha256 of every packed file's
relative path + bytes, truncated to 40 hex chars). Consumers
install with "bouncer apis add --from-tarball <path>" — the
embedded source.yaml carries the install record, so --ref isn't
required at install time.

Expected layout under <dir>:

  bouncer.yaml          manifest (schema_version, name, version,
                        description, apis: [...])
  apis/<name>.yaml      API specs (the manifest's apis: list may
                        point at individual files or at the apis/
                        directory itself for auto-glob)
  README.md             optional; served as the bundle's docs
                        surface at /_api/apis/<name>/readme`

type packOpts struct {
	output string
	refStr string
}

func (o *packOpts) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.output, "output", "", "output tarball path (required)")
	cmd.Flags().StringVar(&o.refStr, "ref", "", "ref to record in source.yaml (required, e.g. github.com/me/bouncer-svc@v0.1.0)")
}

func packCommand() *cobra.Command {
	var o packOpts
	cmd := &cobra.Command{
		Use:   "pack <dir>",
		Short: "Pack a local bundle directory into a tarball",
		Long:  packLong,
		RunE:  func(_ *cobra.Command, args []string) error { return runPackImpl(args, &o) },
	}
	o.bind(cmd)
	return cmd
}

// runPack is the test entry point: builds the cobra command and
// executes it with argv.
func runPack(args []string) error { return execute(packCommand(), args) }

func runPackImpl(args []string, o *packOpts) error {
	if len(args) != 1 {
		return fmt.Errorf("expected one directory argument; got %d", len(args))
	}
	if o.output == "" {
		return errors.New("--output is required")
	}
	if o.refStr == "" {
		return errors.New("--ref is required (the install record needs a ref)")
	}
	ref, err := bundles.ParseRef(o.refStr)
	if err != nil {
		return fmt.Errorf("ref: %w", err)
	}
	srcDir := filepath.Clean(args[0])
	info, err := os.Stat(srcDir)
	if err != nil {
		return fmt.Errorf("source dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source dir %s: not a directory", srcDir)
	}
	manifestPath := filepath.Join(srcDir, bundles.ManifestFile)
	mf, err := bundles.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	// Sanity-check every manifest entry resolves on disk through the
	// same path-resolver the boot loader uses. Validate already
	// rejected path-escape / absolute paths; this catches the typo
	// where the author named a file/dir that doesn't exist.
	for _, rel := range mf.APIs {
		if _, err := bundles.ResolveManifestEntry(srcDir, rel); err != nil {
			return fmt.Errorf("manifest entry %q: %w", rel, err)
		}
	}
	// Stage into a workdir so we can drop the generated source.yaml
	// alongside the source files before packing. We don't want the
	// stamped file to land in the user's working tree.
	stage, err := os.MkdirTemp("", "apis-pack-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := copyTree(srcDir, stage); err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	sha, err := contentSHA(stage)
	if err != nil {
		return fmt.Errorf("content sha: %w", err)
	}
	src := &bundles.SourceRecord{
		Ref:         ref.String(),
		ResolvedSHA: sha,
		FetchedAt:   nowUTCSecond(),
	}
	if err := bundles.WriteSource(filepath.Join(stage, bundles.SourceFile), src); err != nil {
		return fmt.Errorf("write source.yaml: %w", err)
	}
	prefix := mf.Name + "-" + mf.Version
	if err := writeBundleTarballWithPrefix(o.output, stage, prefix); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "wrote %s\n  bundle %s@%s\n  ref %s\n  sha %s\n",
		o.output, mf.Name, mf.Version, ref, sha)
	return nil
}

// contentSHA produces a deterministic 40-hex digest over every
// regular file under root. Each file contributes its relative path
// + a NUL + its bytes + a NUL; the sorted concatenation is hashed
// with sha256 and truncated to match git's display width. Identical
// trees (modulo file mode + mtime) hash identically across machines,
// so a `pack` rerun against the same source tree produces an
// identical install record.
func contentSHA(root string) (string, error) {
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
		// Skip the source.yaml we're about to write — its content
		// embeds the SHA we're computing, which would be circular.
		if filepath.ToSlash(rel) == bundles.SourceFile {
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
