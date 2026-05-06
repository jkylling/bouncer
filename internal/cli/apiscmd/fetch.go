package apiscmd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

const fetchLong = `Pack a GitHub-hosted bundle into a tarball without installing.

Resolves <ref> to a SHA, downloads the codeload tarball, validates
that it shapes as a bundle, then re-packs the result (plus a generated
source.yaml) into the proxy's own tarball format under --output. The
file is suitable for "bouncer apis add --from-tarball <path>" on a
disconnected host — both sides understand the same layout, so nothing
about the install needs to be re-resolved offline.`

type fetchOpts struct {
	output        string
	dataDir       string
	skipAllowlist bool
}

func (o *fetchOpts) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.output, "output", "", "output tarball path (required)")
	cmd.Flags().StringVar(&o.dataDir, "data-dir", "", "data directory; used to read bouncer.yaml#apis.allowlist")
	cmd.Flags().BoolVar(&o.skipAllowlist, "skip-allowlist", false, "bypass the bouncer.yaml#apis.allowlist check")
}

func fetchCommand() *cobra.Command {
	var o fetchOpts
	cmd := &cobra.Command{
		Use:   "fetch <ref>",
		Short: "Pack a GitHub-hosted bundle into a tarball (no install)",
		Long:  fetchLong,
		RunE:  func(_ *cobra.Command, args []string) error { return runFetch(args, &o) },
	}
	o.bind(cmd)
	return cmd
}

func runFetch(args []string, o *fetchOpts) error {
	if len(args) != 1 {
		return fmt.Errorf("expected one ref argument; got %d", len(args))
	}
	if o.output == "" {
		return errors.New("--output is required")
	}
	ref, err := bundles.ParseRef(args[0])
	if err != nil {
		return err
	}
	if ref.Version == "" {
		return fmt.Errorf("ref %s: a version is required", ref)
	}
	if !o.skipAllowlist {
		if err := enforceAllowlist(o.dataDir, ref); err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	work, err := os.MkdirTemp("", "apis-fetch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	fetcher := bundles.NewFetcher(bundles.FetcherOpts{Token: os.Getenv("GITHUB_TOKEN")})
	sha, err := fetcher.Stage(ctx, ref, work, nil)
	if err != nil {
		return err
	}
	if err := writeBundleTarball(o.output, work, ref, sha); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "wrote %s\n  ref %s\n  sha %s\n", o.output, ref, sha)
	return nil
}

// writeBundleTarball packs the prepared bundle directory into a
// gzipped tar at out, using a top-level "<repo>-<sha>/" prefix that
// matches the codeload shape — so ExtractTarGz can read both formats
// the same way.
func writeBundleTarball(out, srcDir string, ref bundles.Ref, sha string) error {
	return writeBundleTarballWithPrefix(out, srcDir, ref.Repo+"-"+sha)
}

// writeBundleTarballWithPrefix is the shared packing engine. The
// prefix is the top-level directory name inside the tarball (its
// trailing slash is added automatically). `apis fetch` derives
// this from a github ref + resolved SHA; `apis pack` derives it
// from the manifest's name + version.
//
// File modes are normalised to 0o755 / 0o644; tarballs are content-
// addressable inputs to a later install, not direct artefacts, so
// preserving local stat bits would just be a source of nondeterminism.
// ModTime is left at the zero value for the same reason.
func writeBundleTarballWithPrefix(out, srcDir, prefix string) error {
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
