package apiscmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

const upgradeLong = `Re-resolve a bundle ref against upstream.

If <name> is given, only that bundle is upgraded. Without arguments,
every installed bundle is upgraded.

For each bundle, the recorded source.yaml#ref is re-resolved through
GitHub. If the resolution returns the same SHA the bundle is already
installed at, nothing happens. Otherwise the new tarball is fetched
into .tmp.<rand>/, validated, written with a fresh source.yaml, and
swapped into place atomically — the old directory is renamed aside
and removed only after the new directory is in place. A killed
upgrade leaves the old bundle intact.`

type upgradeOpts struct {
	dirs   apisDirFlags
	dryRun bool
}

func (o *upgradeOpts) bind(cmd *cobra.Command) {
	o.dirs.bind(cmd, "", "")
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "do not modify disk; print what would change")
}

func upgradeCommand() *cobra.Command {
	var o upgradeOpts
	cmd := &cobra.Command{
		Use:   "upgrade [<name>]",
		Short: "Re-resolve a bundle's ref against upstream",
		Long:  upgradeLong,
		RunE:  func(_ *cobra.Command, args []string) error { return runUpgrade(args, &o) },
	}
	o.bind(cmd)
	return cmd
}

func runUpgrade(args []string, o *upgradeOpts) error {
	root, err := o.dirs.resolve()
	if err != nil {
		return err
	}
	rows, err := scanInstalledBundles(root)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no bundles installed; nothing to upgrade")
		return nil
	}
	wantName := ""
	if len(args) > 0 {
		wantName = args[0]
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fetcher := bundles.NewFetcher(bundles.FetcherOpts{Token: os.Getenv("GITHUB_TOKEN")})
	matched := false
	for _, row := range rows {
		ref, err := bundles.ParseRef(row.Ref)
		if err != nil {
			return fmt.Errorf("source ref %q in %s: %w", row.Ref, row.Path, err)
		}
		if wantName != "" && row.Name != wantName {
			continue
		}
		matched = true
		if err := upgradeOne(ctx, fetcher, root, ref, row, o.dryRun, os.Stdout); err != nil {
			return err
		}
	}
	if wantName != "" && !matched {
		return fmt.Errorf("no installed bundle named %q", wantName)
	}
	return nil
}

// upgradeOne handles one bundle. dry-run reports what would happen
// without writing; the live path swaps the directory atomically and
// preserves the previous install in .upgrade-old.<rand> until rename
// succeeds, then removes it.
func upgradeOne(ctx context.Context, f *bundles.Fetcher, root string, ref bundles.Ref, row installedBundle, dryRun bool, stdout io.Writer) error {
	if ref.Version == "" {
		return fmt.Errorf("source.yaml ref %s lacks a version; manual edit required", ref)
	}
	newSHA, err := f.ResolveSHA(ctx, ref)
	if err != nil {
		return err
	}
	if strings.EqualFold(newSHA, row.ResolvedSHA) {
		fmt.Fprintf(stdout, "%s: up to date (sha %s)\n", ref.Slug(), shortSHA(newSHA))
		return nil
	}
	fmt.Fprintf(stdout, "%s: %s -> %s\n", ref.Slug(), shortSHA(row.ResolvedSHA), shortSHA(newSHA))
	if dryRun {
		manifestDiff, err := dryRunManifestDiff(ctx, f, ref, newSHA, row.Path)
		if err != nil {
			fmt.Fprintf(stdout, "  (manifest diff unavailable: %v)\n", err)
		} else if manifestDiff != "" {
			fmt.Fprintln(stdout, "  manifest changes:")
			for _, line := range strings.Split(manifestDiff, "\n") {
				if line == "" {
					continue
				}
				fmt.Fprintf(stdout, "    %s\n", line)
			}
		}
		return nil
	}

	// Live upgrade: fetch into a sibling tmp dir, validate, then
	// rename old dir aside, rename new into place, finally rm the
	// old. Any failure short of the second rename leaves the old
	// install intact.
	body, err := f.Download(ctx, ref, newSHA)
	if err != nil {
		return err
	}
	defer body.Close()

	parent := filepath.Dir(row.Path)
	tmp, err := os.MkdirTemp(parent, ".tmp.upgrade.*")
	if err != nil {
		return err
	}
	cleanup := tmp
	defer func() {
		if cleanup != "" {
			_ = os.RemoveAll(cleanup)
		}
	}()
	if err := bundles.ExtractTarGz(body, tmp); err != nil {
		return err
	}
	if _, err := bundles.LoadManifest(filepath.Join(tmp, bundles.ManifestFile)); err != nil {
		return fmt.Errorf("upgrade %s: %w", ref, err)
	}
	// Carry the existing rename map forward — operators expect their
	// rename to survive an upgrade.
	prevSrc, err := bundles.LoadSource(filepath.Join(row.Path, bundles.SourceFile))
	if err != nil {
		return err
	}
	newSrc := *prevSrc
	newSrc.Ref = ref.String()
	newSrc.ResolvedSHA = newSHA
	newSrc.FetchedAt = nowUTCSecond()
	if err := bundles.WriteSource(filepath.Join(tmp, bundles.SourceFile), &newSrc); err != nil {
		return err
	}

	// The upgrade keeps the bundle's on-disk name (apisDir/<name>/),
	// so the swap is "rename row.Path aside; rename tmp into place;
	// remove the staged-aside copy". The new SHA rides inside
	// source.yaml — the path no longer encodes it.
	finalDir := row.Path
	stale, err := os.MkdirTemp(parent, ".upgrade-old.*")
	if err != nil {
		return err
	}
	staleDest := filepath.Join(stale, filepath.Base(row.Path))
	if err := os.Rename(row.Path, staleDest); err != nil {
		_ = os.RemoveAll(stale)
		return fmt.Errorf("rename old aside: %w", err)
	}
	if err := os.Rename(tmp, finalDir); err != nil {
		// Best-effort rollback: put the old install back.
		_ = os.Rename(staleDest, row.Path)
		_ = os.RemoveAll(stale)
		return fmt.Errorf("rename new into place: %w", err)
	}
	cleanup = "" // tmp is now finalDir; defer should not delete it.
	if err := os.RemoveAll(stale); err != nil {
		fmt.Fprintf(os.Stderr, "warn: failed to remove old install %s: %v\n", stale, err)
	}
	fmt.Fprintf(stdout, "  upgraded %s\n", finalDir)
	return nil
}

// dryRunManifestDiff fetches the upstream tarball just for its
// apis.yaml and reports a one-line summary of the manifest changes.
// Cheap because we abort the extraction as soon as we have what we
// need; expensive enough that we only run it on dry-run, not on
// every upgrade.
func dryRunManifestDiff(ctx context.Context, f *bundles.Fetcher, ref bundles.Ref, sha, oldDir string) (string, error) {
	body, err := f.Download(ctx, ref, sha)
	if err != nil {
		return "", err
	}
	defer body.Close()
	tmp, err := os.MkdirTemp("", "apis-dryrun-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	if err := bundles.ExtractTarGz(body, tmp); err != nil {
		return "", err
	}
	newM, err := bundles.LoadManifest(filepath.Join(tmp, bundles.ManifestFile))
	if err != nil {
		return "", err
	}
	oldM, err := bundles.LoadManifest(filepath.Join(oldDir, bundles.ManifestFile))
	if err != nil {
		return "", err
	}
	return summariseManifestDiff(oldM, newM), nil
}

// summariseManifestDiff turns two manifests into a short multi-line
// string. Pulled out so it can be unit-tested without touching the
// network.
func summariseManifestDiff(oldM, newM *bundles.Manifest) string {
	var lines []string
	if oldM.Version != newM.Version {
		lines = append(lines, fmt.Sprintf("version: %s -> %s", oldM.Version, newM.Version))
	}
	added, removed := diffStringSlices(oldM.APIs, newM.APIs)
	if len(added) > 0 {
		lines = append(lines, "added apis: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		lines = append(lines, "removed apis: "+strings.Join(removed, ", "))
	}
	return strings.Join(lines, "\n")
}

func diffStringSlices(oldS, newS []string) (added, removed []string) {
	o := setOf(oldS)
	n := setOf(newS)
	for v := range n {
		if !o[v] {
			added = append(added, v)
		}
	}
	for v := range o {
		if !n[v] {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func setOf(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}
