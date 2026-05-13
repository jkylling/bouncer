package apiscmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

const listLong = `List installed bundles.

Walks <apis-dir> for immediate subdirectories carrying a bouncer.yaml
and prints one row per bundle, sorted by name. Columns: name, ref,
manifest version, resolved SHA (short form), install time, count of
APIs, count of renames.`

func listCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed bundles",
		Long:  listLong,
		RunE:  runWithOpts(func(_ []string, dirs *apisDirFlags) error { return runList(dirs) }),
	}
	(&apisDirFlags{}).bind(cmd.Flags(), "where to look (defaults to $BOUNCER_APIS_DIR or <data-dir>/apis)")
	return cmd
}

func runList(dirs *apisDirFlags) error {
	root, err := dirs.resolve()
	if err != nil {
		return err
	}
	rows, err := scanInstalledBundles(root)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintf(os.Stderr, "no bundles installed under %s\n", root)
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tREF\tVERSION\tSHA\tFETCHED\tAPIS\tRENAMES")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			r.Name, r.Ref, r.ManifestVersion, shortSHA(r.ResolvedSHA), formatFetched(r.FetchedAt), r.APICount, r.RenameCount)
	}
	return tw.Flush()
}

// installedBundle is the shape `apis list` prints. Pulled out so the
// scanner can be tested without touching stdout.
type installedBundle struct {
	Name            string
	Ref             string
	ManifestVersion string
	ResolvedSHA     string
	FetchedAt       time.Time
	APICount        int
	RenameCount     int
	Path            string
}

// scanInstalledBundles walks the apis dir's immediate subdirectories
// and returns one installedBundle per directory that has a valid
// manifest + source.yaml. Subdirs without a manifest are silently
// skipped (they're not bundles); subdirs with a manifest but a
// malformed source.yaml are surfaced as path-prefixed errors so a
// half-broken bundle isn't hidden from the operator.
func scanInstalledBundles(root string) ([]installedBundle, error) {
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var bundleDirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(dir, bundles.ManifestFile)); err != nil {
			continue
		}
		bundleDirs = append(bundleDirs, dir)
	}
	sort.Strings(bundleDirs)
	out := make([]installedBundle, 0, len(bundleDirs))
	for _, dir := range bundleDirs {
		manifest, err := bundles.LoadManifest(filepath.Join(dir, bundles.ManifestFile))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", dir, err)
		}
		source, err := bundles.LoadSource(filepath.Join(dir, bundles.SourceFile))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", dir, err)
		}
		out = append(out, installedBundle{
			Name:            manifest.Name,
			Ref:             source.Ref,
			ManifestVersion: manifest.Version,
			ResolvedSHA:     source.ResolvedSHA,
			FetchedAt:       source.FetchedAt,
			APICount:        len(manifest.APIs),
			RenameCount:     len(source.APIRenames),
			Path:            dir,
		})
	}
	return out, nil
}

func shortSHA(s string) string {
	n := 7
	if len(s) < n {
		n = len(s)
	}
	return strings.ToLower(s[:n])
}

func formatFetched(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02")
}
