package apiscmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// runAddFromDir installs a bundle from a local working tree (no
// GitHub round-trip). The ref's version is recorded in source.yaml's
// resolved_sha field for upgrade-time bookkeeping; the install path
// is just <apisDir>/<bundle-name>/.
func runAddFromDir(o *addOpts, apisDir string, renames map[string]string) error {
	if o.RefOverride == "" {
		return errors.New("--from-dir requires --ref <ref> (e.g. --ref github.com/jkylling/bouncer-gws@dev)")
	}
	srcDir := filepath.Clean(o.FromDir)
	info, err := os.Stat(srcDir)
	if err != nil {
		return fmt.Errorf("--from-dir %s: %w", srcDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--from-dir %s: not a directory", srcDir)
	}
	manifest, err := bundles.LoadManifest(filepath.Join(srcDir, bundles.ManifestFile))
	if err != nil {
		return fmt.Errorf("%s: %w", srcDir, err)
	}
	ref, err := bundles.ParseRef(o.RefOverride)
	if err != nil {
		return err
	}
	if ref.Version == "" {
		return fmt.Errorf("ref %s: a version is required", ref)
	}
	if err := enforceAllowlist(o.Dirs.DataDir, ref, o.SkipAllowlist); err != nil {
		return err
	}
	src := &bundles.SourceRecord{
		Ref:         ref.String(),
		ResolvedSHA: ref.Version,
		FetchedAt:   nowUTCSecond(),
		APIRenames:  renames,
	}
	finalDir, err := stageInstall(apisDir, manifest.Name, ".tmp.from-dir.*",
		func(tmpDir string) error { return copyTree(srcDir, tmpDir) }, src)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "installed %s\n  at %s\n", ref, finalDir)
	return nil
}
