package apiscmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// runAddFromTarball installs from a tarball produced by apis fetch.
// The tarball embeds source.yaml so the install can run without
// network access; --ref overrides the embedded ref.
func runAddFromTarball(tarballPath, refOverride, dataDir, apisDir string, renames map[string]string, skipAllowlist bool) error {
	if apisDir == "" {
		return errors.New(errMissingAPIsDir)
	}
	in, err := os.Open(tarballPath)
	if err != nil {
		return err
	}
	defer in.Close()

	work, err := os.MkdirTemp("", "apis-from-tarball-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err := bundles.ExtractTarGz(in, work); err != nil {
		return fmt.Errorf("extract %s: %w", tarballPath, err)
	}
	manifest, err := bundles.LoadManifest(filepath.Join(work, bundles.ManifestFile))
	if err != nil {
		return err
	}
	embedded, err := bundles.LoadSource(filepath.Join(work, bundles.SourceFile))
	if err != nil {
		return fmt.Errorf("tarball missing source.yaml (was it produced by `apis fetch`?): %w", err)
	}

	refStr := embedded.Ref
	if strings.TrimSpace(refOverride) != "" {
		refStr = refOverride
	}
	ref, err := bundles.ParseRef(refStr)
	if err != nil {
		return fmt.Errorf("ref %q: %w", refStr, err)
	}
	if !skipAllowlist {
		if err := enforceAllowlist(dataDir, ref); err != nil {
			return err
		}
	}
	sha := embedded.ResolvedSHA
	if !bundles.IsFullSHA(sha) {
		return fmt.Errorf("embedded source.yaml resolved_sha %q is not a 40-char SHA", sha)
	}

	src := &bundles.SourceRecord{
		Ref:         ref.String(),
		ResolvedSHA: sha,
		FetchedAt:   nowUTCSecond(),
		APIRenames:  mergeRenames(embedded.APIRenames, renames),
	}
	finalDir, err := stageInstall(apisDir, manifest.Name, ".tmp.tarball.*",
		func(tmpDir string) error { return copyTree(work, tmpDir) }, src)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "installed %s\n  at %s\n", ref, finalDir)
	return nil
}

// mergeRenames returns a fresh map of base ∪ extra (extra wins on
// collision). Returns nil when both inputs are empty so the
// resulting source.yaml omits the api_renames key entirely.
func mergeRenames(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
