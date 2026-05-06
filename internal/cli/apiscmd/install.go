package apiscmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// stageInstall runs the atomic-install ritual shared by from-tarball
// and from-dir: stat finalDir, mkdtemp, cleanup defer, populate via
// stage(tmpDir), write source.yaml, rename. The caller decides what
// goes into the SourceRecord; everything else is invariant.
//
// bundleName drives the on-disk layout — the bundle ends up at
// <apisDir>/<bundleName>/. stage is invoked with the temp directory
// and is expected to fill it with the final layout (sans source.yaml
// — this helper writes that).
func stageInstall(apisDir, bundleName, tmpPrefix string,
	stage func(tmpDir string) error, src *bundles.SourceRecord) (string, error) {
	finalDir := bundles.BundleDir(apisDir, bundleName)
	if _, err := os.Stat(finalDir); err == nil {
		return "", fmt.Errorf("install %s: %s already exists; remove or upgrade first", bundleName, finalDir)
	}
	if err := os.MkdirAll(apisDir, 0o755); err != nil {
		return "", err
	}
	tmpFinal, err := os.MkdirTemp(apisDir, tmpPrefix)
	if err != nil {
		return "", err
	}
	cleanup := tmpFinal
	defer func() {
		if cleanup != "" {
			_ = os.RemoveAll(cleanup)
		}
	}()
	if err := stage(tmpFinal); err != nil {
		return "", err
	}
	if err := bundles.WriteSource(filepath.Join(tmpFinal, bundles.SourceFile), src); err != nil {
		return "", err
	}
	if err := os.Rename(tmpFinal, finalDir); err != nil {
		return "", err
	}
	cleanup = ""
	return finalDir, nil
}
