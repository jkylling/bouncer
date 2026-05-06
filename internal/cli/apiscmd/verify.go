package apiscmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

const verifyLong = `Validate a bundle or apis dir using the proxy's boot chain.

Runs the same validation chain the proxy uses at boot:

  1. (bundle mode only) the bouncer.yaml manifest parses and validates;
  2. every API YAML parses with strict field checking — typos like
     "conditon:" for "condition:" surface here, not silently at
     runtime;
  3. every API compiles through the runtime Builder — CEL expressions
     in actions / binds / metas type-check, cross-API references
     resolve, path prefixes don't ambiguously overlap.

Mode is auto-detected by the presence of <dir>/bouncer.yaml:

  - bundle mode: <dir> is the bundle root; <dir>/bouncer.yaml lists
    which paths under the bundle to load (file paths or dir paths;
    a dir entry globs *.yaml/*.yml inside, non-recursively).
    Files outside the manifest's listed paths are NOT loaded.
  - bare apis-dir mode: every *.yaml under <dir> is loaded. This
    is the operator's --apis-dir.

Exit code: 0 on success, non-zero on the first failure (with the
offending file's path in the error message).`

func verifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <dir>",
		Short: "Validate a bundle or apis dir loads",
		Long:  verifyLong,
		RunE:  func(_ *cobra.Command, args []string) error { return runVerifyImpl(args) },
	}
}

// runVerify is the test entry: builds the cobra command and runs it
// with argv.
func runVerify(args []string) error { return execute(verifyCommand(), args) }

func runVerifyImpl(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected one directory argument; got %d", len(args))
	}
	dir := filepath.Clean(args[0])
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("source dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source dir %s: not a directory", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, bundles.ManifestFile)); err == nil {
		return verifyBundle(dir)
	}
	return verifyApisDir(dir)
}

// verifyBundle validates the manifest, walks every manifest entry
// (file or dir) through the same path-resolver the boot loader uses,
// parses each API YAML, then runs them through the runtime Builder.
// A verify-clean bundle is one a proxy will actually accept.
func verifyBundle(dir string) error {
	mf, err := bundles.LoadManifest(filepath.Join(dir, bundles.ManifestFile))
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	var apis []models.API
	for _, rel := range mf.APIs {
		paths, err := bundles.ResolveManifestEntry(dir, rel)
		if err != nil {
			return fmt.Errorf("manifest entry %q: %w", rel, err)
		}
		for _, full := range paths {
			docs, err := models.FromYAMLFile[models.API](full)
			if err != nil {
				return fmt.Errorf("%s: %w", full, err)
			}
			apis = append(apis, docs...)
		}
	}
	if len(apis) == 0 {
		return fmt.Errorf("manifest %q resolves to no API specs", mf.Name)
	}
	if err := buildRuntime(apis); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ok %s@%s\n  %d apis\n", mf.Name, mf.Version, len(apis))
	return nil
}

// verifyApisDir handles the bare --apis-dir case: no manifest, just
// load every *.yaml in the directory and run the runtime build.
func verifyApisDir(dir string) error {
	apis, err := models.FromYAMLDir[models.API](dir)
	if err != nil {
		return fmt.Errorf("load %s: %w", dir, err)
	}
	if len(apis) == 0 {
		return fmt.Errorf("%s contains no api YAML files", dir)
	}
	if err := buildRuntime(apis); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ok %s\n  %d apis\n", dir, len(apis))
	return nil
}

// buildRuntime is the runtime-compile gate: AddAPI registers types,
// Build does the cross-API consistency pass (path-prefix
// ambiguity, unresolved meta references, CEL type-checks). Same
// chain bouncer/serve runs at boot.
func buildRuntime(apis []models.API) error {
	b := runtime.NewBuilder()
	for i := range apis {
		spec := apis[i]
		if err := b.AddAPI(&spec); err != nil {
			return fmt.Errorf("compile %q: %w", spec.Name, err)
		}
	}
	if _, err := b.Build(); err != nil {
		return fmt.Errorf("build runtime: %w", err)
	}
	return nil
}
