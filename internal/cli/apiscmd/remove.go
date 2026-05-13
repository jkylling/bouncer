package apiscmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

const removeLong = `Remove an installed bundle by name.

The bundle name matches the manifest's ` + "`name:`" + ` field — the same
identifier ` + "`apis list`" + ` prints in the NAME column. Removing a bundle
deletes its on-disk directory verbatim.`

func removeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an installed bundle by name",
		Long:  removeLong,
		RunE:  runWithOpts(runRemoveImpl),
	}
	(&apisDirFlags{}).bind(cmd.Flags(), "")
	return cmd
}

// runRemove is the test entry: builds the cobra command and runs it
// with argv.
func runRemove(args []string) error { return execute(removeCommand(), args) }

func runRemoveImpl(args []string, dirs *apisDirFlags) error {
	if len(args) != 1 {
		return fmt.Errorf("expected one bundle-name argument; got %d", len(args))
	}
	name := args[0]
	root, err := dirs.resolve()
	if err != nil {
		return err
	}
	target := bundles.BundleDir(root, name)
	// Containment guard: the bundle name must not contain any path
	// separator or escape sequence. Without this an operator-typo
	// `apis remove ../etc` would dispatch a RemoveAll outside root.
	if cleaned := filepath.Clean(target); cleaned != target ||
		filepath.Dir(target) != filepath.Clean(root) {
		return fmt.Errorf("bundle name %q contains path separators", name)
	}
	if _, err := os.Stat(filepath.Join(target, bundles.ManifestFile)); err != nil {
		return fmt.Errorf("no bundle named %q under %s", name, root)
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("remove %s: %w", target, err)
	}
	fmt.Fprintf(os.Stdout, "removed %s\n", name)
	return nil
}
