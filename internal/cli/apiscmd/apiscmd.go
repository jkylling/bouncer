// Package apiscmd implements `bouncer apis ...` — the CLI surface
// for managing API bundles.
//
// Subcommands:
//
//	add       — fetch a bundle from GitHub and install it
//	list      — show every installed bundle (and its renames)
//	remove    — delete an installed bundle by name
//	upgrade   — re-resolve a bundle's ref against upstream
//	fetch     — pack a bundle into a tarball without installing
//
// The proxy at runtime never talks to the network; the verbs in this
// package are the only place that does. They write into the apis
// directory the loader (internal/control/bundles) reads on every
// `serve`. Bundles install at <apis-dir>/<bundle-name>/; loose
// single-file specs sit at the top level alongside.
package apiscmd

import (
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/datadir"
)

// nowUTCSecond returns time.Now().UTC().Truncate(time.Second). Tests
// override for deterministic timestamps.
var nowUTCSecond = func() time.Time { return time.Now().UTC().Truncate(time.Second) }

const apisLong = `Manage API bundles.

Bundles install under <apis-dir>/<bundle-name>/, alongside any top-level
*.yaml files (loose single-API specs the operator drops in by hand).
The apis dir is read from --apis-dir, --data-dir/apis, or
$BOUNCER_APIS_DIR (in that order). These flags are scoped per
subcommand — pass them after the verb, not before.

A <ref> is github.com/<owner>/<repo>[@<version>]. Versions may be a
semver tag, branch name, or full commit SHA. The version is required
for add/fetch.`

// Command returns the `bouncer apis` subcommand tree. Composed under
// cmd/bouncer's root cobra.Command.
func Command() *cobra.Command {
	apis := &cobra.Command{
		Use:           "apis",
		Short:         "Manage API bundles",
		Long:          apisLong,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	apis.AddCommand(
		addCommand(),
		listCommand(),
		removeCommand(),
		upgradeCommand(),
		fetchCommand(),
		packCommand(),
		verifyCommand(),
	)
	return apis
}

// execute is the test entry: silences cobra's auto-printed usage +
// error so the caller (tests) controls presentation.
func execute(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	return cmd.Execute()
}

// resolveAPIsDir picks the apis directory. Precedence:
//
//	--apis-dir → --data-dir/apis → $BOUNCER_APIS_DIR → cwd/apis
//	(when cwd is an initialized data dir)
//	→ $BOUNCER_DATA_DIR/apis
//
// Returns "" when nothing matches; the caller turns that into a
// clear error.
func resolveAPIsDir(flagVal, dataDir string) string {
	if flagVal != "" {
		return flagVal
	}
	if dataDir != "" {
		return datadir.Layout{Dir: dataDir}.APIs()
	}
	if env := strings.TrimSpace(os.Getenv("BOUNCER_APIS_DIR")); env != "" {
		return env
	}
	if datadir.IsInitialized(".") {
		return datadir.Layout{Dir: "."}.APIs()
	}
	if env := strings.TrimSpace(os.Getenv(datadir.EnvDataDir)); env != "" {
		return datadir.Layout{Dir: env}.APIs()
	}
	return ""
}
