// Command bouncer is the binary entry point for the policy-enforcing
// HTTP proxy and its companion CLI tools. Subcommand implementations
// live under internal/cli/*; this file composes them into a cobra
// root and routes the exit code (2 for argv-shape errors, 1 for any
// other subcommand failure).
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/buildinfo"
	"github.com/jkylling/bouncer/internal/cli/apiscmd"
	"github.com/jkylling/bouncer/internal/cli/connectionscmd"
	"github.com/jkylling/bouncer/internal/cli/initcmd"
	"github.com/jkylling/bouncer/internal/cli/issuetokencmd"
	"github.com/jkylling/bouncer/internal/cli/servecmd"
)

const rootLong = `Policy-enforcing HTTP proxy for upstream APIs.

Quick start:
  bouncer init ./bouncer-data
  bouncer serve --data-dir ./bouncer-data

Run any command with --help for its flags.`

func main() {
	root := &cobra.Command{
		Use:           "bouncer",
		Short:         "Policy-enforcing HTTP proxy for upstream APIs",
		Long:          rootLong,
		Version:       fmt.Sprintf("%s (%s)", buildinfo.Version, buildinfo.Commit),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("bouncer {{.Version}}\n")
	root.AddCommand(
		initcmd.Command(),
		servecmd.Command(),
		apiscmd.Command(),
		issuetokencmd.Command(),
		connectionscmd.Command(),
		versionCommand(root),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "bouncer: %v\n", err)
		if isUsageError(err) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

// versionCommand mirrors `bouncer --version` as a subcommand so the
// pre-cobra `bouncer version` shape keeps working. Reads the version
// off the root so the format stays in lockstep with --version.
func versionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version and commit",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("bouncer %s\n", root.Version)
		},
	}
}

// isUsageError matches the argv-shape errors cobra reports so we can
// land them on exit 2, matching the pre-cobra dispatcher. Cobra has
// no exported sentinel for "unknown command/flag", so we match the
// string the operator sees.
func isUsageError(err error) bool {
	msg := err.Error()
	for _, marker := range []string{"unknown command", "unknown flag", "unknown shorthand"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
