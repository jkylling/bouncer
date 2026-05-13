package apiscmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/cli/cliconfig"
	"github.com/jkylling/bouncer/internal/control/bundles"
)

// runWithOpts wraps the RunE shape every apiscmd subcommand uses:
// cliconfig.Load into a fresh opts struct, then dispatch to fn.
func runWithOpts[T any](fn func(args []string, o *T) error) func(*cobra.Command, []string) error {
	return func(c *cobra.Command, args []string) error {
		var o T
		if err := cliconfig.Load(c.Flags(), &o); err != nil {
			return err
		}
		return fn(args, &o)
	}
}

// newGitHubFetcher constructs the standard fetcher used by every
// network-touching subcommand. $GITHUB_TOKEN, if set, is sent as a
// bearer to GitHub.
func newGitHubFetcher() *bundles.Fetcher {
	return bundles.NewFetcher(bundles.FetcherOpts{Token: os.Getenv("GITHUB_TOKEN")})
}

// signalContext returns a context cancelled on SIGINT/SIGTERM so a
// long-running fetch tears down cleanly when the operator hits ^C.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
