package apiscmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jkylling/bouncer/internal/cli/datadir"
	"github.com/jkylling/bouncer/internal/control/bundles"
)

const fetchLong = `Pack a GitHub-hosted bundle into a tarball without installing.

Resolves <ref> to a SHA, downloads the codeload tarball, validates
that it shapes as a bundle, then re-packs the result (plus a generated
source.yaml) into the proxy's own tarball format under --output. The
file is suitable for "bouncer apis add --from-tarball <path>" on a
disconnected host — both sides understand the same layout, so nothing
about the install needs to be re-resolved offline.`

type fetchOpts struct {
	Output        string `mapstructure:"output"`
	DataDir       string `mapstructure:"data-dir"`
	SkipAllowlist bool   `mapstructure:"skip-allowlist"`
}

func (o *fetchOpts) bind(fs *pflag.FlagSet) {
	fs.String("output", "", "output tarball path (required)")
	datadir.BindFlag(fs)
	fs.Bool("skip-allowlist", false, "bypass the bouncer.yaml#apis.allowlist check")
}

func fetchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch <ref>",
		Short: "Pack a GitHub-hosted bundle into a tarball (no install)",
		Long:  fetchLong,
		RunE:  runWithOpts(runFetch),
	}
	(&fetchOpts{}).bind(cmd.Flags())
	return cmd
}

func runFetch(args []string, o *fetchOpts) error {
	if len(args) != 1 {
		return fmt.Errorf("expected one ref argument; got %d", len(args))
	}
	if o.Output == "" {
		return errors.New("--output is required")
	}
	ref, err := bundles.ParseRef(args[0])
	if err != nil {
		return err
	}
	if ref.Version == "" {
		return fmt.Errorf("ref %s: a version is required", ref)
	}
	if err := enforceAllowlist(o.DataDir, ref, o.SkipAllowlist); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	work, err := os.MkdirTemp("", "apis-fetch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	sha, err := newGitHubFetcher().Stage(ctx, ref, work, nil)
	if err != nil {
		return err
	}
	if err := bundles.WriteTarball(o.Output, work, ref.Repo+"-"+sha); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "wrote %s\n  ref %s\n  sha %s\n", o.Output, ref, sha)
	return nil
}
