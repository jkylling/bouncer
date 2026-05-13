package apiscmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

const addLong = `Install an API bundle.

Default mode resolves <ref> to a commit SHA via the GitHub commits API,
downloads the tarball from codeload.github.com, validates it shapes
as a bundle (apis.yaml + apis/<files>), and writes a generated
source.yaml alongside the upstream content. Installation is atomic:
a partial extract under .tmp.<rand>/ is renamed into the final
host/owner/repo@<sha>/ path only after success.

--from-dir reads a local working tree of a bundle repo and installs
it under <vendored>/<host>/<owner>/<repo>@<version>/ — designed for
iterating on a bundle before publishing. .git/ is skipped on copy;
the version segment in the install path is whatever you pass in
--ref (often "dev" or a feature-branch name).

Auth: $GITHUB_TOKEN, when non-empty, is sent as a bearer to GitHub.
Empty means anonymous (public repos only).

Renames: --rename <upstream>=<local> writes an entry into the
generated source.yaml#api_renames; the runtime loader registers the
API under <local> instead of <upstream> on every serve. Multiple
flags compose. Use this when two installed bundles ship an API of
the same name.`

type addOpts struct {
	Dirs          apisDirFlags `mapstructure:",squash"`
	Renames       []string     `mapstructure:"rename"`
	FromTarball   string       `mapstructure:"from-tarball"`
	FromDir       string       `mapstructure:"from-dir"`
	RefOverride   string       `mapstructure:"ref"`
	SkipAllowlist bool         `mapstructure:"skip-allowlist"`
}

func (o *addOpts) bind(fs *pflag.FlagSet) {
	o.Dirs.bind(fs, "where to install (defaults to $BOUNCER_APIS_DIR or <data-dir>/apis)")
	fs.StringSlice("rename", nil, "rename an upstream API on install (--rename gmail=acme-gmail). May repeat.")
	fs.String("from-tarball", "", "install from a tarball produced by `apis fetch` instead of contacting GitHub")
	fs.String("from-dir", "", "install from a local directory (e.g. a working tree of bouncer-gws). Requires --ref.")
	fs.String("ref", "", "ref to record in source.yaml. Required with --from-dir; with --from-tarball, overrides the tarball's embedded ref.")
	fs.Bool("skip-allowlist", false, "bypass the bouncer.yaml#apis.allowlist check (use sparingly)")
}

func addCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <ref>",
		Short: "Fetch and install a bundle from GitHub",
		Long:  addLong,
		Example: `  bouncer apis add github.com/jkylling/bouncer-gws@v0.1.0
  bouncer apis add --from-tarball ./bundle.tar.gz
  bouncer apis add --from-dir ./bouncer-gws --ref dev`,
		RunE: runWithOpts(runAdd),
	}
	(&addOpts{}).bind(cmd.Flags())
	return cmd
}

func runAdd(args []string, o *addOpts) error {
	if o.FromTarball != "" && o.FromDir != "" {
		return errors.New("--from-tarball and --from-dir are mutually exclusive")
	}
	root, err := o.Dirs.resolve()
	if err != nil {
		return err
	}
	renameMap, err := parseRenames(o.Renames)
	if err != nil {
		return err
	}
	if o.FromTarball != "" {
		if len(args) != 0 {
			return errors.New("--from-tarball does not accept a positional ref; use --ref instead")
		}
		return runAddFromTarball(o, root, renameMap)
	}
	if o.FromDir != "" {
		if len(args) != 0 {
			return errors.New("--from-dir does not accept a positional ref; use --ref instead")
		}
		return runAddFromDir(o, root, renameMap)
	}
	if len(args) != 1 {
		return fmt.Errorf("expected one ref argument; got %d", len(args))
	}
	ref, err := bundles.ParseRef(args[0])
	if err != nil {
		return err
	}
	if ref.Version == "" {
		// Refs without a version track the upstream default branch.
		// `apis upgrade` re-resolves the recorded "main" the same
		// way, so the install stays follow-the-branch.
		ref.Version = "main"
	}
	if err := enforceAllowlist(o.Dirs.DataDir, ref, o.SkipAllowlist); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	dest, err := newGitHubFetcher().Install(ctx, root, ref, renameMap)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "installed %s\n  at %s\n", ref, dest)
	return nil
}

// parseRenames takes ["from=to", "alpha=beta"] and returns the
// equivalent map. Empty input gives nil. Errors out on malformed
// entries so the operator gets a clear "you passed --rename foo"
// rather than silently dropping the flag.
func parseRenames(flags []string) (map[string]string, error) {
	if len(flags) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	for _, raw := range flags {
		from, to, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, fmt.Errorf("--rename %q: must be <upstream>=<local>", raw)
		}
		from, to = strings.TrimSpace(from), strings.TrimSpace(to)
		if from == "" || to == "" {
			return nil, fmt.Errorf("--rename %q: empty side", raw)
		}
		if existing, ok := out[from]; ok {
			return nil, fmt.Errorf("--rename %q: %s already mapped to %s", raw, from, existing)
		}
		out[from] = to
	}
	return out, nil
}
