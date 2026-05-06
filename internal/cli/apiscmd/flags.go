package apiscmd

import (
	"errors"

	"github.com/spf13/cobra"
)

// errMissingAPIsDir is the message every install path uses when the
// destination root is unresolved.
const errMissingAPIsDir = "missing destination: pass --apis-dir, --data-dir, or set $BOUNCER_APIS_DIR"

// apisDirFlags binds the standard --apis-dir/--data-dir pair every
// verb touching the apis directory accepts. The flags resolve to a
// single root via resolveAPIsDir.
type apisDirFlags struct {
	apisDir string
	dataDir string
}

func (f *apisDirFlags) bind(cmd *cobra.Command, apisDirHelp, dataDirHelp string) {
	if apisDirHelp == "" {
		apisDirHelp = "where bundles live (defaults to $BOUNCER_APIS_DIR or <data-dir>/apis)"
	}
	if dataDirHelp == "" {
		dataDirHelp = "data directory (used to derive --apis-dir)"
	}
	cmd.Flags().StringVar(&f.apisDir, "apis-dir", "", apisDirHelp)
	cmd.Flags().StringVar(&f.dataDir, "data-dir", "", dataDirHelp)
}

func (f *apisDirFlags) resolve() (string, error) {
	root := resolveAPIsDir(f.apisDir, f.dataDir)
	if root == "" {
		return "", errors.New(errMissingAPIsDir)
	}
	return root, nil
}
