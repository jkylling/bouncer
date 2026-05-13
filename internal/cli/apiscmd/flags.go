package apiscmd

import (
	"errors"

	"github.com/spf13/pflag"

	"github.com/jkylling/bouncer/internal/datadir"
)

// errMissingAPIsDir is the message every install path uses when the
// destination root is unresolved.
const errMissingAPIsDir = "missing destination: pass --apis-dir, --data-dir, or set $BOUNCER_APIS_DIR"

// apisDirFlags is the shared `--apis-dir` / `--data-dir` pair every
// verb touching the apis directory accepts. Resolves to a single root
// via resolveAPIsDir, which also honours $BOUNCER_DATA_DIR and the
// cwd-if-initialized fallback.
type apisDirFlags struct {
	ApisDir string `mapstructure:"apis-dir"`
	DataDir string `mapstructure:"data-dir"`
}

func (f *apisDirFlags) bind(fs *pflag.FlagSet, apisDirHelp string) {
	if apisDirHelp == "" {
		apisDirHelp = "where bundles live (defaults to $BOUNCER_APIS_DIR or <data-dir>/apis)"
	}
	fs.String("apis-dir", "", apisDirHelp)
	datadir.BindFlag(fs)
}

func (f *apisDirFlags) resolve() (string, error) {
	root := resolveAPIsDir(f.ApisDir, f.DataDir)
	if root == "" {
		return "", errors.New(errMissingAPIsDir)
	}
	return root, nil
}
