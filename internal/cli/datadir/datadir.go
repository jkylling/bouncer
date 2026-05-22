// Package datadir owns the on-disk layout `bouncer init` writes and
// every other CLI reads. Constants describe the files; Layout points
// at one resolved dir and returns the per-domain paths; Resolve picks
// the dir from --data-dir, $BOUNCER_DATA_DIR, or cwd-if-initialized.
package datadir

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
)

const (
	SecretFile        = "secret.hex"
	AdminPasswordFile = "admin-password.hash"
	StoreDir          = "store"
	StoreDBFile       = "store.db"
	APIsDir           = "apis"
	PoliciesDir       = "policies"
	MITMCertFile      = "mitm-ca.crt"
	MITMKeyFile       = "mitm-ca.key"
	ReadmeFile        = "README.md"

	EnvDataDir = "BOUNCER_DATA_DIR"

	FlagName = "data-dir"
	FlagHelp = "data directory created by `bouncer init`; defaults to $BOUNCER_DATA_DIR or cwd if cwd looks initialized"
)

// IsInitialized reports whether dir holds the minimum layout (secret
// + admin password hash). Other files are optional.
func IsInitialized(dir string) bool {
	for _, name := range []string{SecretFile, AdminPasswordFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}

// BindFlag registers --data-dir on fs with the standard description.
func BindFlag(fs *pflag.FlagSet) {
	fs.String(FlagName, "", FlagHelp)
}

// Resolve returns the resolved data dir, in precedence:
//
//	--data-dir flag → $BOUNCER_DATA_DIR → cwd if it looks initialized
//
// Returns "" when nothing matches. The flag must already be bound on
// fs (use BindFlag).
func Resolve(fs *pflag.FlagSet) string {
	if v, _ := fs.GetString(FlagName); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(EnvDataDir)); v != "" {
		return v
	}
	if IsInitialized(".") {
		return "."
	}
	return ""
}

// Layout is the resolved data dir; methods return per-domain paths.
type Layout struct {
	Dir string
}

func (l Layout) APIs() string      { return filepath.Join(l.Dir, APIsDir) }
func (l Layout) Policies() string  { return filepath.Join(l.Dir, PoliciesDir) }
func (l Layout) Store() string     { return filepath.Join(l.Dir, StoreDir) }
func (l Layout) StoreDB() string   { return filepath.Join(l.Dir, StoreDir, StoreDBFile) }
func (l Layout) Secret() string    { return filepath.Join(l.Dir, SecretFile) }
func (l Layout) AdminHash() string { return filepath.Join(l.Dir, AdminPasswordFile) }
func (l Layout) MITMCert() string  { return filepath.Join(l.Dir, MITMCertFile) }
func (l Layout) MITMKey() string   { return filepath.Join(l.Dir, MITMKeyFile) }

// ReadSecret reads <dir>/secret.hex (trimmed of trailing newline).
func (l Layout) ReadSecret() (string, error) {
	return readTrimmed(l.Secret())
}

// ReadAdminHash reads <dir>/admin-password.hash (trimmed).
func (l Layout) ReadAdminHash() (string, error) {
	return readTrimmed(l.AdminHash())
}

// Exists reports whether path exists on disk.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readTrimmed(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}
