// Package initcmd implements `bouncer init`: bootstrap a
// self-contained data directory the operator can immediately point
// `bouncer serve` at. The layout it writes is the same one
// `serve --data-dir` knows how to consume, so the two-command
// happy path is:
//
//	bouncer init ./bouncer-data
//	bouncer serve --data-dir ./bouncer-data
package initcmd

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"github.com/jkylling/bouncer/internal/server/mitm"
)

// Layout is the on-disk shape `init` writes and `serve --data-dir`
// reads. Exported so callers (init here, serve elsewhere) refer to
// the same path constants instead of stringly-duplicated literals.
const (
	SecretFile        = "secret.hex"
	AdminPasswordFile = "admin-password.hash"
	StoreDir          = "store"
	APIsDir           = "apis"
	PoliciesDir       = "policies"
	MITMCertFile      = "mitm-ca.crt"
	MITMKeyFile       = "mitm-ca.key"
	ReadmeFile        = "README.md"
)

const initLong = `Bootstrap a self-contained data directory.

Writes the following layout under <dir> (default: the current
directory, which must be empty):

  <dir>/
    secret.hex            32-byte server secret (mode 0600)
    admin-password.hash   bcrypt of the prompted admin password (0600)
    store/                sqlite databases, populated on first serve
    apis/                 API specs (loose *.yaml + installed bundles)
    policies/             drop policy YAML files here
    mitm-ca.crt           (optional) MITM CA certificate
    mitm-ca.key           (optional) MITM CA private key (0600)
    README.md             layout reminder + sample serve command

After this completes, start the proxy with:

  bouncer serve --data-dir <dir>`

// Options controls Bootstrap. Exposed so other entry points
// (notably `bouncer serve --init`) can drive the same logic without
// going through pflag a second time.
type Options struct {
	// AdminPassword is the cleartext password to bcrypt into
	// admin-password.hash. Empty means: read from
	// $BOUNCER_ADMIN_PASSWORD, fall back to a stdin prompt.
	AdminPassword string

	// MITM, when true, generates a self-signed CA and writes
	// mitm-ca.{crt,key} alongside the rest of the layout. Default
	// behaviour because --mitm on serve also defaults on; the two
	// happy-paths line up.
	MITM bool

	// MITMCommonName is stamped onto the generated CA. Defaults to
	// "bouncer MITM CA" when empty.
	MITMCommonName string

	// Force recreates existing layout files. Without it, Bootstrap
	// refuses to clobber a directory that already has a secret /
	// admin-password / store.db / mitm-ca.* — overwriting any of
	// those silently invalidates every JWT issued against the
	// previous secret. Note: --force rotates the credential files
	// but leaves an existing store.db in place; rows in it still
	// reference principals issued under the old secret. Delete
	// store.db separately if you want a fully clean slate.
	Force bool
}

// IsInitialized reports whether dir already holds a usable bouncer
// data directory. Used by `serve --init` to no-op a second invocation
// instead of refusing to start.
func IsInitialized(dir string) bool {
	for _, name := range []string{SecretFile, AdminPasswordFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}

// Bootstrap writes the data-directory layout. Idempotent only when
// IsInitialized(dir) is true and Force is false: in that case the
// caller is expected to short-circuit. With Force=true Bootstrap
// recreates every layout file even if one already exists, which
// invalidates previously issued JWTs.
func Bootstrap(dir string, opts Options) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve dir: %w", err)
	}

	// Refuse to clobber an existing setup unless --force. Picking up
	// an in-progress dir would mean writing a fresh secret on top of
	// the one operators already issued tokens against.
	existing := existingLayoutFiles(abs)
	if len(existing) > 0 && !opts.Force {
		return fmt.Errorf("refusing to overwrite existing files in %s:\n  %s\n\nPass --force to recreate them (this invalidates every JWT issued against the previous secret)",
			abs, strings.Join(existing, "\n  "))
	}

	if err := os.MkdirAll(abs, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", abs, err)
	}
	if err := os.MkdirAll(filepath.Join(abs, APIsDir), 0o755); err != nil {
		return fmt.Errorf("mkdir apis: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, PoliciesDir), 0o755); err != nil {
		return fmt.Errorf("mkdir policies: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, StoreDir), 0o755); err != nil {
		return fmt.Errorf("mkdir store: %w", err)
	}

	if err := writeSecret(filepath.Join(abs, SecretFile)); err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  wrote %s\n", SecretFile)

	pw, err := resolvePassword(opts.AdminPassword)
	if err != nil {
		return fmt.Errorf("admin password: %w", err)
	}
	if err := writeBcrypt(filepath.Join(abs, AdminPasswordFile), pw); err != nil {
		return fmt.Errorf("admin password hash: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  wrote %s\n", AdminPasswordFile)

	if opts.MITM {
		cn := opts.MITMCommonName
		if cn == "" {
			cn = "bouncer MITM CA"
		}
		if err := writeMITMCA(abs, cn); err != nil {
			return fmt.Errorf("mitm CA: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  wrote %s + %s\n", MITMCertFile, MITMKeyFile)
	}

	if err := os.WriteFile(filepath.Join(abs, ReadmeFile), []byte(readmeBody(abs, opts.MITM)), 0o644); err != nil {
		return fmt.Errorf("readme: %w", err)
	}
	return nil
}

// Command returns the `bouncer init` cobra subcommand.
type initOpts struct {
	mitmEnabled bool
	mitmCN      string
	password    string
	force       bool
}

func (o *initOpts) bind(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.mitmEnabled, "mitm", true, "generate a self-signed MITM CA cert/key. Set --mitm=false to skip.")
	cmd.Flags().StringVar(&o.mitmCN, "mitm-ca-cn", "bouncer MITM CA", "Common Name on the generated MITM CA cert")
	cmd.Flags().StringVar(&o.password, "admin-password", "", "admin password to hash; empty value reads from $BOUNCER_ADMIN_PASSWORD or prompts on stdin")
	cmd.Flags().BoolVar(&o.force, "force", false, "overwrite existing files in the target dir (default: refuse if any layout file already exists)")
}

func Command() *cobra.Command {
	var o initOpts
	cmd := &cobra.Command{
		Use:   "init [<dir>]",
		Short: "Bootstrap a data directory (secret, admin password, apis/policies dirs, optional MITM CA)",
		Long:  initLong,
		RunE:  func(_ *cobra.Command, args []string) error { return runInit(args, &o) },
	}
	o.bind(cmd)
	return cmd
}

func runInit(args []string, o *initOpts) error {
	if len(args) > 1 {
		return fmt.Errorf("expected at most one directory argument; got %d", len(args))
	}
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	} else if !o.force {
		// No arg: use cwd, but only if it looks empty. Refuse to
		// scribble layout files into a populated working directory
		// (e.g. the operator typed `bouncer init` in their home dir
		// by accident). --force gates the override the same way it
		// gates layout-file collisions inside Bootstrap.
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("read cwd: %w", err)
		}
		if n := nonHiddenCount(entries); n > 0 {
			return fmt.Errorf("refusing to init the current directory: it contains %d entr%s. Pass an explicit <dir>, run inside an empty dir, or use --force",
				n, plural(n))
		}
	}
	if err := Bootstrap(dir, Options{
		AdminPassword:  o.password,
		MITM:           o.mitmEnabled,
		MITMCommonName: o.mitmCN,
		Force:          o.force,
	}); err != nil {
		return err
	}
	// `bouncer serve` (no --data-dir) auto-detects an initialized
	// cwd, so when the operator just init'd cwd they can drop the
	// flag entirely. The explicit --data-dir form stays in the hint
	// for the case where the init dir wasn't cwd.
	if dir == "." {
		fmt.Fprint(os.Stderr, "\nReady. Start the proxy from this directory with:\n\n  bouncer serve\n\n")
	} else {
		fmt.Fprintf(os.Stderr, "\nReady. Start the proxy with:\n\n  bouncer serve --data-dir %s\n\n  # or `cd %s && bouncer serve` — `serve` auto-detects an initialized cwd.\n\n", dir, dir)
	}
	return nil
}

// existingLayoutFiles returns the layout-relative paths that already
// exist under dir. The empty slice means a clean target.
func existingLayoutFiles(dir string) []string {
	var hits []string
	for _, name := range []string{
		SecretFile, AdminPasswordFile, MITMCertFile, MITMKeyFile,
		filepath.Join(StoreDir, "store.db"),
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			hits = append(hits, name)
		}
	}
	return hits
}

// writeSecret generates 32 random bytes, hex-encodes them, and
// writes the result with mode 0600. Hex (rather than raw binary)
// keeps the file copy-pastable and matches `--secret-hex` directly.
func writeSecret(path string) error {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	enc := hex.EncodeToString(raw[:]) + "\n"
	return os.WriteFile(path, []byte(enc), 0o600)
}

// resolvePassword picks the admin password from, in order:
//   - the --admin-password flag (handy for scripted bootstrap),
//   - the BOUNCER_ADMIN_PASSWORD env var,
//   - an interactive read from stdin (no echo when stdin is a tty,
//     plain read otherwise so a piped `echo … | bouncer init` works).
func resolvePassword(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if env := os.Getenv("BOUNCER_ADMIN_PASSWORD"); env != "" {
		return env, nil
	}
	fmt.Fprint(os.Stderr, "Admin password: ")
	pw, err := readLine(os.Stdin)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	pw = strings.TrimRight(pw, "\r\n")
	if pw == "" {
		return "", errors.New("empty password")
	}
	return pw, nil
}

// readLine reads one line from r. Echo suppression on a TTY would
// require golang.org/x/term, which we keep out for now — operators
// who care use --admin-password or BOUNCER_ADMIN_PASSWORD instead.
// bufio handles arbitrary-length lines and short reads correctly,
// unlike a single fixed-buffer Read.
func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return line, nil
}

func writeBcrypt(path, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(hash, '\n'), 0o600)
}

// writeMITMCA generates a fresh self-signed CA and writes the cert
// + key to the data dir. Reuses the mitm package's helper so the
// shape exactly matches what `bouncer serve --mitm` expects.
func writeMITMCA(dir, cn string) error {
	cert, key, err := mitm.GenerateCA(cn, 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, MITMCertFile), cert, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, MITMKeyFile), key, 0o600)
}

func readmeBody(dir string, mitm bool) string {
	mitmLine := ""
	if mitm {
		mitmLine = fmt.Sprintf("- %s + %s : self-signed MITM CA. Install %s in your client's trust store and run serve with --mitm.\n", MITMCertFile, MITMKeyFile, MITMCertFile)
	}
	return fmt.Sprintf(`# bouncer data dir

This directory was created by `+"`bouncer init`"+`. The layout is:

- %s : 32-byte server secret (hex). Treat like a private key.
- %s : bcrypt hash of the admin password (for /_admin/login).
- %s/ : sqlite store(s) for traffic / policies / proposals (populated on first serve).
- %s/ : API specs. Top-level *.yaml files are loose specs; immediate subdirs are bundles installed via "bouncer apis add ...".
- %s/ : drop policy YAML specs here.
%s
Optional bouncer.yaml in this dir constrains which refs apis add
will install:

    apis:
      allowlist:
        - github.com/acme/*
        - github.com/jkylling/*

Start the proxy:

    bouncer serve --data-dir %s

The serve subcommand reads each file above in place; you can override any
individual flag (e.g. --addr :8443) without unsetting --data-dir.
`,
		SecretFile, AdminPasswordFile, StoreDir,
		APIsDir, PoliciesDir, mitmLine, dir,
	)
}

// nonHiddenCount counts directory entries whose names don't start
// with `.`. Hidden files (notably `.git`) are tolerated so an
// operator can `bouncer init` inside an existing repo's worktree.
func nonHiddenCount(entries []os.DirEntry) int {
	n := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			n++
		}
	}
	return n
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
