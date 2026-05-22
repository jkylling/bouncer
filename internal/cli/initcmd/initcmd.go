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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/datadir"
	"github.com/jkylling/bouncer/internal/server/mitm"
)

// Layout constants and IsInitialized live in internal/datadir; this
// package writes through those names. The aliases keep the existing
// external references (initcmd.SecretFile etc.) working.
const (
	SecretFile        = datadir.SecretFile
	AdminPasswordFile = datadir.AdminPasswordFile
	StoreDir          = datadir.StoreDir
	APIsDir           = datadir.APIsDir
	PoliciesDir       = datadir.PoliciesDir
	MITMCertFile      = datadir.MITMCertFile
	MITMKeyFile       = datadir.MITMKeyFile
	ReadmeFile        = datadir.ReadmeFile
)

// IsInitialized re-exports datadir.IsInitialized for back-compat.
func IsInitialized(dir string) bool { return datadir.IsInitialized(dir) }

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

// Options is the shared option set Run and Bootstrap accept.
type Options struct {
	// Empty AdminPassword falls through to $BOUNCER_ADMIN_PASSWORD,
	// then to a stdin prompt.
	AdminPassword string

	MITM           bool
	MITMCommonName string // defaults to "bouncer MITM CA"

	// Force rotates the credential files but leaves an existing
	// store.db in place — rows in it still reference principals
	// issued under the previous secret. Delete store.db separately
	// for a fully clean slate.
	Force bool

	// SkipIfInitialized makes Run a no-op when the dir already has
	// secret.hex + admin-password.hash. On for `serve --init` so
	// daemon restart is safe; off for `bouncer init` so an explicit
	// re-init errors loudly instead of rotating the secret out from
	// under previously issued JWTs.
	SkipIfInitialized bool

	// Quiet suppresses progress lines and the post-init "Ready"
	// hint. `serve --init` sets this since serve logs its own
	// listening banner immediately after.
	Quiet bool

	// WithApis runs through bundles.InstallRefs after bootstrap;
	// already-vendored refs are skipped.
	WithApis []string
}

// Run is the shared entry for `bouncer init` and `bouncer serve --init`.
func Run(dir string, opts Options) error {
	if dir == "" {
		dir = "."
	}
	skipBootstrap := opts.SkipIfInitialized && IsInitialized(dir)
	w := io.Discard
	if !opts.Quiet {
		w = os.Stderr
	}
	if !skipBootstrap {
		if err := bootstrap(dir, opts, w); err != nil {
			return err
		}
	}
	// --with-apis runs on the skip-bootstrap path too, so a restart
	// with a new ref picks it up. InstallRefs is idempotent.
	if len(opts.WithApis) > 0 {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if err := bundles.InstallRefs(ctx, filepath.Join(dir, APIsDir), opts.WithApis, w); err != nil {
			return err
		}
	}
	if !opts.Quiet && !skipBootstrap {
		printReadyHint(dir)
	}
	return nil
}

// Bootstrap writes the data-directory layout with progress suppressed.
// Prefer Run for end-user-facing flows.
func Bootstrap(dir string, opts Options) error {
	return bootstrap(dir, opts, io.Discard)
}

func bootstrap(dir string, opts Options, w io.Writer) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve dir: %w", err)
	}
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
	fmt.Fprintf(w, "  wrote %s\n", SecretFile)

	pw, err := resolvePassword(opts.AdminPassword)
	if err != nil {
		return fmt.Errorf("admin password: %w", err)
	}
	if err := writeBcrypt(filepath.Join(abs, AdminPasswordFile), pw); err != nil {
		return fmt.Errorf("admin password hash: %w", err)
	}
	fmt.Fprintf(w, "  wrote %s\n", AdminPasswordFile)

	if opts.MITM {
		cn := opts.MITMCommonName
		if cn == "" {
			cn = "bouncer MITM CA"
		}
		if err := writeMITMCA(abs, cn); err != nil {
			return fmt.Errorf("mitm CA: %w", err)
		}
		fmt.Fprintf(w, "  wrote %s + %s\n", MITMCertFile, MITMKeyFile)
	}

	if err := os.WriteFile(filepath.Join(abs, ReadmeFile), []byte(readmeBody(abs, opts.MITM)), 0o644); err != nil {
		return fmt.Errorf("readme: %w", err)
	}
	return nil
}

func printReadyHint(dir string) {
	if dir == "." {
		fmt.Fprint(os.Stderr, "\nReady. Start the proxy from this directory with:\n\n  bouncer serve\n\n")
		return
	}
	fmt.Fprintf(os.Stderr, "\nReady. Start the proxy with:\n\n  bouncer serve --data-dir %s\n\n  # or `cd %s && bouncer serve` — `serve` auto-detects an initialized cwd.\n\n", dir, dir)
}

type initOpts struct {
	mitmEnabled bool
	mitmCN      string
	password    string
	force       bool
	withApis    []string
}

func (o *initOpts) bind(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.mitmEnabled, "mitm", true, "generate a self-signed MITM CA cert/key. Set --mitm=false to skip.")
	cmd.Flags().StringVar(&o.mitmCN, "mitm-ca-cn", "bouncer MITM CA", "Common Name on the generated MITM CA cert")
	cmd.Flags().StringVar(&o.password, "admin-password", "", "admin password to hash; empty value reads from $BOUNCER_ADMIN_PASSWORD or prompts on stdin")
	cmd.Flags().BoolVar(&o.force, "force", false, "overwrite existing files in the target dir (default: refuse if any layout file already exists)")
	cmd.Flags().StringSliceVar(&o.withApis, "with-apis", nil, "install one or more bundle refs into <dir>/apis (e.g. github.com/jkylling/bouncer-gws@v0.1.0, or just github.com/jkylling/bouncer-gws to track main). Already-installed refs are skipped; repeat the flag for several bundles.")
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
		// No arg: refuse to scribble layout files into a populated
		// cwd. --force overrides, the same as for inside bootstrap.
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("read cwd: %w", err)
		}
		if n := nonHiddenCount(entries); n > 0 {
			return fmt.Errorf("refusing to init the current directory: it contains %d entr%s. Pass an explicit <dir>, run inside an empty dir, or use --force",
				n, plural(n))
		}
	}
	return Run(dir, Options{
		AdminPassword:  o.password,
		MITM:           o.mitmEnabled,
		MITMCommonName: o.mitmCN,
		Force:          o.force,
		WithApis:       o.withApis,
	})
}

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

// writeSecret writes 32 random bytes hex-encoded; hex (rather than
// raw binary) keeps the file copy-pastable and matches --secret-hex.
func writeSecret(path string) error {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	enc := hex.EncodeToString(raw[:]) + "\n"
	return os.WriteFile(path, []byte(enc), 0o600)
}

// resolvePassword picks the password from, in order:
// flagVal → $BOUNCER_ADMIN_PASSWORD → TTY prompt (no echo)
// → plain line-read (for piped stdin).
func resolvePassword(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if env := os.Getenv("BOUNCER_ADMIN_PASSWORD"); env != "" {
		return env, nil
	}
	stdinFD := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFD) {
		return promptPasswordTTY(stdinFD)
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

// promptPasswordTTY reads password with echo off.
func promptPasswordTTY(fd int) (string, error) {
	fmt.Fprint(os.Stderr, "Admin password: ")
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(pw) == 0 {
		return "", errors.New("empty password")
	}
	return string(pw), nil
}

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
- %s/ : sqlite store(s) for traffic and policies (populated on first serve).
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

// nonHiddenCount ignores `.git` and friends so init can run inside
// an existing repo worktree.
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
