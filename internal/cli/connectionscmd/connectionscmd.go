// Package connectionscmd implements the `bouncer connections`
// subcommand family: BYOT (bring-your-own-token) put, list, delete.
// The CLI writes directly to the on-disk store rather than talking
// to a running bouncer — mirrors `bouncer issue-token`, so an
// operator can stage credentials before the proxy is up. The wizard
// at /_admin/onboarding/connect writes through the same store.
package connectionscmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jkylling/bouncer/internal/cli/cliconfig"
	"github.com/jkylling/bouncer/internal/control/connections"
	"github.com/jkylling/bouncer/internal/datadir"
)

func Command() *cobra.Command {
	root := &cobra.Command{
		Use:   "connections",
		Short: "Manage stored upstream credentials (BYOT)",
		Long: `Manage the per-provider upstream credentials bouncer wraps into
JWTs at request time. Each entry is the OAuth triple
(client_id, client_secret, refresh_token) plus token_url — the same
shape ` + "`bouncer issue-token --credentials-file`" + ` consumes.

The data dir resolves the same way every other CLI does:
--data-dir flag → $BOUNCER_DATA_DIR → cwd-if-initialized.`,
	}
	root.AddCommand(putCommand(), listCommand(), deleteCommand())
	return root
}

// commonOpts holds flags every connections subcommand accepts.
type commonOpts struct {
	DataDir string `mapstructure:"data-dir"`
}

func (o *commonOpts) bind(fs *pflag.FlagSet) {
	datadir.BindFlag(fs)
}

// resolveLayout returns the per-subcommand Layout, defaulting via
// datadir.Resolve. Errors when the data dir can't be determined.
func resolveLayout(fs *pflag.FlagSet) (datadir.Layout, error) {
	dir, err := datadir.ResolveRequired(fs)
	if err != nil {
		return datadir.Layout{}, err
	}
	return datadir.Layout{Dir: dir}, nil
}

func openStore(l datadir.Layout) *connections.Store {
	return connections.NewStore(l.Connections())
}

// ---------- put -----------------------------------------------------

type putOpts struct {
	commonOpts   `mapstructure:",squash"`
	ClientID     string `mapstructure:"client-id"`
	ClientSecret string `mapstructure:"client-secret"`
	RefreshToken string `mapstructure:"refresh-token"`
	TokenURL     string `mapstructure:"token-url"`
	FromFile     string `mapstructure:"from-file"`
}

func (o *putOpts) bind(fs *pflag.FlagSet) {
	o.commonOpts.bind(fs)
	fs.String("client-id", "", "OAuth2 client ID (required)")
	fs.String("client-secret", "", "OAuth2 client secret (required)")
	fs.String("refresh-token", "", "upstream refresh token (required)")
	fs.String("token-url", "", "upstream OAuth2 token endpoint (required for non-google providers)")
	fs.String("from-file", "", "alternative to flags: read the credentials JSON {client_id, client_secret, refresh_token, token_url} from this file")
}

func putCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "put <provider>",
		Short: "Store an upstream credential for <provider>",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			var o putOpts
			if err := cliconfig.Load(c.Flags(), &o); err != nil {
				return err
			}
			return runPut(c.Flags(), &o, args[0])
		},
	}
	(&putOpts{}).bind(cmd.Flags())
	return cmd
}

func runPut(fs *pflag.FlagSet, o *putOpts, provider string) error {
	l, err := resolveLayout(fs)
	if err != nil {
		return err
	}
	creds, err := o.credentials()
	if err != nil {
		return err
	}
	rec, err := openStore(l).Put(provider, creds)
	if err != nil {
		return fmt.Errorf("put %s: %w", provider, err)
	}
	fmt.Fprintf(os.Stdout, "ok %s (client_id=%s, connected_at=%s)\n", rec.Provider, rec.Credentials.ClientID, rec.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	return nil
}

// credentials reads the OAuth triple from --from-file or from the
// flag fields. The file route is script-friendlier: the secret never
// hits argv.
func (o *putOpts) credentials() (connections.Credentials, error) {
	if o.FromFile != "" {
		body, err := os.ReadFile(o.FromFile)
		if err != nil {
			return connections.Credentials{}, fmt.Errorf("read %s: %w", o.FromFile, err)
		}
		var c connections.Credentials
		if err := json.Unmarshal(body, &c); err != nil {
			return connections.Credentials{}, fmt.Errorf("parse %s: %w", o.FromFile, err)
		}
		return c, nil
	}
	if o.ClientID == "" || o.ClientSecret == "" || o.RefreshToken == "" {
		return connections.Credentials{}, errors.New("--client-id, --client-secret, and --refresh-token are required (or pass --from-file)")
	}
	return connections.Credentials{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RefreshToken: o.RefreshToken,
		TokenURL:     o.TokenURL,
	}, nil
}

// ---------- list ----------------------------------------------------

func listCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored connections (provider + connected_at, secrets redacted)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runList(c.Flags())
		},
	}
	(&commonOpts{}).bind(cmd.Flags())
	return cmd
}

func runList(fs *pflag.FlagSet) error {
	l, err := resolveLayout(fs)
	if err != nil {
		return err
	}
	got, err := openStore(l).List()
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	if len(got) == 0 {
		fmt.Fprintln(os.Stdout, "(no connections)")
		return nil
	}
	for _, c := range got {
		fmt.Fprintf(os.Stdout, "%s\tclient_id=%s\t%s\n", c.Provider, c.Credentials.ClientID, c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	}
	return nil
}

// ---------- delete --------------------------------------------------

func deleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <provider>",
		Short: "Remove a stored connection",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runDelete(c.Flags(), args[0])
		},
	}
	(&commonOpts{}).bind(cmd.Flags())
	return cmd
}

func runDelete(fs *pflag.FlagSet, provider string) error {
	l, err := resolveLayout(fs)
	if err != nil {
		return err
	}
	if err := openStore(l).Delete(provider); err != nil {
		return fmt.Errorf("delete %s: %w", provider, err)
	}
	fmt.Fprintf(os.Stdout, "ok %s\n", provider)
	return nil
}
