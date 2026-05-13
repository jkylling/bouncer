// Package cliconfig wraps viper.Unmarshal into one call per CLI
// subcommand. All bouncer CLIs share the same env prefix (BOUNCER_*)
// and the same dash-to-underscore key replacer; this package owns
// the boilerplate so subcommands only declare their struct + flag set.
package cliconfig

import (
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// EnvPrefix is the env namespace every bouncer CLI reads from.
const EnvPrefix = "BOUNCER"

// Load reads fs (flags + their defaults) and the BOUNCER_* env into
// cfg via viper.Unmarshal. The decode hook supports time.Duration,
// comma-separated string slices, and any TextUnmarshaler-typed field
// (e.g. slog.Level).
func Load(fs *pflag.FlagSet, cfg any) error {
	v := viper.New()
	if err := v.BindPFlags(fs); err != nil {
		return fmt.Errorf("bind flags: %w", err)
	}
	v.SetEnvPrefix(EnvPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	if err := v.Unmarshal(cfg, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		mapstructure.TextUnmarshallerHookFunc(),
	))); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	return nil
}
