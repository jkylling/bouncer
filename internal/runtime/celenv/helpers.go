package celenv

import (
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// Helpers returns a cel.Lib that bundles every general-purpose helper
// function exposed to filter/bind/output/policy expressions. Add new
// helpers here so the call site in languageOptions() stays the single
// place that decides which extras every env gets.
//
// Helpers added here are *available everywhere*; if a function should
// only be visible to the request env (like the http verb builders),
// register it in env.go's HTTPHelpers instead.
func Helpers() cel.EnvOption {
	return cel.Lib(helpersLib{})
}

type helpersLib struct{}

// Compile-time interface assertion.
var _ cel.Library = helpersLib{}

func (helpersLib) LibraryName() string { return "bouncer.helpers" }

func (helpersLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// timestamp_seconds(n) builds a Timestamp from a Unix-seconds
		// integer. CEL's stdlib `timestamp(string)` only parses RFC3339
		// strings, but most upstream APIs (Slack, GitHub, Unix tools)
		// expose creation times as integer seconds — wrapping the
		// conversion as a function avoids forcing every policy author
		// to write `timestamp(string(n)+"s")`-style incantations.
		cel.Function("timestamp_seconds",
			cel.Overload("timestamp_seconds_int",
				[]*cel.Type{cel.IntType}, cel.TimestampType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					i, ok := v.(types.Int)
					if !ok {
						return types.NewErr("timestamp_seconds: want int, got %T", v)
					}
					return types.Timestamp{Time: time.Unix(int64(i), 0).UTC()}
				}),
			),
		),
	}
}

func (helpersLib) ProgramOptions() []cel.ProgramOption { return nil }
