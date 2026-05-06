package celenv

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// LanguageOptions returns the cel-go env options shared by every env
// builder: pure language extensions, optional types, and the
// general-purpose Helpers() library. HTTPHelpers is deliberately *not*
// in this list — only the request env exposes the http verb bindings.
func LanguageOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.OptionalTypes(),
		ext.Strings(),
		ext.Encoders(),
		ext.Math(),
		ext.Sets(),
		ext.Lists(),
		Helpers(),
	}
}
