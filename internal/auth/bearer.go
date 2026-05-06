package auth

import "log/slog"

// Bearer is the upstream credential the proxy forwards in the
// `Authorization: Bearer ...` header. It is a distinct named string
// so signatures that thread it alongside other strings (subject, api
// name, refresh token) reject a wrong-position argument at compile
// time. Conversions to plain `string` are explicit at the call site
// (e.g. server/load.go) so the unsafe path stays visible.
type Bearer string

// String returns a redacted placeholder so fmt/slog/json never emit
// the raw upstream access token without an explicit string() cast.
// `fmt.Sprintf("%v", bearer)` and `slog.LogValue(bearer)` are the
// common ways accidental disclosure happens; both go through these
// hooks. encoding/json has no String/LogValue hook, so passing a
// Bearer to json.Marshal still emits the cleartext — don't do that.
func (Bearer) String() string { return "[bearer redacted]" }

// LogValue implements slog.LogValuer. slog calls this when the
// Bearer is passed as a log attribute value, ensuring the bearer
// never reaches the log pipeline cleartext.
func (Bearer) LogValue() slog.Value { return slog.StringValue("[bearer redacted]") }
