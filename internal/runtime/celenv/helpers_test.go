package celenv

import (
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTimestampSecondsRoundTrip verifies that timestamp_seconds(int)
// produces a CEL Timestamp that compares equal to the same instant
// constructed via the stdlib `timestamp(rfc3339)` builder. Slack-style
// integer-seconds timestamps are the primary use case.
func TestTimestampSecondsRoundTrip(t *testing.T) {
	env, err := cel.NewEnv(LanguageOptions()...)
	require.NoError(t, err)

	// 1700000000 == 2023-11-14T22:13:20Z. Comparing to the parsed
	// RFC3339 form is the canonical way to assert the cast preserved
	// the instant.
	ast, iss := env.Compile(`timestamp_seconds(1700000000) == timestamp("2023-11-14T22:13:20Z")`)
	require.NoError(t, iss.Err())

	prg, err := env.Program(ast)
	require.NoError(t, err)

	out, _, err := prg.Eval(map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, types.Bool(true), out)
}

// TestTimestampSecondsArithmetic confirms duration arithmetic works
// against a timestamp_seconds() value — the "files in the last 24h"
// pattern policies are expected to use.
func TestTimestampSecondsArithmetic(t *testing.T) {
	env, err := cel.NewEnv(append(LanguageOptions(),
		cel.Variable("now", cel.TimestampType),
		cel.Variable("file_created", cel.IntType),
	)...)
	require.NoError(t, err)

	ast, iss := env.Compile(`timestamp_seconds(file_created) > now - duration("24h")`)
	require.NoError(t, iss.Err())

	prg, err := env.Program(ast)
	require.NoError(t, err)

	now := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	cases := []struct {
		name        string
		fileCreated int64 // unix seconds
		want        bool
	}{
		{"created 1h ago", now.Add(-1 * time.Hour).Unix(), true},
		{"created 23h59m ago", now.Add(-23*time.Hour - 59*time.Minute).Unix(), true},
		{"created exactly 24h ago", now.Add(-24 * time.Hour).Unix(), false},
		{"created 25h ago", now.Add(-25 * time.Hour).Unix(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := prg.Eval(map[string]any{
				"now":          now,
				"file_created": tc.fileCreated,
			})
			require.NoError(t, err)
			assert.Equal(t, types.Bool(tc.want), out)
		})
	}
}
