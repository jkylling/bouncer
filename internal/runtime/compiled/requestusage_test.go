package compiled

import (
	"testing"
)

// TestAstUsesRequestBody pins the conservative detection contract the
// data plane's stream-vs-buffer decision rests on: reading any
// request field other than body is "no body use"; selecting body —
// directly, optionally, or under has()/macros — is "body use"; and
// any whole-`request` usage counts as body use because the value
// could carry the body somewhere the walker can't see.
func TestAstUsesRequestBody(t *testing.T) {
	env, err := filterEnv() // declares `request` + `match`
	if err != nil {
		t.Fatalf("filterEnv: %v", err)
	}
	cases := []struct {
		expr string
		want bool
	}{
		// Non-body request fields are free.
		{`request.method == "GET"`, false},
		{`request.path.startsWith("/gmail")`, false},
		{`size(request.path_segments) > 2`, false},
		{`match.user_id == "me"`, false},
		{`true`, false},
		// Direct, optional, and macro-mediated body selection.
		{`has(request.body)`, true},
		{`request.body.?channel.orValue("") == "general"`, true},
		// Body usage nested inside larger expressions.
		{`request.method == "POST" && has(request.body)`, true},
		{`[request.method, string(request.body.?kind.orValue(""))].size() == 2`, true},
		// Whole-request usage is conservatively body usage.
		{`request == request`, true},
	}
	for _, tc := range cases {
		f, err := NewFilter(env, tc.expr)
		if err != nil {
			t.Errorf("compile %q: %v", tc.expr, err)
			continue
		}
		if got := f.UsesRequestBody(); got != tc.want {
			t.Errorf("UsesRequestBody(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}
