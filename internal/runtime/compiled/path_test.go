package compiled

import (
	"reflect"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
)

func TestSplitPathPreservesEmptySegments(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/users/me", []string{"users", "me"}},
		{"/users//me", []string{"users", "", "me"}},
		{"/users/me/", []string{"users", "me", ""}},
		{"//users/me", []string{"", "users", "me"}},
		{"/", nil},
		{"", nil},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := SplitPath(c.in); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("SplitPath(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// A `//` in the request shows up as an empty segment, so a template
// that doesn't have one in the same position fails the length/literal
// check and returns no match. That's the security property that used
// to be enforced by rejecting `//` at the server boundary.
func TestPathTemplate_DoubleSlashDoesNotCollapse(t *testing.T) {
	tpl, err := ParsePathTemplate("GET", "/users/{user}/profile")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	req := newReq("GET", "/users//42/profile", SplitPath("/users//42/profile"))
	if _, ok := tpl.Match(req); ok {
		t.Fatalf("template should not match `//` request")
	}
}

func newReq(method, path string, segs []string) *pb.Request {
	return &pb.Request{Method: method, Path: path, PathSegments: segs}
}

func TestParsePathTemplate_AllLiteral(t *testing.T) {
	tpl, err := ParsePathTemplate("POST", "/v1/users/me/messages:send")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, ok := tpl.Match(newReq("POST", "/v1/users/me/messages:send",
		[]string{"v1", "users", "me", "messages:send"}))
	if !ok {
		t.Fatal("expected match")
	}
	if len(got) != 0 {
		t.Errorf("expected no params, got %v", got)
	}
}

func TestParsePathTemplate_Params(t *testing.T) {
	tpl, err := ParsePathTemplate("get", "/v1/users/{user_id}/messages/{message_id}")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, ok := tpl.Match(newReq("GET", "/v1/users/abc/messages/def",
		[]string{"v1", "users", "abc", "messages", "def"}))
	if !ok {
		t.Fatal("expected match")
	}
	if got["user_id"] != "abc" || got["message_id"] != "def" {
		t.Errorf("captures = %v, want user_id=abc message_id=def", got)
	}
	if names := tpl.ParamNames(); len(names) != 2 || names[0] != "user_id" || names[1] != "message_id" {
		t.Errorf("ParamNames = %v", names)
	}
}

func TestPathTemplate_MethodMismatch(t *testing.T) {
	tpl, _ := ParsePathTemplate("GET", "/v1/users/{id}")
	_, ok := tpl.Match(newReq("POST", "/v1/users/abc", []string{"v1", "users", "abc"}))
	if ok {
		t.Fatal("expected no match for wrong method")
	}
}

func TestPathTemplate_LengthMismatch(t *testing.T) {
	tpl, _ := ParsePathTemplate("GET", "/v1/users/{id}")
	_, ok := tpl.Match(newReq("GET", "/v1/users/abc/extra", []string{"v1", "users", "abc", "extra"}))
	if ok {
		t.Fatal("expected no match for extra segment")
	}
}

func TestPathTemplate_LiteralMismatch(t *testing.T) {
	tpl, _ := ParsePathTemplate("GET", "/v1/users/{id}")
	_, ok := tpl.Match(newReq("GET", "/v1/groups/abc", []string{"v1", "groups", "abc"}))
	if ok {
		t.Fatal("expected literal mismatch")
	}
}

func TestPathTemplate_ColonInLiteralIsLiteral(t *testing.T) {
	// Google-style `:method` lives mid-segment, not at the start of a
	// segment as `{...}`-style would be — so it stays literal.
	tpl, err := ParsePathTemplate("POST", "/v4/spreadsheets/{id}/values:batchGet")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, ok := tpl.Match(newReq("POST", "/v4/spreadsheets/x/values:batchGet",
		[]string{"v4", "spreadsheets", "x", "values:batchGet"}))
	if !ok || got["id"] != "x" {
		t.Fatalf("match=%v ok=%v", got, ok)
	}
}

func TestParsePathTemplate_Errors(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		path        string
		errContains string
	}{
		{"empty method", "", "/v1/x", "method is empty"},
		{"empty path", "GET", "", "path is empty"},
		{"no segments", "GET", "/", "no segments"},
		{"duplicate param", "GET", "/v1/{id}/x/{id}", "duplicate param"},
		{"invalid identifier", "GET", "/v1/{1bad}", "invalid param segment"},
		{"empty braces", "GET", "/v1/{}", "invalid param segment"},
		{"unclosed brace", "GET", "/v1/{user_id", "unmatched brace"},
		{"unopened brace", "GET", "/v1/user_id}", "unmatched brace"},
		{"stray open", "GET", "/v1/{", "unmatched brace"},
		{"mid-segment brace", "GET", "/v1/{id}:enable", "unmatched brace"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePathTemplate(c.method, c.path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), c.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), c.errContains)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
