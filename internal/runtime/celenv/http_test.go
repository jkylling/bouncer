package celenv

import (
	"testing"

	"github.com/google/cel-go/cel"

	pb "github.com/jkylling/bouncer/internal/pb"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

func evalToMetaRequest(t *testing.T, expr string) *pb.MetaRequest {
	t.Helper()
	// HTTP helpers are only registered in the Request env (which needs a
	// meta to bind `input`). For testing the helpers themselves we build
	// a minimal env that just exposes the helpers and proto types.
	opts := append(LanguageOptions(),
		HTTPHelpers(),
		cel.CustomTypeProvider(NewProtoRegistry()),
	)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		t.Fatalf("env: %v", err)
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		t.Fatalf("compile: %v", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program: %v", err)
	}
	out, _, err := prg.Eval(map[string]any{})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	mr, ok := out.Value().(*pb.MetaRequest)
	if !ok {
		t.Fatalf("expected *pb.MetaRequest, got %T", out.Value())
	}
	return mr
}

func TestGetHelperHasNoBody(t *testing.T) {
	mr := evalToMetaRequest(t, `get('/v1/users/42')`)
	if mr.GetMethod() != "GET" {
		t.Errorf("method: %s", mr.GetMethod())
	}
	if mr.GetPath() != "/v1/users/42" {
		t.Errorf("path: %s", mr.GetPath())
	}
	if mr.GetBody() != nil {
		t.Errorf("body should be nil, got %v", mr.GetBody())
	}
}

func TestPostWithStringBody(t *testing.T) {
	mr := evalToMetaRequest(t, `post('/p', 'hello')`)
	if mr.GetBody().GetStringValue() != "hello" {
		t.Errorf("body: %v", mr.GetBody())
	}
}

func TestPostWithIntBody(t *testing.T) {
	mr := evalToMetaRequest(t, `post('/p', 42)`)
	if mr.GetBody().GetNumberValue() != 42 {
		t.Errorf("body: %v", mr.GetBody())
	}
}

func TestPostWithBoolBody(t *testing.T) {
	mr := evalToMetaRequest(t, `post('/p', true)`)
	if mr.GetBody().GetBoolValue() != true {
		t.Errorf("body: %v", mr.GetBody())
	}
}

// post('/x', null) yields a MetaRequest whose body wrapper is non-nil
// but holds a NullValue. apiclient detects the body via `req.GetBody()
// != nil`, so this case follows the "body present" path and serialises
// a literal `null` upstream.
func TestPostWithNullBody(t *testing.T) {
	mr := evalToMetaRequest(t, `post('/p', null)`)
	if mr.GetBody() == nil {
		t.Fatalf("body wrapper should be non-nil for explicit null")
	}
	if _, ok := mr.GetBody().GetKind().(*structpb.Value_NullValue); !ok {
		t.Errorf("body kind = %T, want NullValue", mr.GetBody().GetKind())
	}
}

func TestPostWithListBody(t *testing.T) {
	mr := evalToMetaRequest(t, `post('/p', ['a', 'b', 'c'])`)
	list := mr.GetBody().GetListValue()
	if list == nil || len(list.Values) != 3 {
		t.Fatalf("expected list of 3, got %v", mr.GetBody())
	}
}

func TestPostWithMapBody(t *testing.T) {
	mr := evalToMetaRequest(t, `post('/v1/users', {'name': 'alice', 'tags': ['a', 'b'], 'age': 30})`)
	if mr.GetMethod() != "POST" {
		t.Errorf("method: %s", mr.GetMethod())
	}
	body := mr.GetBody().GetStructValue()
	if body == nil {
		t.Fatalf("body should be Struct, got %v", mr.GetBody())
	}
	if body.Fields["name"].GetStringValue() != "alice" {
		t.Errorf("name: %v", body.Fields["name"])
	}
	if body.Fields["age"].GetNumberValue() != 30 {
		t.Errorf("age: %v", body.Fields["age"])
	}
	tags, ok := body.Fields["tags"].GetKind().(*structpb.Value_ListValue)
	if !ok || len(tags.ListValue.Values) != 2 {
		t.Errorf("tags: %v", body.Fields["tags"])
	}
}

// TestRejectsDotSegmentTraversal pins the path-spoofing fix.
// apiclient.JoinPath is byte-faithful for forward-path semantics —
// it forwards `..` segments verbatim, and the upstream then RFC
// 3986 §5.2.4-normalises them. A policy condition that interpolates
// caller-controlled bytes into a CEL `request:` expression must not
// be allowed to drive that normalisation, or it will reach a
// different resource than the policy gate evaluated.
func TestMetaRequestRejectsDotSegmentTraversal(t *testing.T) {
	cases := []string{
		`get('/users/../admin')`,
		`get('/users/./me')`,
		`get('/a/b/../c')`,
		`get('..')`,
		`get('/foo/..?x=1')`,
		`post('/users/../admin', 'payload')`,
	}
	opts := append(LanguageOptions(),
		HTTPHelpers(),
		cel.CustomTypeProvider(NewProtoRegistry()),
	)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		t.Fatalf("env: %v", err)
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			ast, iss := env.Compile(expr)
			if iss.Err() != nil {
				t.Fatalf("compile: %v", iss.Err())
			}
			prg, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program: %v", err)
			}
			out, _, err := prg.Eval(map[string]any{})
			if err != nil {
				return // CEL surfaced the error directly — also acceptable.
			}
			// CEL helpers may surface the error as a *types.Err
			// rather than a Go error; check the value too.
			if _, ok := out.Value().(*pb.MetaRequest); ok {
				t.Errorf("%s: expected error, got valid MetaRequest", expr)
			}
		})
	}
}

// TestMetaRequestPercentEscapedDotSegmentSurvives pins the operator
// escape hatch: a policy that genuinely needs `..` in a URL component
// can percent-encode it and the validator will leave it alone — so
// will the upstream's normaliser, since `%2E%2E` is not a dot-segment
// per RFC 3986.
func TestMetaRequestPercentEscapedDotSegmentSurvives(t *testing.T) {
	mr := evalToMetaRequest(t, `get('/files/abc%2E%2E')`)
	if mr.GetPath() != "/files/abc%2E%2E" {
		t.Errorf("path = %q, want literal %%2E%%2E preserved", mr.GetPath())
	}
}
