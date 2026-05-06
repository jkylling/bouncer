package compiled

import (
	"testing"
	"time"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	structpb "google.golang.org/protobuf/types/known/structpb"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
)

// testNow is a deterministic timestamp passed as the `now` arg in Eval
// calls. The zero time is fine for tests that don't exercise time-
// dependent expressions; tests that do use a fixed literal locally.
var testNow = time.Time{}

// fixtureRegistry returns a registry with one mail meta and one drive
// meta plus a Complete hook that the tests can observe.
func fixtureRegistry(t *testing.T) (*messages.Registry, *messages.Type) {
	t.Helper()
	r := messages.NewRegistry()
	mail := &messages.Type{
		FullName:     "google.mail.message",
		InputFields:  []string{"id"},
		OutputFields: []string{"sender"},
	}
	require.NoError(t, r.Register(mail))
	require.NoError(t, r.Register(&messages.Type{
		FullName:     "google.drive.file",
		InputFields:  []string{"id"},
		OutputFields: []string{"name"},
	}))
	return r, mail
}

// --- CompiledRequest -------------------------------------------------------

func TestCompiledRequestEvalProducesMetaRequest(t *testing.T) {
	_, mail := fixtureRegistry(t)
	env, err := requestEnv("google.mail", mail)
	require.NoError(t, err)

	cr, err := NewRequest(env, `get("/mail/" + string(input.id))`)
	require.NoError(t, err)

	in, err := buildInput(mail, "id", types.Int(7))
	require.NoError(t, err)
	mr, err := cr.Eval(in)
	require.NoError(t, err)
	assert.Equal(t, "GET", mr.Method)
	assert.Equal(t, "/mail/7", mr.Path)
}

func TestCompiledRequestRejectsNonMetaRequestExpression(t *testing.T) {
	_, mail := fixtureRegistry(t)
	env, err := requestEnv("google.mail", mail)
	require.NoError(t, err)

	_, err = NewRequest(env, `string(input.id)`)
	assert.ErrorContains(t, err, "expected bouncer.MetaRequest")
}

// --- CompiledOutput --------------------------------------------------------

func TestCompiledOutputReadsResponseBody(t *testing.T) {
	r, mail := fixtureRegistry(t)
	env, err := outputEnv("google.mail", mail, r)
	require.NoError(t, err)

	co, err := NewOutput(env, `response.body.sender`)
	require.NoError(t, err)

	in, err := buildInput(mail, "id", types.Int(1))
	require.NoError(t, err)
	body := mustValue(t, map[string]any{"sender": "alice@example"})
	out, err := co.Eval(in, &pb.Request{}, &pb.Response{Body: body})
	require.NoError(t, err)
	assert.Equal(t, "alice@example", out.Value())
}

func TestCompiledOutputProducesMetaValueForTypeLiteral(t *testing.T) {
	r, mail := fixtureRegistry(t)
	env, err := outputEnv("google.mail", mail, r)
	require.NoError(t, err)

	// Returns a *messages.Value built via the FullProvider.
	co, err := NewOutput(env, `drive.file{id: 99}`)
	require.NoError(t, err)

	in, err := buildInput(mail, "id", types.Int(1))
	require.NoError(t, err)
	out, err := co.Eval(in, &pb.Request{}, &pb.Response{})
	require.NoError(t, err)
	v, ok := out.(*messages.Value)
	require.True(t, ok, "expected *messages.Value, got %T", out)
	assert.Equal(t, "google.drive.file", v.MetaType().FullName)
}

// --- CompiledFilter --------------------------------------------------------

func TestCompiledFilterTrueAndFalse(t *testing.T) {
	env, err := filterEnv()
	require.NoError(t, err)

	cf, err := NewFilter(env, `request.path == "/x"`)
	require.NoError(t, err)

	got, err := cf.Eval(&pb.Request{Path: "/x"}, nil)
	require.NoError(t, err)
	assert.True(t, got)

	got, err = cf.Eval(&pb.Request{Path: "/y"}, nil)
	require.NoError(t, err)
	assert.False(t, got)
}

func TestCompiledFilterRejectsNonBool(t *testing.T) {
	env, err := filterEnv()
	require.NoError(t, err)

	_, err = NewFilter(env, `request.path`)
	assert.ErrorContains(t, err, "expected bool")
}

// --- CompiledBind ----------------------------------------------------------

func TestCompiledBindProducesMetaValue(t *testing.T) {
	r, _ := fixtureRegistry(t)
	env, err := bindEnv("google.mail", r)
	require.NoError(t, err)

	cb, err := NewBind(env, `message{id: 11}`)
	require.NoError(t, err)

	v, err := cb.Eval(&pb.Request{Path: "/x"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "google.mail.message", v.MetaType().FullName)
	assert.Equal(t, types.Int(11), v.Get(types.String("id")))
}

func TestCompiledBindRejectsNonMetaResult(t *testing.T) {
	r, _ := fixtureRegistry(t)
	env, err := bindEnv("google.mail", r)
	require.NoError(t, err)

	cb, err := NewBind(env, `1 + 1`)
	require.NoError(t, err)

	_, err = cb.Eval(&pb.Request{}, nil)
	assert.ErrorContains(t, err, "want *messages.Value")
}

// --- CompiledCondition -----------------------------------------------------

func TestCompiledConditionReadsBindAndRequest(t *testing.T) {
	r, _ := fixtureRegistry(t)
	envFactory, err := policyEnv("google.mail", r)
	require.NoError(t, err)

	// Each meta is declared as a plain variable under its full name. The
	// container resolves the bare `message` to `google.mail.message`, so
	// the condition reads fields with the natural shape.
	cp, err := NewCondition(envFactory, `message.sender == "alice" && request.path == "/x"`)
	require.NoError(t, err)

	msg, err := r.NewFullValue("google.mail.message", map[string]ref.Val{
		"id": types.Int(1),
	})
	require.NoError(t, err)
	msg.SetCompleter(func() error {
		msg.SetField("sender", types.String("alice"))
		return nil
	})

	got, err := cp.Eval("get_message", &pb.Request{Path: "/x"}, &pb.Principal{}, testNow,
		map[string]any{"google.mail.message": msg}, nil)
	require.NoError(t, err)
	assert.True(t, got)
}

func TestCompiledConditionRejectsNonBool(t *testing.T) {
	r, _ := fixtureRegistry(t)
	envFactory, err := policyEnv("google.mail", r)
	require.NoError(t, err)

	_, err = NewCondition(envFactory, `request.path`)
	assert.ErrorContains(t, err, "expected bool")
}

func TestCompiledActionPredicate(t *testing.T) {
	env, err := actionPredicateEnv()
	require.NoError(t, err)

	// Empty source compiles as the constant `true`.
	matchAll, err := NewActionPredicate(env, "")
	require.NoError(t, err)
	got, err := matchAll.Eval("anything", &pb.Request{Path: "/x"}, nil, &pb.Principal{}, testNow)
	require.NoError(t, err)
	assert.True(t, got)

	pred, err := NewActionPredicate(env, `action.name in ['a', 'b']`)
	require.NoError(t, err)
	for name, want := range map[string]bool{"a": true, "b": true, "c": false} {
		got, err := pred.Eval(name, &pb.Request{}, nil, &pb.Principal{}, testNow)
		require.NoError(t, err)
		assert.Equal(t, want, got, "action %q", name)
	}

	pred, err = NewActionPredicate(env, `request.path == '/admin'`)
	require.NoError(t, err)
	got, err = pred.Eval("any", &pb.Request{Path: "/admin"}, nil, &pb.Principal{}, testNow)
	require.NoError(t, err)
	assert.True(t, got)

	// `match` flows in, so a predicate can gate by URL captures without
	// firing any binds.
	pred, err = NewActionPredicate(env, `match.user_id == 'me'`)
	require.NoError(t, err)
	got, err = pred.Eval("any", &pb.Request{}, map[string]string{"user_id": "me"}, &pb.Principal{}, testNow)
	require.NoError(t, err)
	assert.True(t, got)
	got, err = pred.Eval("any", &pb.Request{}, map[string]string{"user_id": "alice"}, &pb.Principal{}, testNow)
	require.NoError(t, err)
	assert.False(t, got)
}

// TestCompiledActionPredicateRejectsNilPrincipal pins the runtime
// contract that callers must always pass a principal — same shape as
// the principal predicate's nil-guard, so a stray test caller surfaces
// a clear error rather than a CEL nil-deref.
func TestCompiledActionPredicateRejectsNilPrincipal(t *testing.T) {
	env, err := actionPredicateEnv()
	require.NoError(t, err)
	pred, err := NewActionPredicate(env, "true")
	require.NoError(t, err)

	_, err = pred.Eval("any", &pb.Request{}, nil, nil, testNow)
	assert.ErrorContains(t, err, "principal is required")
}

// TestCompiledConditionRejectsNilPrincipal mirrors the action-predicate
// nil guard for the policy condition.
func TestCompiledConditionRejectsNilPrincipal(t *testing.T) {
	r, _ := fixtureRegistry(t)
	env, err := policyEnv("google.mail", r)
	require.NoError(t, err)
	cond, err := NewCondition(env, "true")
	require.NoError(t, err)

	_, err = cond.Eval("any", &pb.Request{}, nil, testNow, nil, nil)
	assert.ErrorContains(t, err, "principal is required")
}

// --- CompiledPrincipalPredicate -------------------------------------------

func TestCompiledPrincipalPredicateEmptySourceMatchesEveryone(t *testing.T) {
	env, err := principalPredicateEnv()
	require.NoError(t, err)

	pred, err := NewPrincipalPredicate(env, "")
	require.NoError(t, err)

	got, err := pred.Eval(&pb.Request{}, &pb.Principal{}, testNow)
	require.NoError(t, err)
	assert.True(t, got)
}

func TestCompiledPrincipalPredicateGatesBySubject(t *testing.T) {
	env, err := principalPredicateEnv()
	require.NoError(t, err)

	pred, err := NewPrincipalPredicate(env, `principal.subject == "agent-1"`)
	require.NoError(t, err)

	got, err := pred.Eval(&pb.Request{}, &pb.Principal{Subject: "agent-1"}, testNow)
	require.NoError(t, err)
	assert.True(t, got)

	got, err = pred.Eval(&pb.Request{}, &pb.Principal{Subject: "agent-2"}, testNow)
	require.NoError(t, err)
	assert.False(t, got)
}

func TestCompiledPrincipalPredicateRejectsNilPrincipal(t *testing.T) {
	env, err := principalPredicateEnv()
	require.NoError(t, err)

	pred, err := NewPrincipalPredicate(env, "true")
	require.NoError(t, err)

	_, err = pred.Eval(&pb.Request{}, nil, testNow)
	assert.ErrorContains(t, err, "principal is required")
}

func TestCompiledPrincipalPredicateRejectsNonBool(t *testing.T) {
	env, err := principalPredicateEnv()
	require.NoError(t, err)

	_, err = NewPrincipalPredicate(env, `principal.subject`)
	assert.ErrorContains(t, err, "expected bool")
}

// --- helpers ---------------------------------------------------------------

// buildInput constructs an input-view *messages.Value of t holding a
// single field. Allocates a fresh side registry so the helper works
// regardless of whether t is already registered in the test's main
// registry.
func buildInput(t *messages.Type, key string, val ref.Val) (*messages.Value, error) {
	r := messages.NewRegistry()
	clone := *t
	if err := r.Register(&clone); err != nil {
		return nil, err
	}
	return r.NewInputValue(t.FullName, map[string]ref.Val{key: val})
}

func mustValue(t *testing.T, v any) *structpb.Value {
	t.Helper()
	out, err := structpb.NewValue(v)
	require.NoError(t, err)
	return out
}
