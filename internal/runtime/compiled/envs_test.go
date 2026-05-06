package compiled

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
)

// twoMetaRegistry returns a registry pre-populated with two metas under
// distinct API packages, matching the cross-API scenario the new envs
// must support.
func twoMetaRegistry(t *testing.T) *messages.Registry {
	t.Helper()
	r := messages.NewRegistry()
	require.NoError(t, r.Register(&messages.Type{
		FullName:     "google.mail.message",
		InputFields:  []string{"id"},
		OutputFields: []string{"sender"},
	}))
	require.NoError(t, r.Register(&messages.Type{
		FullName:     "google.drive.file",
		InputFields:  []string{"id"},
		OutputFields: []string{"name"},
	}))
	return r
}

// --- Request env -----------------------------------------------------------

func TestRequestEnvCompilesInputAccess(t *testing.T) {
	reg := twoMetaRegistry(t)
	mail, _ := reg.Get("google.mail.message")
	env, err := requestEnv("google.mail", mail)
	require.NoError(t, err)

	_, iss := env.Compile("input.id")
	require.NoError(t, iss.Err())
}

func TestRequestEnvCompilesGetHelper(t *testing.T) {
	reg := twoMetaRegistry(t)
	mail, _ := reg.Get("google.mail.message")
	env, err := requestEnv("google.mail", mail)
	require.NoError(t, err)

	// `get(string(input.id))` is the canonical request expression shape.
	ast, iss := env.Compile(`get(string(input.id))`)
	require.NoError(t, iss.Err())
	assert.Equal(t, "bouncer.MetaRequest", ast.OutputType().String())
}

func TestRequestEnvBlocksOtherMetas(t *testing.T) {
	reg := twoMetaRegistry(t)
	mail, _ := reg.Get("google.mail.message")
	env, err := requestEnv("google.mail", mail)
	require.NoError(t, err)

	// `drive.file` would resolve under the FullProvider, but RequestProvider
	// only knows the input view of the current meta.
	_, iss := env.Compile(`drive.file{id: 1}.id`)
	assert.Error(t, iss.Err(), "drive.file must not be visible inside a request env")
}

func TestRequestEnvBlocksOutputFieldAccess(t *testing.T) {
	reg := twoMetaRegistry(t)
	mail, _ := reg.Get("google.mail.message")
	env, err := requestEnv("google.mail", mail)
	require.NoError(t, err)

	// `sender` is an output field; the input view doesn't expose it.
	_, iss := env.Compile("input.sender")
	assert.Error(t, iss.Err())
}

// --- Output env ------------------------------------------------------------

func TestOutputEnvHasInputRequestResponse(t *testing.T) {
	reg := twoMetaRegistry(t)
	mail, _ := reg.Get("google.mail.message")
	env, err := outputEnv("google.mail", mail, reg)
	require.NoError(t, err)

	for _, src := range []string{
		"input.id",
		"request.path",
		"response.body",
	} {
		_, iss := env.Compile(src)
		assert.NoErrorf(t, iss.Err(), "compiling %q", src)
	}
}

func TestOutputEnvAllowsCrossApiTypeLiteral(t *testing.T) {
	reg := twoMetaRegistry(t)
	mail, _ := reg.Get("google.mail.message")
	env, err := outputEnv("google.mail", mail, reg)
	require.NoError(t, err)

	// Inside google.mail container, `drive.file{...}` resolves to
	// google.drive.file via cel-go's ancestor search.
	_, iss := env.Compile(`drive.file{id: response.body.id}`)
	assert.NoError(t, iss.Err())
}

// --- Filter env ------------------------------------------------------------

func TestFilterEnvHasOnlyRequest(t *testing.T) {
	env, err := filterEnv()
	require.NoError(t, err)

	_, iss := env.Compile(`request.path == "/x"`)
	require.NoError(t, iss.Err())
}

func TestFilterEnvBlocksMetaAccess(t *testing.T) {
	env, err := filterEnv()
	require.NoError(t, err)

	_, iss := env.Compile(`google.mail.message{id: 1}.sender`)
	assert.Error(t, iss.Err(), "filter env must not expose meta types")
}

// --- Bind env --------------------------------------------------------------

func TestBindEnvAllowsTypeLiteralViaContainer(t *testing.T) {
	reg := twoMetaRegistry(t)
	env, err := bindEnv("google.mail", reg)
	require.NoError(t, err)

	// container = google.mail, so `message{id: ...}` resolves to
	// google.mail.message.
	_, iss := env.Compile(`message{id: request.path}`)
	require.NoError(t, iss.Err())
}

func TestBindEnvAllowsCrossAPI(t *testing.T) {
	reg := twoMetaRegistry(t)
	env, err := bindEnv("google.mail", reg)
	require.NoError(t, err)

	// `drive.file{...}` from inside google.mail resolves to google.drive.file.
	_, iss := env.Compile(`drive.file{id: request.path}`)
	require.NoError(t, iss.Err())
}

// --- Policy env ------------------------------------------------------------

func TestPolicyEnvDeclaresEveryMeta(t *testing.T) {
	reg := twoMetaRegistry(t)
	env, err := policyEnv("google.mail", reg)
	require.NoError(t, err)

	// Bare `message` resolves to google.mail.message via the container
	// ancestor search and reads its fields directly.
	_, iss := env.Compile(`message.sender == "alice@example"`)
	require.NoError(t, iss.Err())
}

// TestPolicyEnvLeafResolvesToVariableNotType pins the variable-vs-
// type precedence under cel.Container. With both a registered type
// `google.mail.message` and a variable of the same qualified name,
// the bare identifier `message` must resolve to the *variable* (so
// field selection works against the bound value) rather than the
// *type* (which would fail with "type does not support field
// selection"). Today this works because the variable is declared at
// the full qualified name — see policyEnv. A cel-go upgrade that
// flips that precedence breaks every policy in the bundle and this
// is the only test that would catch it.
func TestPolicyEnvLeafResolvesToVariableNotType(t *testing.T) {
	reg := twoMetaRegistry(t)
	env, err := policyEnv("google.mail", reg)
	require.NoError(t, err)

	// `message` resolves under container ancestor search to
	// `google.mail.message`. With a variable declared there it must
	// be field-selectable. Compiling proves the resolver picked the
	// variable; eval double-checks by reading a real field.
	ast, iss := env.Compile(`message.sender`)
	require.NoError(t, iss.Err())
	prg, err := env.Program(ast)
	require.NoError(t, err)

	msgVal, err := reg.NewFullValue("google.mail.message", map[string]ref.Val{"id": types.Int(1)})
	require.NoError(t, err)
	msgVal.SetCompleter(func() error {
		msgVal.SetField("sender", types.String("alice"))
		return nil
	})
	out, _, err := prg.Eval(map[string]any{
		"google.mail.message": msgVal,
		// google.drive.file is declared in the env but unreferenced here:
		// the resolution mechanic must not depend on which meta is in
		// the source expression. Reviewer's specific defensive ask.
		"request": &pb.Request{},
		"action":  map[string]any{"name": "any"},
	})
	require.NoError(t, err)
	assert.Equal(t, "alice", out.Value())
}

// --- Principal-aware envs --------------------------------------------------

func TestPrincipalPredicateEnvResolvesPrincipal(t *testing.T) {
	env, err := principalPredicateEnv()
	require.NoError(t, err)

	_, iss := env.Compile(`principal.subject == "agent-1"`)
	require.NoError(t, iss.Err())
}

func TestActionPredicateEnvResolvesPrincipal(t *testing.T) {
	env, err := actionPredicateEnv()
	require.NoError(t, err)

	_, iss := env.Compile(`principal.subject == "agent-1"`)
	require.NoError(t, iss.Err())
}

func TestPolicyEnvResolvesPrincipal(t *testing.T) {
	reg := twoMetaRegistry(t)
	env, err := policyEnv("google.mail", reg)
	require.NoError(t, err)

	_, iss := env.Compile(`principal.subject == "agent-1"`)
	require.NoError(t, iss.Err())
}

func TestPolicyEnvCanEvaluateAcrossBindAndRequest(t *testing.T) {
	reg := twoMetaRegistry(t)
	env, err := policyEnv("google.mail", reg)
	require.NoError(t, err)

	ast, iss := env.Compile(`message.sender == "alice" && request.path == "/x"`)
	require.NoError(t, iss.Err())
	prg, err := env.Program(ast)
	require.NoError(t, err)

	msgVal, err := reg.NewFullValue("google.mail.message", map[string]ref.Val{"id": types.Int(1)})
	require.NoError(t, err)
	msgVal.SetCompleter(func() error {
		msgVal.SetField("sender", types.String("alice"))
		return nil
	})

	out, _, err := prg.Eval(map[string]any{
		"google.mail.message": msgVal,
		"request":             &pb.Request{Path: "/x"},
		"action":              map[string]any{"name": "any"},
	})
	require.NoError(t, err)
	assert.Equal(t, true, out.Value())
}
