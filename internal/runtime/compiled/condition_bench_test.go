package compiled

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
)

// Benchmarks for CompiledCondition.Eval. After the decorator-based
// refactor, NewCondition builds one shared (env, program) and Eval
// just runs prg.Eval with a fresh activation, so these benchmarks
// double as a regression check that we keep the shared-program
// performance characteristics. Run with:
//
//	go test -bench=BenchmarkCondition -benchmem -run=^$ ./internal/compiled
//
// Production constraints honoured by every benchmark:
//
//   - Each iteration pays for one fresh activation (production
//     CompiledCondition.Eval allocates one per call).
//   - Bind values are pre-allocated outside the timed region; their
//     construction belongs to CompiledBind, not CompiledCondition,
//     and the SetCompleter contract makes them one-shot.

// benchPolicyEnv builds the policy env used across the benchmarks: the
// standard google.mail container, one bind variable `msg` typed as the
// mail message meta, and a sibling drive.file meta for the inline-Type
// bench.
func benchPolicyEnv(b *testing.B) (*messages.Registry, *cel.Env) {
	b.Helper()
	r := messages.NewRegistry()
	for _, t := range []*messages.Type{
		{FullName: "google.mail.message", InputFields: []string{"id"}, OutputFields: []string{"sender"}},
		{FullName: "google.drive.file", InputFields: []string{"id"}, OutputFields: []string{"name"}},
	} {
		if err := r.Register(t); err != nil {
			b.Fatalf("register %s: %v", t.FullName, err)
		}
	}
	env, err := policyEnv("google.mail", r)
	if err != nil {
		b.Fatalf("policyEnv: %v", err)
	}
	return r, env
}

// preallocBoundMessages returns n fresh bound message values, each
// with a one-shot completer that sets sender = "alice". The benches
// consume one per iteration; pre-allocating outside the timed region
// avoids the b.StopTimer/StartTimer overhead that distorts short
// benchmarks (each toggle costs ~30-100ns).
func preallocBoundMessages(b *testing.B, r *messages.Registry, n int) []*messages.Value {
	b.Helper()
	out := make([]*messages.Value, n)
	for i := range out {
		v, err := r.NewFullValue("google.mail.message", map[string]ref.Val{
			"id": types.Int(1),
		})
		if err != nil {
			b.Fatalf("NewFullValue: %v", err)
		}
		v.SetCompleter(func() error {
			v.SetField("sender", types.String("alice"))
			return nil
		})
		out[i] = v
	}
	return out
}

// BenchmarkConditionEvalSimple measures the full CompiledCondition.Eval
// path on a condition that reads only the request — no bind, no inline
// Type literal. This is the production cost for a "plain" policy
// condition.
func BenchmarkConditionEvalSimple(b *testing.B) {
	_, env := benchPolicyEnv(b)
	cc, err := NewCondition(env, `request.path == "/x"`)
	if err != nil {
		b.Fatalf("NewCondition: %v", err)
	}
	req := &pb.Request{Path: "/x"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cc.Eval("a", req, &pb.Principal{}, testNow, nil, nil); err != nil {
			b.Fatalf("Eval: %v", err)
		}
	}
}

// BenchmarkConditionEvalBindRead measures the full Eval path on a
// condition that reads a bind value's output field. Each iteration
// consumes one pre-built bind value (construction is the bind layer's
// responsibility, not the condition's). The bind variable is exposed
// as the meta type itself so the condition reads `.sender` directly.
func BenchmarkConditionEvalBindRead(b *testing.B) {
	r, env := benchPolicyEnv(b)
	cc, err := NewCondition(env, `message.sender == "alice"`)
	if err != nil {
		b.Fatalf("NewCondition: %v", err)
	}
	req := &pb.Request{}
	binds := preallocBoundMessages(b, r, b.N)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cc.Eval("a", req, &pb.Principal{}, testNow, map[string]any{
			"google.mail.message": binds[i],
		}, nil); err != nil {
			b.Fatalf("Eval: %v", err)
		}
	}
}

// BenchmarkConditionEvalInlineType measures the full Eval path on a
// condition that constructs an inline Type{...} literal. The reference
// stays on `.id` (an input field) so the installer fires but no
// completer runs — isolating CEL construction + provider routing from
// any upstream-fetch cost.
func BenchmarkConditionEvalInlineType(b *testing.B) {
	_, env := benchPolicyEnv(b)
	cc, err := NewCondition(env, `drive.file{id: 1}.id == 1`)
	if err != nil {
		b.Fatalf("NewCondition: %v", err)
	}
	req := &pb.Request{}
	installer := func(*messages.Value) {}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cc.Eval("a", req, &pb.Principal{}, testNow, nil, installer); err != nil {
			b.Fatalf("Eval: %v", err)
		}
	}
}
