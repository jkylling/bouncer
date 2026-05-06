package compiled

import (
	"context"
	"time"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// FetchObserver fires once per upstream side call made by a meta
// completer. metaName is the meta type's full name; apiName is the
// meta's resolver key. err is whatever api.Call returned: nil on
// success, otherwise either a transport error or a typed upstream
// status that callers can extract with errors.As.
//
// Implementations must be safe to invoke from the evaluation
// goroutine; the runtime never invokes them concurrently for one
// request. Calls fire in completer order, which matches the order
// the policy condition walked into output fields — a chain like
// .parent.parent appears as three sequential entries.
type FetchObserver func(metaName, apiName string, mr *pb.MetaRequest, resp *pb.Response, err error, latency time.Duration)

// FiringObserver fires the first time a policy condition returns
// true. actionName and policyName carry the firing pair; binds is
// the resolved bind list as the policy saw it. The runtime invokes
// this at most once per Evaluate.
type FiringObserver func(actionName, policyName string, binds []BoundValue)

// ConditionEvalObserver fires once per (policy, action) condition
// evaluation, regardless of outcome. result is the policy's declared
// outcome (i.e. what would happen if its condition fires). fired is
// true when the condition returned true; condErr is the eval error,
// if any. Use for traffic capture so the viewer can show the full
// list of policies that ran for one request — the runtime breaks
// out of the loop on the first fired=true, so the deciding policy
// is the last entry.
type ConditionEvalObserver func(actionName, policyName string, result models.PolicyResult, fired bool, condErr error)

type fetchKey struct{}
type firingKey struct{}
type condEvalKey struct{}

// WithFetchObserver returns a context that carries obs. The meta
// completer reads the observer off ctx and fires it after every
// upstream call. Pass nil to clear an observer attached upstream.
func WithFetchObserver(ctx context.Context, obs FetchObserver) context.Context {
	return context.WithValue(ctx, fetchKey{}, obs)
}

// WithFiringObserver returns a context that carries obs. The
// runtime reads the observer off ctx and fires it the moment a
// policy condition fires. Pass nil to clear.
func WithFiringObserver(ctx context.Context, obs FiringObserver) context.Context {
	return context.WithValue(ctx, firingKey{}, obs)
}

// WithConditionEvalObserver returns a context that carries obs. The
// runtime reads it off ctx and fires it after every (policy, action)
// condition evaluation. Pass nil to clear.
func WithConditionEvalObserver(ctx context.Context, obs ConditionEvalObserver) context.Context {
	return context.WithValue(ctx, condEvalKey{}, obs)
}

// FetchObserverFrom returns the fetch observer attached to ctx, or
// nil when none is attached.
func FetchObserverFrom(ctx context.Context) FetchObserver {
	obs, _ := ctx.Value(fetchKey{}).(FetchObserver)
	return obs
}

// FiringObserverFrom returns the firing observer attached to ctx,
// or nil when none is attached.
func FiringObserverFrom(ctx context.Context) FiringObserver {
	obs, _ := ctx.Value(firingKey{}).(FiringObserver)
	return obs
}

// ConditionEvalObserverFrom returns the condition-eval observer
// attached to ctx, or nil when none is attached.
func ConditionEvalObserverFrom(ctx context.Context) ConditionEvalObserver {
	obs, _ := ctx.Value(condEvalKey{}).(ConditionEvalObserver)
	return obs
}
