package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	structpb "google.golang.org/protobuf/types/known/structpb"

	pb "github.com/jkylling/bouncer/internal/pb"

	"github.com/jkylling/bouncer/internal/apiclient"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Recorder is the optional per-request observer the proxy hands one
// Event to after each inbound request finishes. The interface lives
// here, not in the traffic package, so the server's only dependency
// on traffic is the Event payload type — a hot-path call out of
// `handle` does not transitively pull in the sqlite driver.
//
// Implementations must be non-blocking. The recorder is best-effort:
// the proxy never waits on a slow store. `*traffic.AsyncRecorder`
// satisfies this interface and is what cmd/bouncer wires up;
// tests use small fakes.
type Recorder interface {
	Record(ctx context.Context, ev traffic.Event)
}

// recorderHook is the per-request capture state. The handle path
// populates fields as it learns them — subject after authenticate,
// api/decision after evaluate, status after forward — and a deferred
// `commit` builds the Event and hands it to the recorder.
//
// The hook also serves as the runtime's observer sink: it implements
// the FetchObserver / FiringObserver callbacks, so the runtime layer
// stays free of recorder data shapes and of *structpb.Value
// serialization. The translation from raw runtime types into
// traffic.MetaFetch / traffic.ResolvedBind happens here.
type recorderHook struct {
	// rec is nil when the server was constructed without a recorder;
	// commit short-circuits in that case so the hook stays a zero-cost
	// optional.
	rec Recorder

	id       traffic.EventID
	started  time.Time
	method   string
	url      string
	headers  []traffic.KV
	subject  string
	api      string
	decision traffic.Decision

	// Firing-policy snapshot. Populated by onFiring when a policy
	// condition first returns true; left zero on the deny-by-default
	// path. binds carries the firing action's bound values so commit
	// can serialise them at the same instant as the rest of the
	// event.
	action  string
	policy  string
	binds   []compiled.BoundValue
	fetches []traffic.MetaFetch

	// policyEvals captures every (policy, action) condition the
	// runtime ran for this request, in order. Populated by
	// onConditionEval; the deciding policy is the last entry with
	// Fired=true (or absent on a default-deny).
	policyEvals []traffic.PolicyEvaluation

	// forwardedStatus is the upstream status code captured the
	// instant the upstream response is received. Populated only on
	// the happy path (decision = permit, forward did not fail).
	// Distinct from the response writer's status — the proxy may
	// still write a 502 over the top after a body-stream stall.
	forwardedStatus int
	forwarded       bool

	errMsg string
}

// newRecorderHook seeds the per-request state. Cheap — the only
// allocation is the small headers slice, and only when a recorder is
// configured.
func (s *Server) newRecorderHook(r *http.Request) *recorderHook {
	if s.recorder == nil {
		return &recorderHook{} // commit is a no-op
	}
	return &recorderHook{
		rec:      s.recorder,
		id:       traffic.NewEventID(),
		started:  time.Now(),
		method:   r.Method,
		url:      sanitizeURL(r.URL.RequestURI()),
		headers:  cloneRequestHeaders(r.Header),
		decision: traffic.DecisionError, // overwritten on success paths
	}
}

// attachObservers returns ctx augmented with the hook's runtime
// observers. Called by handle just before Evaluate so meta side
// calls and policy firings flow back here for capture. Safe on a
// nil-rec hook — returns ctx unchanged.
func (h *recorderHook) attachObservers(ctx context.Context) context.Context {
	if h == nil || h.rec == nil {
		return ctx
	}
	ctx = compiled.WithFetchObserver(ctx, h.onFetch)
	ctx = compiled.WithFiringObserver(ctx, h.onFiring)
	ctx = compiled.WithConditionEvalObserver(ctx, h.onConditionEval)
	return ctx
}

// onFetch is the FetchObserver implementation. Translates the raw
// runtime types into the traffic.MetaFetch wire shape (status code
// peeled from any apiclient.UpstreamError; structpb.Value bodies
// rendered through json.Marshal). Pinning the success status to 200
// matches apiclient.HTTPAPI.Call's contract: a non-error return
// implies a 2xx response.
func (h *recorderHook) onFetch(meta, apiName string, mr *pb.MetaRequest, resp *pb.Response, callErr error, latency time.Duration) {
	f := traffic.MetaFetch{
		Meta:        meta,
		API:         apiName,
		Method:      mr.GetMethod(),
		Path:        mr.GetPath(),
		RequestBody: marshalStructpb(mr.GetBody()),
		LatencyMS:   latency.Milliseconds(),
	}
	if callErr == nil {
		f.Status = http.StatusOK
		f.ResponseBody = marshalStructpb(resp.GetBody())
	} else {
		f.Error = callErr.Error()
		var ue *apiclient.UpstreamError
		if errors.As(callErr, &ue) {
			f.Status = ue.Status
		}
	}
	h.fetches = append(h.fetches, f)
}

// onFiring captures the (action, policy, binds) tuple the moment
// the runtime sees a policy condition return true. Called at most
// once per request.
func (h *recorderHook) onFiring(action, policy string, binds []compiled.BoundValue) {
	h.action = action
	h.policy = policy
	h.binds = binds
}

// onConditionEval appends one (policy, action, result, fired) entry
// to the per-request evaluation trace. Fires once per condition the
// runtime evaluated, regardless of outcome — the runtime breaks out
// on the first fired=true so the deciding policy is always the last
// entry.
func (h *recorderHook) onConditionEval(action, policy string, result models.PolicyResult, fired bool, evalErr error) {
	entry := traffic.PolicyEvaluation{
		Policy: policy,
		Action: action,
		Result: string(result),
		Fired:  fired,
	}
	if evalErr != nil {
		entry.Error = evalErr.Error()
	}
	h.policyEvals = append(h.policyEvals, entry)
}

// commit hands the assembled Event to the recorder. Safe to call on
// a nil-rec hook — the function returns immediately.
//
// no_match decisions are dropped on the floor: those are paths no
// API claimed (favicon.ico, robots.txt, typo'd URLs) and persisting
// them would burn the byte budget on traffic that never touched a
// policy. Auth failures and eval errors *do* land — they are signal
// the operator wants to see.
func (h *recorderHook) commit(ctx context.Context) {
	if h == nil || h.rec == nil {
		return
	}
	if h.decision == traffic.DecisionNoMatch {
		return
	}
	upstream := 0
	if h.forwarded {
		upstream = h.forwardedStatus
	}
	ev := traffic.Event{
		ID:                h.id,
		Timestamp:         h.started.UTC(),
		Subject:           h.subject,
		Method:            h.method,
		URL:               h.url,
		RequestHeaders:    h.headers,
		API:               h.api,
		Decision:          h.decision,
		Action:            h.action,
		Policy:            h.policy,
		Binds:             encodeBinds(ctx, h.binds),
		MetaFetches:       h.fetches,
		PolicyEvaluations: h.policyEvals,
		UpstreamStatus:    upstream,
		LatencyMS:         time.Since(h.started).Milliseconds(),
		Error:             h.errMsg,
	}
	h.rec.Record(ctx, ev)
}

// encodeBinds serialises each bound *messages.Value to JSON for
// persistence. The recorder is best-effort: a marshal failure logs
// at WARN and the entry is dropped from the captured slice rather
// than failing the request. Empty in arrives as nil out so the JSON
// `binds` field stays omitted via omitempty.
func encodeBinds(ctx context.Context, in []compiled.BoundValue) []traffic.ResolvedBind {
	if len(in) == 0 {
		return nil
	}
	out := make([]traffic.ResolvedBind, 0, len(in))
	for _, b := range in {
		raw, err := json.Marshal(b.Value)
		if err != nil {
			slog.WarnContext(ctx, "traffic: marshal bind", "meta", b.Name, "err", err)
			continue
		}
		out = append(out, traffic.ResolvedBind{Name: b.Name, Value: raw})
	}
	return out
}

// marshalStructpb renders a *structpb.Value as JSON. structpb.Value
// already implements json.Marshaler (via protojson), so encoding/json
// produces the same canonical shape the upstream JSON had — no
// manual lowering needed. nil input yields nil bytes so callers can
// distinguish "no body" from "empty body". Marshal errors yield nil
// too: the observability layer is best-effort and must not break
// the request path. Typed *structpb.Value parameter avoids the
// interface-wraps-nil-pointer trap that would otherwise treat a
// nil-bodied request as a non-nil interface.
func marshalStructpb(v *structpb.Value) []byte {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

// cloneRequestHeaders converts an http.Header into a deterministic
// []traffic.KV the Event format wants. The clone keeps the recorder
// independent of the request's lifetime — the http server is free to
// recycle the Header map after handle returns.
//
// Credential-bearing headers are stripped up front so a JWT or
// session cookie never sits in the Event struct on the buffered
// recorder channel. Sanitize on the writer side does the same strip
// for defence in depth, but doing it here means a heap snapshot
// taken between Record and write contains no plaintext bearer.
//
// Output is sorted by lower-cased key (then value) so the order is
// stable across map iterations and across runs.
func cloneRequestHeaders(h http.Header) []traffic.KV {
	if len(h) == 0 {
		return nil
	}
	out := make([]traffic.KV, 0, len(h))
	for k, vs := range h {
		if isSensitiveHeader(k) {
			continue
		}
		for _, v := range vs {
			out = append(out, traffic.KV{Key: k, Value: v})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if li, lj := strings.ToLower(out[i].Key), strings.ToLower(out[j].Key); li != lj {
			return li < lj
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// isSensitiveHeader reports whether a header name carries credentials
// the recorder must never persist. Mirrors traffic.DefaultSensitiveHeaders
// but lives here so the recorder hook can drop them at clone time
// without an import cycle (the canonical floor is enforced again on
// the Sanitize side).
func isSensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "cookie", "set-cookie", "proxy-authorization":
		return true
	}
	return false
}

// sanitizeURL strips credential-bearing query-parameter values from
// raw before the URL is captured into a traffic Event. Reuses the
// access log's `redactQuery` so the same key set is honoured in
// both surfaces — a token caught in the access log can't escape
// into the recorded traffic store unredacted. Mirrors the header
// strip in cloneRequestHeaders.
func sanitizeURL(raw string) string {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	u.RawQuery = redactQuery(u.RawQuery)
	return u.RequestURI()
}
