package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/jkylling/bouncer/internal/apiclient"
	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/observability"
	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	"github.com/jkylling/bouncer/internal/server/admin"
)

// mountDataPlane wires the browser-glue routes plus the proxy
// catchall onto r. /favicon.ico and the bare-/ redirect are
// registered explicitly so they don't fall into the catchall and
// fill the traffic recorder with no_match denials.
func (s *Server) mountDataPlane(r chi.Router) {
	r.Get("/favicon.ico", admin.FaviconHandler)
	r.Get("/", http.RedirectHandler(admin.UIPath, http.StatusSeeOther).ServeHTTP)
	r.Handle("/*", http.HandlerFunc(s.handle))
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)

	hook := s.newRecorderHook(r)
	defer hook.commit(ctx)

	// Split the *escaped* path once and reuse the segments for both
	// routing and the policy request: decoding per segment keeps an
	// encoded slash (%2F) inside its segment, so it cannot change the
	// segment count anywhere matching happens. A malformed escape
	// fails the request before any matching runs.
	pathSegs, err := compiled.SplitEscapedPath(r.URL.EscapedPath())
	if err != nil {
		hook.errMsg = err.Error()
		failRequest(ctx, w, r, http.StatusBadRequest, "bad request", "parse path", err)
		return
	}

	// Route the path → API up front so a per-API access_denied_status
	// override applies even on the 401 path (where Evaluate hasn't
	// run yet). Empty apiName means no API claimed the prefix —
	// 401/404 fall through to natural defaults in that case.
	matchedAPI := s.runtime.APIForSegments(pathSegs)

	tok, anonymous, err := s.authenticateOrAnonymous(ctx, r, matchedAPI)
	if err != nil {
		slog.WarnContext(ctx, "authenticate", "method", r.Method, "path", r.URL.Path, "err", err)
		hook.errMsg = "unauthorized"
		wireStatus := s.deniedStatusFor(matchedAPI, http.StatusUnauthorized)
		// RFC 7235: a 401 should advertise the auth scheme. Lets
		// MCP-aware clients distinguish "configure a pre-issued
		// Bearer" from the OAuth code-grant flow they default to
		// when no scheme is signalled. Only emit on a real 401 — a
		// per-API override (Slack: 200) means the client doesn't
		// expect the WWW-Authenticate ceremony.
		if wireStatus == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="bouncer"`)
		}
		admin.WriteDenialRemapped(w, wireStatus, http.StatusUnauthorized,
			"missing or invalid Authorization header — present a Bearer JWT issued by this proxy",
			"", nil)
		return
	}
	var (
		subject string
		creds   auth.AccessCreds
	)
	if !anonymous {
		subject = tok.Subject
		creds = tok.Creds
	}
	span.SetAttributes(observability.Subject(subject))
	hook.subject = subject

	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesReader marks the connection closed but leaves the
		// response status to the handler — return 413 explicitly so
		// the client gets a clear signal. Other read errors get a
		// generic 500.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			hook.errMsg = "request body too large"
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		hook.errMsg = err.Error()
		failRequest(ctx, w, r, http.StatusInternalServerError, "read body", "read body", err)
		return
	}
	_ = r.Body.Close()

	policyReq, err := buildPolicyRequest(r, pathSegs, bodyBytes)
	if err != nil {
		hook.errMsg = err.Error()
		failRequest(ctx, w, r, http.StatusBadRequest, "bad request", "parse body", err)
		return
	}

	principal := buildPrincipal(subject, anonymous)
	apiName, decision, err := s.evaluate(hook.attachObservers(ctx), creds, policyReq, principal)
	if err != nil {
		hook.errMsg = err.Error()
		s.handleEvalError(ctx, w, r, apiName, err)
		return
	}
	span.SetAttributes(
		observability.APIName(apiName),
		observability.PolicyDecision(string(decisionLabel(apiName, decision))),
	)
	hook.api = apiName
	hook.decision = decisionLabel(apiName, decision)
	// No API claimed the route — distinct from "policy denied" so
	// operators can tell a misrouted request from one that was actively
	// rejected. The path_prefixes are visible in config anyway, so a
	// 404 here is no more leakage than the 403 was.
	if apiName == "" {
		slog.InfoContext(ctx, "no_match", "method", r.Method, "path", r.URL.Path)
		admin.WriteDenial(w, http.StatusNotFound,
			"no registered API claims this path — see next_steps.supported_apis for the canonical list")
		return
	}
	span.SetName(r.Method + " " + apiName)
	if decision != models.Permit {
		// Re-run the (cheap, in-memory) match probe to surface the
		// action names the request matched. An agent reading the
		// deny body uses this to draft a permitting policy without
		// a separate GET /_api/apis round-trip. Probe failures do
		// not block the deny — we still 403, but with a thinner body.
		_, matchedActions, mErr := s.runtime.MatchedActions(policyReq)
		if mErr != nil {
			slog.WarnContext(ctx, "matched_actions probe failed", "err", mErr)
		}
		slog.InfoContext(ctx, "deny",
			"method", r.Method, "path", r.URL.Path,
			"api", apiName, "matched_actions", matchedActions)
		admin.WriteDenialRemapped(w,
			s.deniedStatusFor(apiName, http.StatusForbidden),
			http.StatusForbidden,
			"a policy denied this request — see matched_actions for the actions your request fired and next_steps for the live policy set",
			apiName, matchedActions)
		return
	}

	upstream, err := s.upstreamFor(apiName)
	if err != nil {
		hook.errMsg = err.Error()
		failRequest(ctx, w, r, http.StatusInternalServerError, "server error", "upstream lookup", err)
		return
	}
	if err := s.forward(ctx, w, r, bodyBytes, creds, upstream, apiName, hook); err != nil {
		hook.errMsg = err.Error()
		failRequest(ctx, w, r, http.StatusBadGateway, "bad gateway", "upstream", err)
	}
}

// evaluate runs the per-request policy evaluation under its own span
// so the trace timeline shows authenticate / evaluate / forward as
// distinct intervals — useful when one of them dominates request
// latency.
func (s *Server) evaluate(ctx context.Context, creds auth.AccessCreds, req *pb.Request, principal *pb.Principal) (string, models.PolicyResult, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "policy.evaluate")
	defer span.End()
	resolve := func(apiName string) (compiled.PhysicalAPI, error) {
		return s.apiFactory(apiName, creds)
	}
	apiName, decision, err := s.runtime.Evaluate(ctx, resolve, req, principal)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "policy evaluate")
	}
	return apiName, decision, err
}

// handleEvalError surfaces a runtime.Evaluate failure as a structured
// denial. Eval failures are policy-side: the request reached us,
// matched a route, fired a policy, and the policy itself errored.
// From the caller's view that's "denied" not "the proxy crashed", so
// we fail closed with the API's natural denial status (overridable
// via access_denied_status). The eval detail goes to the log only —
// see classifyEvalError for why the body stays generic.
func (s *Server) handleEvalError(ctx context.Context, w http.ResponseWriter, r *http.Request, apiName string, err error) {
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
	span.SetStatus(codes.Error, "policy eval")
	slog.ErrorContext(ctx, "policy eval",
		"method", r.Method, "path", r.URL.Path,
		"api", apiName, "err", err)
	semanticStatus, msg := classifyEvalError(err)
	wireStatus := s.deniedStatusFor(apiName, semanticStatus)
	admin.WriteDenialRemapped(w, wireStatus, semanticStatus, msg, apiName, nil)
}

// classifyEvalError maps a policy-eval error onto a (semantic status,
// message) pair. An embedded `apiclient.UpstreamError` from a meta
// side call carries actionable info — the client's upstream cred
// failed, or the upstream object doesn't exist, or the upstream is
// broken — and surfaces with a status that lets the client tell
// these apart. Anything else is a CEL eval / binding error: the
// policy itself broke. From the caller's view that's a denial
// (request never reached upstream), not a 500 — fail closed. The
// eval detail stays server-side (handleEvalError logs it in full):
// CEL error strings reveal meta names, policy names, and JSON
// offsets, which is failRequest's threat model too. A policy author
// debugging a broken expression reads the logs or `:dryRun`.
func classifyEvalError(err error) (int, string) {
	var upstream *apiclient.UpstreamError
	if !errors.As(err, &upstream) {
		return http.StatusForbidden, "policy evaluation error — an operator can find the full error in the server logs, or validate the policy via :dryRun"
	}
	switch {
	case upstream.Status == http.StatusUnauthorized:
		return http.StatusUnauthorized, "upstream credentials invalid"
	case upstream.Status == http.StatusForbidden:
		return http.StatusForbidden, "upstream forbade the meta request"
	case upstream.Status == http.StatusNotFound:
		return http.StatusNotFound, "upstream object not found"
	default:
		return http.StatusBadGateway, "upstream meta request failed"
	}
}

// decisionLabel maps the (apiName, PolicyResult) pair the runtime
// returns into the four labels used for the policy.decision span
// attribute. The labels match the strings the future traffic viewer
// stores in `decision`, so a span and an Event row use the same
// vocabulary.
func decisionLabel(apiName string, decision models.PolicyResult) traffic.Decision {
	if apiName == "" {
		return traffic.DecisionNoMatch
	}
	if decision == models.Permit {
		return traffic.DecisionPermit
	}
	return traffic.DecisionDeny
}

// failRequest writes a generic client-facing message and logs the
// real error (with method+path context) for operators. The two are
// separate on purpose: the server-side error string from a CEL eval
// failure or YAML parse error reveals meta names, policy names, and
// JSON offsets that an unauthenticated client has no business
// learning. Sentinel `clientMsg`
// values stay stable across internal renames so log filters don't
// have to chase them.
//
// The detail string is also recorded on the active span (with the
// underlying error) so a trace shows *where* the request failed
// without an operator having to cross-reference the slog stream.
func failRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, status int, clientMsg, detail string, err error) {
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
	span.SetStatus(codes.Error, detail)
	slog.ErrorContext(ctx, detail,
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"err", err,
	)
	http.Error(w, clientMsg, status)
}

// upstreamFor returns the parsed BaseURL of the matched API. The
// APIRuntime parsed it once at compile time; we just hand
// the cached *url.URL out.
func (s *Server) upstreamFor(apiName string) (*url.URL, error) {
	rt := s.runtime.API(apiName)
	if rt == nil {
		return nil, fmt.Errorf("api %q not registered", apiName)
	}
	return rt.ParsedBaseURL(), nil
}

// deniedStatusFor resolves the HTTP status to return on a denial
// path (auth fail or policy deny). When the matched API has an
// access_denied_status override, that value wins; otherwise the
// natural default for the path is used. Empty apiName (route-not-
// matched, or a 401 on a request whose path no API claims) always
// falls through to the default.
func (s *Server) deniedStatusFor(apiName string, defaultStatus int) int {
	if apiName == "" {
		return defaultStatus
	}
	api := s.runtime.API(apiName)
	if api == nil {
		return defaultStatus
	}
	if override := api.AccessDeniedStatus(); override != 0 {
		return override
	}
	return defaultStatus
}

// authenticateOrAnonymous wraps the bearer-required and auth: optional
// paths into one call. Returns (tok, false, nil) when a valid bearer
// was presented; (nil, true, nil) when no bearer was presented and the
// matched API admits anonymous traffic; (nil, _, err) otherwise.
//
// The anonymous path is gated on the *matched* API rather than the
// presence of the header alone — a request that doesn't match any
// API still 401s (and 404s later in eval), so anonymous fall-through
// can't be abused to probe arbitrary paths.
//
// A bearer that's present but invalid always fails the request, even
// on an optional-auth API: an explicit malformed credential is a
// client bug, not a "treat as anonymous" signal.
func (s *Server) authenticateOrAnonymous(ctx context.Context, r *http.Request, matchedAPI string) (*auth.AccessToken, bool, error) {
	if hv := r.Header.Get("Authorization"); hv == "" {
		if matchedAPI != "" && s.authOptionalFor(matchedAPI) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("missing bearer")
	}
	tok, err := s.authenticate(ctx, r)
	if err != nil {
		return nil, false, err
	}
	return tok, false, nil
}

// authOptionalFor reads the per-API auth: optional flag. Centralised
// so the proxy hot path doesn't drill into the runtime in two places.
func (s *Server) authOptionalFor(apiName string) bool {
	api := s.runtime.API(apiName)
	if api == nil {
		return false
	}
	return api.AuthOptional()
}

// authenticate parses Authorization, verifies the JWT, and returns
// the verified AccessToken (carrying the upstream credential bundle)
// + JWT subject. A token with no AccessToken / Headers / Cookies at
// all is rejected — there's nothing to forward.
//
// Wrapped in its own span so JWT verification time (HKDF, ChaCha20,
// EdDSA verify) is visible in traces — useful when chasing CPU
// pressure under load.
func (s *Server) authenticate(ctx context.Context, r *http.Request) (*auth.AccessToken, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "proxy.authenticate")
	defer span.End()
	hv := r.Header.Get("Authorization")
	rest, ok := strings.CutPrefix(hv, "Bearer ")
	if !ok {
		return nil, fmt.Errorf("missing bearer")
	}
	tok, err := auth.VerifyAccessToken(s.keys, rest)
	if err != nil {
		return nil, err
	}
	if tok.Creds.AccessToken == "" && len(tok.Creds.Headers) == 0 {
		return nil, fmt.Errorf("token carries no upstream credential")
	}
	return tok, nil
}

// buildPrincipal builds the *pb.Principal the runtime expects.
// `anonymous` distinguishes the two callers a policy may want to
// gate on differently:
//
//   - anonymous=true: no Bearer was presented and the matched API
//     declared `auth: optional`. Subject is empty and kind is
//     "anonymous"; a policy permits via
//     `principal.kind == "anonymous"`.
//   - anonymous=false: a Bearer was verified. Subject is the JWT
//     subject and kind is "agent" — every access JWT today
//     represents a non-human caller.
func buildPrincipal(subject string, anonymous bool) *pb.Principal {
	if anonymous {
		return &pb.Principal{Kind: "anonymous"}
	}
	return &pb.Principal{
		Subject: subject,
		Kind:    "agent",
	}
}

// buildPolicyRequest assembles the pb.Request policies evaluate
// against. pathSegs carries the per-segment-decoded path (see
// compiled.SplitEscapedPath) so templates and `path_segments` are
// %2F-safe; the flat `path` field stays the fully decoded string —
// fine for prefix checks, but slash-in-segment matching belongs on
// the segments.
func buildPolicyRequest(r *http.Request, pathSegs []string, body []byte) (*pb.Request, error) {
	values := r.URL.Query()
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	q := make([]*pb.KeyValue, 0, len(values))
	for _, k := range keys {
		for _, v := range values[k] {
			q = append(q, &pb.KeyValue{Key: k, Value: v})
		}
	}
	pbBody, err := parseRequestBody(r.Header.Get("Content-Type"), body)
	if err != nil {
		return nil, err
	}
	return &pb.Request{
		Method:       strings.ToUpper(r.Method),
		Path:         r.URL.Path,
		PathSegments: pathSegs,
		Query:        q,
		Body:         pbBody,
	}, nil
}

// parseRequestBody dispatches body decoding by Content-Type so a
// CEL `request.body.?channel.orValue("")` works the same way
// regardless of which encoding the SDK uses. Empty body short-
// circuits to nil before content-type sniffing — anything else with
// an unrecognised Content-Type defaults to JSON, matching the
// historical behaviour and the most common case.
//
// Three encodings are projected into the same `request.body` map:
//
//   - `application/json` — native shape, structpb-converted.
//   - `application/x-www-form-urlencoded` — every official Slack
//     SDK uses this; flat keys → strings (or lists on repeat).
//   - `multipart/form-data` — file uploads (Slack files.upload,
//     Drive resumable uploads). Text parts behave like form fields;
//     file parts project to a metadata object (filename,
//     content_type, size) — the bytes are dropped.
func parseRequestBody(contentType string, body []byte) (*structpb.Value, error) {
	if len(body) == 0 {
		return nil, nil
	}
	mediaType, params, _ := mime.ParseMediaType(contentType)
	switch mediaType {
	case "application/x-www-form-urlencoded":
		return parseFormBody(body)
	case "multipart/form-data":
		return parseMultipartBody(body, params["boundary"])
	}
	return parseJSONBody(body)
}

// parseJSONBody decodes a request body into a *structpb.Value so policies
// can read object/array/scalar shapes uniformly. Anything that fails to
// parse as JSON, or fails the structpb conversion, is surfaced as an
// error so the caller can fail the request at the proxy boundary instead
// of silently denying-without-eval.
//
// JSON nulls are dropped from objects via apiclient.DropJSONNulls so a
// CEL pattern like `request.body.?name.orValue("")` short-circuits the
// same way for "missing" and "explicit null" — without that, a literal
// `null` triggers "no such overload" on the `.startsWith()` (or any
// other type-specific call) downstream.
func parseJSONBody(body []byte) (*structpb.Value, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	pv, err := structpb.NewValue(apiclient.DropJSONNulls(v))
	if err != nil {
		return nil, fmt.Errorf("body to value: %w", err)
	}
	return pv, nil
}

// parseMultipartBody decodes multipart/form-data into the same
// flat object shape parseFormBody produces. Text parts (no
// `filename` on the `Content-Disposition`) project to strings (or
// lists on repeat); file parts project to a small metadata object
// `{filename, content_type, size}` — the bytes are deliberately
// dropped because the proxy already enforces MaxRequestBodyBytes
// and policies have no use for raw file content.
//
// Empty boundary fails loud: a multipart Content-Type without a
// boundary param is malformed by RFC 2046, and silently parsing
// nothing would mask a real client bug.
func parseMultipartBody(body []byte, boundary string) (*structpb.Value, error) {
	if boundary == "" {
		return nil, fmt.Errorf("multipart body: missing boundary parameter")
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	collect := map[string][]any{}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("multipart body: %w", err)
		}
		name := part.FormName()
		filename := part.FileName()
		var entry any
		if filename == "" {
			// Text part — collect the value verbatim.
			buf, err := io.ReadAll(part)
			_ = part.Close()
			if err != nil {
				return nil, fmt.Errorf("multipart text part %q: %w", name, err)
			}
			entry = string(buf)
		} else {
			// File part — count bytes, project metadata.
			n, err := io.Copy(io.Discard, part)
			_ = part.Close()
			if err != nil {
				return nil, fmt.Errorf("multipart file part %q: %w", name, err)
			}
			ct := part.Header.Get("Content-Type")
			if ct == "" {
				ct = "application/octet-stream"
			}
			entry = map[string]any{
				"filename":     filename,
				"content_type": ct,
				"size":         float64(n),
			}
		}
		if name == "" {
			continue
		}
		collect[name] = append(collect[name], entry)
	}
	obj := make(map[string]any, len(collect))
	for k, vs := range collect {
		if len(vs) == 1 {
			obj[k] = vs[0]
			continue
		}
		obj[k] = vs
	}
	pv, err := structpb.NewValue(obj)
	if err != nil {
		return nil, fmt.Errorf("body to value: %w", err)
	}
	return pv, nil
}

// parseFormBody decodes application/x-www-form-urlencoded into a
// flat object whose keys are the form field names. Single-value
// fields project to strings (the typical SDK shape — Slack's
// `channel=C…` is one value per key), and a key that repeats across
// the body becomes a list. Mirroring the JSON path's body=map shape
// means a CEL condition like `request.body.?channel.orValue("")`
// works without the policy author caring which Content-Type the
// SDK chose.
func parseFormBody(body []byte) (*structpb.Value, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("invalid form body: %w", err)
	}
	obj := make(map[string]any, len(values))
	for k, vs := range values {
		if len(vs) == 1 {
			obj[k] = vs[0]
			continue
		}
		slice := make([]any, len(vs))
		for i, v := range vs {
			slice[i] = v
		}
		obj[k] = slice
	}
	pv, err := structpb.NewValue(obj)
	if err != nil {
		return nil, fmt.Errorf("body to value: %w", err)
	}
	return pv, nil
}

func (s *Server) forward(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, creds auth.AccessCreds, baseURL *url.URL, apiName string, hook *recorderHook) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "proxy.forward")
	defer span.End()

	// EscapedPath, not Path: the upstream must receive the client's
	// original bytes. The decoded Path would turn an encoded slash
	// (%2F in a Drive file ID, a GCS object name) into a real
	// separator. JoinPath preserves the escapes via RawPath.
	target, err := apiclient.JoinPath(baseURL, r.URL.EscapedPath())
	if err != nil {
		return err
	}
	target.RawQuery = r.URL.RawQuery

	out, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	reqHopByHop := connectionNamedHeaders(r.Header)
	for name, values := range r.Header {
		if shouldStripForwarded(name) || reqHopByHop[name] {
			continue
		}
		for _, v := range values {
			out.Header.Add(name, v)
		}
	}
	applyCredentials(out, creds)

	resp, err := s.forwardClient.Do(out)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	hook.forwarded = true
	hook.forwardedStatus = resp.StatusCode

	respHopByHop := connectionNamedHeaders(resp.Header)
	for name, values := range resp.Header {
		if shouldStripForwarded(name) || respHopByHop[name] {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(newStreamWriter(w, s.streamIdle), resp.Body); err != nil {
		// Headers + status are already on the wire, so we cannot
		// surface this to the client — but a stalled or truncated
		// upstream stream should be visible to operators rather than
		// silently leaving the client with partial bytes.
		span.RecordError(err)
		slog.WarnContext(ctx, "forward copy body",
			"method", r.Method, "path", r.URL.Path, "err", err)
	}
	return nil
}

// applyCredentials stamps the upstream credential bundle onto a
// freshly built outbound request. The order is load-bearing:
//
//  1. Authorization rides as `Bearer <AccessToken>` when present.
//     The bare-bearer case is the OAuth2 / API-token flow.
//  2. Each Header entry replaces any client-supplied value via
//     http.Header.Set — operator config wins (later entries with
//     the same name overwrite earlier ones, mirroring Set-then-Set
//     idempotently).
//
// Cookies are headers too — operators put them in Headers as a
// `Cookie: name=value; name2=value2` row. Empty AccessToken is
// skipped so a token that only carries headers (X-API-Key) doesn't
// end up with a stray `Authorization: Bearer `.
func applyCredentials(req *http.Request, creds auth.AccessCreds) {
	if creds.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)
	}
	for _, h := range creds.Headers {
		req.Header.Set(h.Name, h.Value)
	}
}

// shouldStripForwarded matches the Rust impl's hop-by-hop + per-proxy
// header set. We strip `Authorization` because the proxy rewrites it,
// and `Host`/`Content-Length` because Go's http client computes them.
//
// `Cookie` and `Set-Cookie` are stripped as well: the proxy is a
// Bearer-token endpoint, and a cookie a client happens to send
// alongside the JWT would otherwise ride to the upstream's host —
// a credential leak across a trust boundary the operator did not
// opt into. Today no bundled API uses cookies in either direction,
// but the strip is a defensive default rather than a feature flag.
//
// X-Forwarded-* / X-Real-IP / Forwarded are stripped to prevent a
// client from spoofing the apparent source IP/proto/host as seen by
// the upstream. Without this strip, a request like
// `X-Forwarded-For: 10.0.0.1` flows through to upstream services
// that trust those headers (cloud metadata endpoints, internal
// admin tools), allowing an outside caller to forge the chain.
// connectionNamedHeaders returns the canonicalised header names the
// Connection header declares hop-by-hop (RFC 7230 §6.1: `Connection:
// X-Foo` marks X-Foo as connection-scoped). shouldStripForwarded
// covers the well-known set; this covers the by-declaration ones, in
// both forward directions, matching net/http's own reverse proxy.
func connectionNamedHeaders(h http.Header) map[string]bool {
	var out map[string]bool
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			name = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			if out == nil {
				out = map[string]bool{}
			}
			out[name] = true
		}
	}
	return out
}

func shouldStripForwarded(name string) bool {
	switch strings.ToLower(name) {
	case "host", "authorization", "content-length",
		"connection", "keep-alive",
		"cookie", "set-cookie",
		"proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade",
		"forwarded",
		"x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
		"x-real-ip":
		return true
	}
	return false
}
