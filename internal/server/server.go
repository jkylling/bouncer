// Package server fronts a multi-API `*runtime.Runtime` as a
// policy-enforcing HTTP proxy. Every inbound request is authenticated
// via JWT, routed to the API whose actions claim it, evaluated against
// that API's policy set, and (on Permit) forwarded upstream with the
// JWT-embedded access token swapped into the `Authorization` header.
package server

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/jkylling/bouncer/internal/apiclient"
	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/proposals"
	"github.com/jkylling/bouncer/internal/control/propose"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/observability"
	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	"github.com/jkylling/bouncer/internal/server/admin"
	"github.com/jkylling/bouncer/internal/server/admin/mcp"
	"github.com/jkylling/bouncer/internal/server/oauth"
)

// tracerName is the otel instrumentation library identifier for this
// package's spans. Derived from the package import path so a rename
// or move surfaces in collector UIs without a hand-edit.
var tracerName = observability.PackagePath()

// PhysicalAPIFactory builds the per-request compiled.PhysicalAPI for
// the API matched by routing. apiName picks the upstream base URL;
// creds carries the full upstream credential bundle (access token +
// any extra headers like Cookie / Origin / Referer for browser-
// session tokens) so meta side calls authenticate identically to the
// outer forwarded request.
type PhysicalAPIFactory func(apiName string, creds auth.AccessCreds) (compiled.PhysicalAPI, error)

// MaxRequestBodyBytes caps the inbound request body the proxy will
// buffer before forwarding. JSON control-plane traffic is small; the
// limit prevents a single hostile POST from OOMing the proxy.
const MaxRequestBodyBytes int64 = 1 << 20 // 1 MiB

// Server is the HTTP handler. Use `NewServer` to construct one.
type Server struct {
	runtime      *runtime.Runtime
	keys         *auth.ServerKeys
	httpClient   *http.Client
	apiFactory   PhysicalAPIFactory
	oauthHandler *oauth.Handler

	// recorder is the optional per-request observer; nil = no-op.
	// Set with SetRecorder before serving.
	recorder Recorder

	// trafficStore powers the read side of the traffic viewer
	// (`/_api/traffic` endpoints). Optional — when nil the routes
	// are not mounted. Operationally distinct from `recorder`
	// (write side) so a deployment can opt into one without the
	// other; in practice cmd/bouncer wires both to the same
	// underlying store.
	trafficStore traffic.Store

	// policyService backs the policy CRUD endpoints
	// (`/_api/policies`). Optional — when nil the routes are not
	// mounted, matching the trafficStore opt-in pattern.
	policyService *policies.Service

	// proposalService backs the proposal endpoints
	// (`/_api/proposals`). Optional — when nil the routes are not
	// mounted.
	proposalService *proposals.Service

	// adminPasswordHash is the bcrypt hash POST /_api/admin/login
	// compares against. Empty leaves the login endpoint wired but
	// serving 503; an operator who hasn't configured a password
	// bootstraps via `cmd/issue-token --admin`.
	adminPasswordHash string

	// mitmCAPath, when non-empty, is the file the GET /_api/ca.crt
	// download endpoint serves on demand. Empty means MITM is
	// disabled / unconfigured — the route is still mounted but
	// 404s, so a client checking for it sees an unambiguous
	// "this deployment has no MITM CA" rather than a 200 with empty
	// bytes.
	mitmCAPath string

	// bundleData carries per-bundle README bytes and the api→bundle
	// projection so /_api/apis can stamp a `readme_url` on each
	// descriptor and the new `/_api/apis/{bundle}/readme` route can
	// serve the bytes. Empty-zero is fine — the route 404s for
	// every bundle name and `readme_url` stays absent.
	bundleData admin.BundleData
}

// SetRecorder configures the per-request recorder. Pass nil to
// disable. Call before `Router()` is wired into a listener; the
// field is read on every request without locking.
func (s *Server) SetRecorder(r Recorder) {
	s.recorder = r
}

// SetTrafficStore configures the store backing the traffic-viewer
// query API. Pass nil to leave the routes unmounted. Call before
// `Router()` since the routing decision is made there.
func (s *Server) SetTrafficStore(store traffic.Store) {
	s.trafficStore = store
}

// SetPolicyService configures the service backing the policy CRUD
// API. Pass nil to leave the routes unmounted. Call before `Router()`
// since the routing decision is made there.
func (s *Server) SetPolicyService(svc *policies.Service) {
	s.policyService = svc
}

// SetProposalService configures the service backing the proposal
// review API. Pass nil to leave the routes unmounted. Call before
// `Router()` since the routing decision is made there.
func (s *Server) SetProposalService(svc *proposals.Service) {
	s.proposalService = svc
}

// SetAdminPasswordHash configures the bcrypt hash POST
// /_api/admin/login compares against. Empty leaves the endpoint
// wired but serving 503 until an operator sets the hash. Call before
// `Router()`.
func (s *Server) SetAdminPasswordHash(hash string) {
	s.adminPasswordHash = hash
}

// SetMITMCAPath points the GET /_api/ca.crt download endpoint at the
// CA cert file. Empty leaves the endpoint mounted but 404'ing.
// Call before `Router()`.
func (s *Server) SetMITMCAPath(path string) {
	s.mitmCAPath = path
}

// SetBundleData attaches per-bundle README + api→bundle metadata
// the admin and MCP layers surface (`/_api/apis` `readme_url`,
// `/_api/apis/{bundle}/readme`, `bouncer://bundles/<name>/readme`).
// Zero-value is fine for deployments with no vendored bundles.
// Call before `Router()` since the routing decision is made there.
func (s *Server) SetBundleData(bd admin.BundleData) {
	s.bundleData = bd
}

// NewServer wires the auth, policy, and forwarding layers together.
// The server fronts every API registered on rt; per-API upstream URLs
// come from `runtime.API(name).BaseURL()`. refreshTTL controls the
// `exp` claim on refresh JWTs the /token handler issues when an
// upstream rotates the refresh token; zero means "no exp" (matching
// the default issue-token shape).
func NewServer(
	rt *runtime.Runtime,
	keys *auth.ServerKeys,
	httpClient *http.Client,
	apiFactory PhysicalAPIFactory,
	refreshTTL time.Duration,
) *Server {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Server{
		runtime:      rt,
		keys:         keys,
		httpClient:   httpClient,
		apiFactory:   apiFactory,
		oauthHandler: oauth.New(keys, httpClient, refreshTTL),
	}
}

// Router mounts the admin endpoints (UI + control-plane APIs from
// the admin subpackage) and forwards everything else through the
// proxy handler. Admin routes come first so chi's literal-vs-catchall
// priority keeps them out of the proxy's reach.
//
// Middleware order is load-bearing:
//   - otelhttp (outer) starts a server span; the proxy handler
//     overrides the span name via SetName once the matched API
//     and policy decision are known.
//   - chi's RealIP rewrites r.RemoteAddr from X-Forwarded-For /
//     X-Real-IP so the access log records the upstream client.
//   - the access logger emits one structured line per request; the
//     trace_id rides along inside the otel span context.
//   - the panic recoverer is innermost so the access log records
//     500 (not the default 0 → 200) when a handler panics.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(accessLog)
	r.Use(recoverer)
	// AuthMiddleware runs before any /_api or /_admin handler so
	// the per-route RequireAdmin / RequireAuthenticated wrappers
	// can read the verified Caller from ctx. It does not reject
	// anonymous traffic — open routes (docs, /_api/apis,
	// :capabilities) keep working without a JWT.
	r.Use(admin.AuthMiddleware(s.keys))
	admin.MountOn(r, s.keys)
	admin.MountLogin(r, s.keys, s.adminPasswordHash)
	admin.MountWhoami(r)
	admin.MountAPIs(r, s.runtime, s.bundleData)
	admin.MountDocs(r)
	admin.MountCA(r, s.mitmCAPath)
	if s.trafficStore != nil {
		admin.MountTraffic(r, s.trafficStore, admin.AnonymousPrincipal)
	}
	if s.policyService != nil {
		admin.MountPolicies(r, s.policyService)
	}
	if s.proposalService != nil {
		admin.MountProposals(r, s.proposalService)
	}
	// The propose ("policy from request") endpoint needs both the
	// traffic store (to look up the recorded event) and the runtime
	// (the engine wraps it for compile validation). Proposals are
	// optional — without them the endpoint serves previews but
	// `?submit=true` returns 501.
	if s.trafficStore != nil {
		admin.MountPropose(r, s.trafficStore, propose.New(s.runtime), s.proposalService)
	}
	// MCP server sits at /_api/mcp and re-projects the surfaces
	// above as JSON-RPC tools + resources. RequireAuthenticated /
	// admin gating happens inside the tool runners (mirroring the
	// HTTP-side discipline) so the bare endpoint stays accessible
	// for tools/list discovery.
	agentMD, policyMD, apiMD := admin.DocsBytes()
	mcp.New(mcp.Deps{
		Runtime:         s.runtime,
		PolicyService:   s.policyService,
		ProposalService: s.proposalService,
		TrafficStore:    s.trafficStore,
		BundleReadmes:   s.bundleData.Readmes,
		APIBundle:       s.bundleData.APIBundle,
		Docs: mcp.Docs{
			AgentGuide:      agentMD,
			PolicyAuthoring: policyMD,
			APIAuthoring:    apiMD,
		},
	}).Mount(r)
	// MCP-aware harnesses probe OAuth metadata + DCR before falling
	// back to a configured Bearer; intercept the probe paths so they
	// return a clean signal instead of being eaten by the data-plane
	// catchall and showing up as confusing "missing JWT" log lines.
	mcp.MountWellKnown(r)
	r.Method(http.MethodPost, oauth.Path, s.oauthHandler)
	// Browser-glue routes: /favicon.ico is auto-fetched on every page
	// load — without an explicit handler it falls into the proxy
	// catchall and fills the traffic recorder with no_match denials.
	// Bare `/` redirects to the admin UI rather than 404'ing.
	r.Get("/favicon.ico", faviconHandler)
	r.Get("/", http.RedirectHandler(admin.UIPath, http.StatusSeeOther).ServeHTTP)
	r.Handle("/*", http.HandlerFunc(s.handle))
	return otelhttp.NewHandler(r, "bouncer.request")
}

//go:embed favicon.svg
var faviconSVG []byte

func faviconHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconSVG)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)

	hook := s.newRecorderHook(r)
	defer hook.commit(ctx)

	// Route the path → API up front so a per-API access_denied_status
	// override applies even on the 401 path (where Evaluate hasn't
	// run yet). Empty apiName means no API claimed the prefix —
	// 401/404 fall through to natural defaults in that case.
	matchedAPI := s.runtime.APIForPath(r.URL.Path)

	tok, err := s.authenticate(ctx, r)
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
	subject := tok.Subject
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

	policyReq, err := buildPolicyRequest(r, bodyBytes)
	if err != nil {
		hook.errMsg = err.Error()
		failRequest(ctx, w, r, http.StatusBadRequest, "bad request", "parse body", err)
		return
	}

	principal := buildPrincipal(subject)
	apiName, decision, err := s.evaluate(hook.attachObservers(ctx), tok.Creds, policyReq, principal)
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
			"a policy denied this request — see matched_actions for the actions your request fired and next_steps for the live policy set and propose-policy entry points",
			apiName, matchedActions)
		return
	}

	upstream, err := s.upstreamFor(apiName)
	if err != nil {
		hook.errMsg = err.Error()
		failRequest(ctx, w, r, http.StatusInternalServerError, "server error", "upstream lookup", err)
		return
	}
	if err := s.forward(ctx, w, r, bodyBytes, tok.Creds, upstream, hook); err != nil {
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
// From the caller's view that's "denied, here's why" not "the proxy
// crashed", so we fail closed with the API's natural denial status
// (overridable via access_denied_status) and put the eval detail in
// the body so a policy author can fix the broken expression.
// Operators still get the full error logged for triage.
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
// (request never reached upstream), not a 500 — fail closed with
// the eval detail so the policy author can fix the expression.
func classifyEvalError(err error) (int, string) {
	var upstream *apiclient.UpstreamError
	if !errors.As(err, &upstream) {
		return http.StatusForbidden, fmt.Sprintf("policy evaluation error: %v", err)
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

// buildPrincipal builds the *pb.Principal the runtime expects from the
// verified access-JWT subject. Today the access JWT only carries the
// subject, so kind, scopes, and attributes stay empty — the policy
// runtime tolerates absent fields (a CEL `principal.scopes` is the
// empty list, not an error). `kind` is populated as "agent" because
// every access JWT the proxy issues today represents a non-human
// caller; once we issue user-bound tokens this branches on the
// claim that distinguishes them.
func buildPrincipal(subject string) *pb.Principal {
	return &pb.Principal{
		Subject: subject,
		Kind:    "agent",
	}
}

func buildPolicyRequest(r *http.Request, body []byte) (*pb.Request, error) {
	segs := compiled.SplitPath(r.URL.Path)
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
		PathSegments: segs,
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

func (s *Server) forward(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, creds auth.AccessCreds, baseURL *url.URL, hook *recorderHook) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "proxy.forward")
	defer span.End()

	target, err := apiclient.JoinPath(baseURL, r.URL.Path)
	if err != nil {
		return err
	}
	target.RawQuery = r.URL.RawQuery

	out, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	for name, values := range r.Header {
		if shouldStripForwarded(name) {
			continue
		}
		for _, v := range values {
			out.Header.Add(name, v)
		}
	}
	applyCredentials(out, creds)

	resp, err := s.httpClient.Do(out)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	hook.forwarded = true
	hook.forwardedStatus = resp.StatusCode

	for name, values := range resp.Header {
		if shouldStripForwarded(name) {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
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
