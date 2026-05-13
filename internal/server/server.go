// Package server fronts a multi-API `*runtime.Runtime` as a
// policy-enforcing HTTP proxy. Every inbound request is authenticated
// via JWT, routed to the API whose actions claim it, evaluated against
// that API's policy set, and (on Permit) forwarded upstream with the
// JWT-embedded access token swapped into the `Authorization` header.
//
// The HTTP surface splits two ways:
//
//   - Data plane (proxy.go): /favicon, /, and the catchall handler
//     that authenticates → evaluates → forwards. The hot path.
//   - Control plane (mount.go): /_admin and /_api routes from the
//     admin subpackage, the MCP JSON-RPC endpoint, OAuth refresh,
//     /.well-known metadata. Operator and agent surfaces.
//
// Router() composes them with shared middleware.
package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/agents"
	"github.com/jkylling/bouncer/internal/control/agentseen"
	"github.com/jkylling/bouncer/internal/control/connections"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/services"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/observability"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/server/admin"
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

	recorder          Recorder
	trafficStore      traffic.Store
	policyService     *policies.Service
	adminPasswordHash string
	mitmCAPath        string
	bundleData        admin.BundleData
	connectionStore   *connections.Store
	providersInfo     map[string]connections.ProviderInfo
	agentStore        *agents.Store
	seenTracker       *agentseen.Tracker
	servicesRegistry  *services.Registry
	internalRuntime   *runtime.Runtime

	// apiToService is derived from bundleData at construction and
	// drives the upstream-401 rewrite to credentials_not_staged.
	apiToService map[string]string
}

// Dependencies bundles every input NewServer needs. Runtime, Keys,
// and APIFactory are required (the proxy can't function without them);
// every other field is optional and selectively wires the matching
// admin/MCP surface — a nil pointer leaves the routes unmounted, an
// empty string leaves the corresponding endpoint dormant.
//
// HTTPClient defaults to http.DefaultClient when nil. RefreshTTL
// controls the `exp` claim on refresh JWTs the /token handler issues;
// zero means "no exp" (matching the default issue-token shape).
//
// Optional fields:
//   - Recorder: per-request observer; nil = no-op write side.
//   - TrafficStore: backs /_api/traffic; nil leaves the routes
//     unmounted. Recorder and TrafficStore are operationally
//     independent (write vs read side) — production wires both to the
//     same store, tests can opt into either alone.
//   - PolicyService / ProposalService: back the CRUD endpoints; nil
//     leaves the routes unmounted.
//   - AdminPasswordHash: bcrypt hash POST /_api/admin/login compares
//     against. Empty leaves the endpoint wired but 503'ing.
//   - MITMCAPath: file GET /_api/ca.crt serves. Empty 404s.
//   - BundleData: per-bundle README + api→bundle/service projection.
//     Also drives the upstream-401 → credentials_not_staged rewrite.
//   - ConnectionStore + ProvidersInfo: upstream-credentials store and
//     the frozen-at-boot connect-mode availability snapshot. nil store
//     leaves /_api/connections/* unmounted.
//   - AgentStore: backs /_api/agents/*; nil leaves the routes
//     unmounted.
//   - ServicesRegistry: backs /_api/services. Always mounted; nil
//     registry returns an empty list.
//   - InternalRuntime: drives the internal-policy middleware that
//     gates every /_admin and /_api request. nil leaves the surface
//     open (test default).
type Dependencies struct {
	Runtime    *runtime.Runtime
	Keys       *auth.ServerKeys
	HTTPClient *http.Client
	APIFactory PhysicalAPIFactory
	RefreshTTL time.Duration

	Recorder          Recorder
	TrafficStore      traffic.Store
	PolicyService     *policies.Service
	AdminPasswordHash string
	MITMCAPath        string
	BundleData        admin.BundleData
	ConnectionStore   *connections.Store
	ProvidersInfo     map[string]connections.ProviderInfo
	AgentStore        *agents.Store
	SeenTracker       *agentseen.Tracker
	ServicesRegistry  *services.Registry
	InternalRuntime   *runtime.Runtime
}

// NewServer wires the auth, policy, and forwarding layers together.
// The server fronts every API registered on deps.Runtime; per-API
// upstream URLs come from `runtime.API(name).BaseURL()`.
func NewServer(deps Dependencies) *Server {
	httpClient := deps.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Server{
		runtime:           deps.Runtime,
		keys:              deps.Keys,
		httpClient:        httpClient,
		apiFactory:        deps.APIFactory,
		oauthHandler:      oauth.New(deps.Keys, httpClient, deps.RefreshTTL),
		recorder:          deps.Recorder,
		trafficStore:      deps.TrafficStore,
		policyService:     deps.PolicyService,
		adminPasswordHash: deps.AdminPasswordHash,
		mitmCAPath:        deps.MITMCAPath,
		bundleData:        deps.BundleData,
		connectionStore:   deps.ConnectionStore,
		providersInfo:     deps.ProvidersInfo,
		agentStore:        deps.AgentStore,
		seenTracker:       deps.SeenTracker,
		servicesRegistry:  deps.ServicesRegistry,
		internalRuntime:   deps.InternalRuntime,
		apiToService:      deriveAPIToService(deps.BundleData),
	}
}

// deriveAPIToService walks the bundle data once and returns api →
// service for every API whose owning bundle declares a token block.
// Pure helper so it can be tested in isolation if needed.
func deriveAPIToService(bd admin.BundleData) map[string]string {
	if len(bd.APIBundle) == 0 || len(bd.TokenBundles) == 0 {
		return nil
	}
	bundleToService := make(map[string]string, len(bd.TokenBundles))
	for _, b := range bd.TokenBundles {
		if b == nil || b.Spec == nil || b.BundleName == "" {
			continue
		}
		bundleToService[b.BundleName] = b.Spec.Slug
	}
	out := make(map[string]string, len(bd.APIBundle))
	for api, bundle := range bd.APIBundle {
		if svc, ok := bundleToService[bundle]; ok {
			out[api] = svc
		}
	}
	return out
}

// Router mounts the control plane (admin / MCP / OAuth) ahead of the
// data plane (proxy catchall) so chi's literal-vs-catchall priority
// keeps the admin routes out of the proxy's reach.
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
	// AuthMiddleware runs first so the verified Caller is in ctx
	// before the internal-policy middleware turns it into a
	// *pb.Principal. It does not reject anonymous traffic — open
	// routes (docs, /_api/apis, :capabilities) keep working without
	// a JWT, and the policy set decides which routes those are.
	r.Use(admin.AuthMiddleware(s.keys))
	// InternalPolicyMiddleware gates every /_admin and /_api request
	// against the embedded policy set the operator selected at boot.
	// Requests outside that prefix fall through to the proxy path
	// unchanged. nil internalRuntime leaves the surface open — the
	// test-double construction path uses NewServer directly without
	// a Load.
	if s.internalRuntime != nil {
		r.Use(admin.InternalPolicyMiddleware(s.internalRuntime))
	}
	s.mountControlPlane(r)
	s.mountDataPlane(r)
	return otelhttp.NewHandler(r, "bouncer.request")
}
