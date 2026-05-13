package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/jkylling/bouncer/internal/apiclient"
	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/agents"
	"github.com/jkylling/bouncer/internal/control/agentseen"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/connections"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/services"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/server/admin"
)

// Config bundles the disk + transport knobs Load needs. Keeping this
// here (rather than reaching into cmd's flag struct) lets test code
// drive the same boot path with temp config dirs without depending
// on the binary entry point.
type Config struct {
	// ApisDir is the unified apis directory: top-level *.yaml files
	// are loose API specs (single-API operator overrides, test
	// fixtures), and immediate subdirectories that contain a
	// bouncer.yaml are bundles installed via `bouncer apis add`.
	// Empty yields zero APIs (acceptable for proxies whose only
	// surface is the admin / control plane).
	ApisDir string

	// PolicyStore is the durable backing for the policy CRUD pipeline.
	// Caller-supplied so the boot path can swap backends (file, sqlite,
	// in-memory) without Load ever taking a hard dependency on a
	// specific implementation. Required.
	PolicyStore policies.Store

	// PolicyStoreReadOnly, when true, instructs the policy Service to
	// reject every mutating call (Create / Replace / Delete) without
	// touching disk or the runtime. LoadFromStore still runs, so the
	// runtime mirrors the on-disk policy set; only the control-plane
	// write paths are gated.
	PolicyStoreReadOnly bool

	// UpstreamCallTimeout caps every upstream HTTP call (forward path
	// and meta side calls share one client). Zero means "no timeout"
	// — production wiring should always set this.
	UpstreamCallTimeout time.Duration

	// RefreshTTL is the `exp` claim applied to refresh JWTs the
	// /token handler issues when the upstream rotates the refresh
	// token. Zero means "no exp", matching the default issue-token
	// shape so a rotation does not silently shrink the lifetime.
	RefreshTTL time.Duration

	// AdminPasswordHash is the bcrypt hash the password-login flow
	// (POST /_api/admin/login) compares against. Empty means the
	// login endpoint is wired but returns 503 until an operator sets
	// --admin-password-hash; bootstrap then runs through
	// `cmd/issue-token --admin` instead.
	AdminPasswordHash string

	// MITMCAPath, when non-empty, points at the MITM CA cert file the
	// /_api/ca.crt download endpoint serves. The file is read on
	// every fetch (rather than at boot) so an operator who
	// regenerates the CA without restarting still serves the right
	// bytes. Empty leaves the endpoint mounted but 404'ing — fine
	// for non-MITM deployments.
	MITMCAPath string

	// ConnectionStore persists wizard-pasted upstream credentials.
	// Used by both /_api/connections/* (the wizard's CRUD surface)
	// and the MCP `get_{service}_token` tools. nil leaves both routes
	// unmounted and the MCP tools returning service_not_connected.
	ConnectionStore *connections.Store

	// ProvidersInfo is the frozen-at-boot map of per-provider
	// connect-mode availability. Drives the wizard's two-tab panel.
	// Empty / nil is fine; the wizard then only offers "Paste
	// credentials." See connections.ProviderAvailability.
	ProvidersInfo map[string]connections.ProviderInfo

	// AgentStore tracks pending + approved agent registrations
	// (/_api/agents/*). Optional — when nil the routes aren't mounted.
	AgentStore *agents.Store

	// Env is the frozen-at-boot env snapshot the services registry
	// reads to decide which bundles' OAuth tabs to light up. Pass the
	// same map the connections.ProviderAvailability call consumes;
	// nil yields a registry where no service reports OAuthAvailable.
	Env map[string]string

	// InternalPolicies picks the embedded policy set that gates the
	// control-plane HTTP surface (`/_admin` + `/_api`). Empty
	// defaults to admin.PolicySetSimple — matches today's access
	// control. The middleware loads exactly one set at boot; an
	// unknown name fails Load loudly rather than silently falling
	// back.
	InternalPolicies admin.PolicySet

	// TrafficStore backs the read side of the traffic viewer
	// (`/_api/traffic`). nil leaves the routes unmounted.
	TrafficStore traffic.Store

	// Recorder is the per-request write-side observer. Operationally
	// independent of TrafficStore (production wires both to one
	// store; tests can opt into either alone).
	Recorder Recorder
}

// Load compiles the on-disk API/policy spec into a ready-to-serve
// Server. It is the single boot path: cmd/bouncer calls Load and
// hands the resulting Router() to its `http.Server`. Tests that need
// to inject a fake upstream go through NewServer directly.
//
// One http.Client services both the forward path and every meta side
// call. The upstream factory closes over that client and
// each API's parsed BaseURL so the per-request handler does no URL
// parsing.
func Load(cfg *Config, keys *auth.ServerKeys) (*Server, error) {
	loaded, err := bundles.LoadAll(bundles.LoadOptions{
		APIsDir: cfg.ApisDir,
	})
	if err != nil {
		return nil, fmt.Errorf("load apis: %w", err)
	}

	builder := runtime.NewBuilder()
	for i := range loaded {
		spec := loaded[i].Spec
		if err := builder.AddAPI(&spec); err != nil {
			return nil, fmt.Errorf("register api %q (from %s): %w", spec.Name, loaded[i].Source, err)
		}
	}
	rt, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("compile runtime: %w", err)
	}

	// Policies route through the supplied Store so the same
	// validate-then-persist-then-apply pipeline used by the control
	// plane also drives the boot-time load. Calling LoadFromStore
	// here (rather than walking models.FromYAMLDir directly) means
	// boot and CRUD writes share one path.
	if cfg.PolicyStore == nil {
		return nil, fmt.Errorf("Config.PolicyStore is required")
	}
	policyService := policies.New(rt, cfg.PolicyStore)
	if err := policyService.LoadFromStore(context.Background()); err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}
	// Flip the flag *after* LoadFromStore so the boot-time replay can
	// hand each policy through the runtime; SetReadOnly only gates the
	// CRUD entrypoints, never the load.
	policyService.SetReadOnly(cfg.PolicyStoreReadOnly)

	// otelhttp.NewTransport wraps the default transport so every
	// upstream call (forward path + meta side calls) emits an
	// HTTP-client span as a child of whatever request context drove
	// it. The spans pick up trace propagation headers automatically,
	// so an operator who fronts bouncer with another otel-aware
	// service sees one continuous trace.
	httpClient := &http.Client{
		Timeout:   cfg.UpstreamCallTimeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		// Refuse to follow redirects: a 3xx from a compromised or
		// misconfigured upstream would otherwise drag the upstream
		// access token (forward path) or the proxy's internal
		// network identity (meta side calls) to whatever Location
		// the upstream chose. Both consumers (server.forward and
		// apiclient.HTTPAPI.Call) already surface a non-2xx response
		// as an UpstreamError, so the only behavioural change here
		// is that 3xx is now opaque rather than chased internally.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	factory := func(apiName string, creds auth.AccessCreds) (compiled.PhysicalAPI, error) {
		api := rt.API(apiName)
		if api == nil {
			return nil, fmt.Errorf("api %q not registered", apiName)
		}
		// apiclient is auth-agnostic by design (no auth import) — convert
		// at the boundary. The Headers carry the JWT-bundled extras
		// (Cookie / Origin / Referer for browser-session creds, X-API-Key
		// for header tokens) so meta side calls authenticate the same way
		// as the outer forward path's applyCredentials does.
		extra := make([]apiclient.Header, 0, len(creds.Headers))
		for _, h := range creds.Headers {
			extra = append(extra, apiclient.Header{Name: h.Name, Value: h.Value})
		}
		return apiclient.New(httpClient, api.BaseURL(), creds.AccessToken, extra)
	}
	internalSet := cfg.InternalPolicies
	if internalSet == "" {
		internalSet = admin.PolicySetSimple
	}
	internalRT, err := admin.LoadInternalRuntime(internalSet)
	if err != nil {
		return nil, fmt.Errorf("load internal-policies %q: %w", internalSet, err)
	}

	loadedServices := bundles.Services(loaded)
	return NewServer(Dependencies{
		Runtime:           rt,
		Keys:              keys,
		HTTPClient:        httpClient,
		APIFactory:        factory,
		RefreshTTL:        cfg.RefreshTTL,
		Recorder:          cfg.Recorder,
		TrafficStore:      cfg.TrafficStore,
		PolicyService:     policyService,
		AdminPasswordHash: cfg.AdminPasswordHash,
		MITMCAPath:        cfg.MITMCAPath,
		BundleData: admin.BundleData{
			Readmes:      bundles.Readmes(loaded),
			APIBundle:    bundles.APIBundles(loaded),
			TokenBundles: bundles.TokenBundles(loaded),
			Services:     loadedServices,
		},
		ConnectionStore:  cfg.ConnectionStore,
		ProvidersInfo:    cfg.ProvidersInfo,
		AgentStore:       cfg.AgentStore,
		SeenTracker:      agentseen.New(),
		ServicesRegistry: services.New(loadedServices, cfg.Env, cfg.ConnectionStore),
		InternalRuntime:  internalRT,
	}), nil
}

// APINames returns the names of every API mounted on the server. It is
// the only Server accessor cmd needs — log output at boot lists the
// configured upstreams so a misconfigured config dir is visible.
func (s *Server) APINames() []string { return s.runtime.APINames() }
