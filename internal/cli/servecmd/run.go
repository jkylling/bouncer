// Package serve implements the `bouncer serve` subcommand: load
// configuration, build the policy/traffic stores, wire the
// HTTP server, and run until SIGINT/SIGTERM. The dispatcher in
// cmd/bouncer hands raw argv (without the subcommand) to Run.
//
// Wiring:
//   - load API YAML from --apis-dir and policy YAML from --policies-dir,
//   - derive server keys from --secret-hex (typically auto-loaded from
//     <data-dir>/secret.hex written by `bouncer init`),
//   - compile every bundled API into a shared Runtime so policies on any
//     API can reference any other's meta types,
//   - listen on --addr and forward Permit decisions to the matched API's
//     own base_url. Routing happens inside the Runtime: each request is
//     dispatched to the API whose actions claim its method+path.
//
// Configuration is read via viper (flags > env > defaults). Every flag
// has a `BOUNCER_<UPPER_SNAKE>` env equivalent — e.g. `--secret-hex`
// pairs with `BOUNCER_SECRET_HEX`. All non-trivial behaviour is in
// `internal/server`; this file is the configuration entry point.
package servecmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/observability"
	"github.com/jkylling/bouncer/internal/server"
	"github.com/jkylling/bouncer/internal/server/admin"
	"github.com/jkylling/bouncer/internal/server/mitm"
)

// shutdownTimeout caps both the http.Server.Shutdown wait and the
// recorder/cache cleanup. Sized so a misbehaving sqlite (or a stuck
// connection) cannot pin the process past a reasonable supervisor
// retry interval.
const shutdownTimeout = 10 * time.Second

// Command returns the `bouncer serve` cobra subcommand.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the proxy",
		Long:  serveLong,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := buildConfig(c.Flags())
			if err != nil {
				return err
			}
			return runServe(cfg)
		},
	}
	bindServeFlags(cmd.Flags())
	return cmd
}

// runServe is the post-config wiring path: derives keys, builds the
// stores, loads the runtime, builds the listener, and serves until
// shutdown. Errors flow up so the caller decides the exit code;
// this lets the deferred observability shutdown actually run before
// the process dies. Pre-Go-1.22, the function used a fatal() helper
// that called os.Exit and skipped every defer — buffered traces
// were dropped.
func runServe(cfg *config) error {
	shutdown, err := setupObservability(cfg)
	if err != nil {
		return fmt.Errorf("observability: %w", err)
	}
	defer func() { _ = observability.ShutdownWithTimeout(shutdown, 5*time.Second) }()

	secret, err := deriveSecret(cfg)
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	keys, err := auth.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}

	cache := &backendCache{}

	policyStore, err := buildPolicyStore(cfg, cache)
	if err != nil {
		cache.closeAll()
		return fmt.Errorf("policy store: %w", err)
	}
	proposalStore, err := buildProposalStore(cfg, cache)
	if err != nil {
		cache.closeAll()
		return fmt.Errorf("proposal store: %w", err)
	}

	trafficStore, recorder, err := buildTraffic(cfg, cache)
	if err != nil {
		cache.closeAll()
		return fmt.Errorf("traffic store: %w", err)
	}

	srv, err := server.Load(&server.Config{
		ApisDir:             cfg.ApisDir,
		PolicyStore:         policyStore,
		PolicyStoreReadOnly: cfg.PoliciesReadOnly,
		ProposalStore:       proposalStore,
		UpstreamCallTimeout: cfg.UpstreamCallTimeout,
		// The listener's WriteTimeout doubles as the per-chunk
		// progress budget on streamed responses: each forwarded
		// chunk pushes the write deadline out by this much.
		StreamIdleTimeout: cfg.InboundWriteTimeout,
		MaxRequestBody:    cfg.MaxRequestBody,
		RefreshTTL:        cfg.RefreshTTL,
		AdminPasswordHash: cfg.AdminPasswordHash,
		// Populated only when --mitm is on; otherwise empty and the
		// /_api/ca.crt endpoint serves 404.
		MITMCAPath:       caDownloadPath(cfg),
		InternalPolicies: admin.PolicySet(cfg.InternalPolicies),
		TrafficStore:     trafficStore,
		Recorder:         recorder,
	}, keys)
	if err != nil {
		cache.closeAll()
		return fmt.Errorf("server load: %w", err)
	}

	handler, err := buildListenerHandler(cfg, srv)
	if err != nil {
		cache.closeAll()
		return fmt.Errorf("listener handler: %w", err)
	}
	httpSrv := newHTTPServer(cfg, handler)
	warnOpenControlPlane(cfg)
	slog.Info("listening",
		"addr", cfg.Addr,
		"apis", srv.APINames(),
		"mode", listenerMode(cfg),
		"traffic_store", cfg.TrafficStore,
	)
	if err := runWithShutdown(httpSrv, recorder, cache); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// runWithShutdown serves until SIGINT/SIGTERM, then stops the HTTP
// server, drains the recorder, and closes the backend cache — in
// that order. Stop accepting requests first so no new events land
// while the recorder drains; close the cache last so the recorder's
// final inserts can hit the underlying sqlite.
//
// One shutdownTimeout budget covers both the http.Server.Shutdown
// wait and the recorder drain — the deadline is shared via ctx, not
// re-spent at each phase. Worst-case wall time is one
// shutdownTimeout, not two, so a supervisor that hard-kills at e.g.
// 30s gives us steady headroom rather than a moving cliff.
func runWithShutdown(httpSrv *http.Server, recorder *traffic.AsyncRecorder, cache *backendCache) error {
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		err := httpSrv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		// Server exited on its own (port-in-use, fatal listener
		// error). Close best-effort and surface the listen error.
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		closeAfterServe(shutCtx, recorder, cache)
		return err
	case <-signalCtx.Done():
		slog.Info("shutdown signal received, draining")
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		slog.Warn("http server shutdown", "err", err)
	}
	closeAfterServe(shutCtx, recorder, cache)

	// Wait for the serve goroutine to exit so we don't return while
	// the listener might still be bouncing.
	if err := <-serveErr; err != nil {
		return err
	}
	return nil
}

// closeAfterServe runs the recorder + cache teardown. Recorder first
// so its drained events flush into the sqlite store before the cache
// closes the *sql.DB.
//
// recorder.Close has no context, so we bound it via select against
// shutdownCtx.Done(). On timeout we still close the cache — but only
// after a final beat to let any in-flight write finish; otherwise
// closing *sql.DB while a writer goroutine is mid-Insert can wedge
// DB.Close itself or produce noisy WARN-per-buffered-event errors as
// the writer drains against a closed handle. The trade is "leak the
// recorder goroutine for a few moments past process exit" vs.
// "leave behind a noisy log tail" — leaking is the cheaper option,
// since process exit reaps it on the next instruction.
func closeAfterServe(ctx context.Context, recorder *traffic.AsyncRecorder, cache *backendCache) {
	if recorder != nil {
		done := make(chan error, 1)
		go func() { done <- recorder.Close() }()
		select {
		case err := <-done:
			if err != nil {
				slog.Warn("traffic recorder close", "err", err)
			}
		case <-ctx.Done():
			slog.Warn("traffic recorder drain timed out",
				"err", ctx.Err())
			// Leave the goroutine running; it'll be reaped by
			// process exit. Don't `cache.closeAll` while it's
			// still racing the *sql.DB — return early so the
			// outer shutdown path completes without the cache
			// close-vs-write race.
			return
		}
	}
	cache.closeAll()
}

// buildListenerHandler returns the http.Handler the listener serves.
// In path-prefix (default) mode this is just `srv.Router()`; in MITM
// mode the router is wrapped by mitm.New so CONNECT is hijacked and
// TLS-terminated before the inner router sees the request. The MITM
// branch is keyed off the `--mitm` flag so the existing direct path
// stays the default and the new behaviour is opt-in.
func buildListenerHandler(cfg *config, srv *server.Server) (http.Handler, error) {
	if !cfg.MITM {
		return srv.Router(), nil
	}
	ca, err := mitm.CAFromFiles(cfg.MITMCAPath, cfg.MITMCAKey)
	if err != nil {
		return nil, err
	}
	return mitm.New(ca, srv.Router(), mitm.Options{
		IdleTimeout:       cfg.InboundIdleTimeout,
		ReadHeaderTimeout: cfg.InboundReadHeaderTimeout,
	}), nil
}

// caDownloadPath returns the path the /_api/ca.crt download endpoint
// should serve, or "" when MITM is disabled (in which case the
// endpoint is mounted but 404s). MITM=on without a configured cert
// path is a misconfiguration validate() already catches; the empty
// fallback here is defence-in-depth.
func caDownloadPath(cfg *config) string {
	if !cfg.MITM {
		return ""
	}
	return cfg.MITMCAPath
}

// warnOpenControlPlane logs a boot-time warning when the control
// plane runs the open `demo` policy set (the default). Demo admits
// anonymous reads of the full policy/service surface and anonymous
// proposal writes — fine on a laptop, a tampering vector on a shared
// network. The warning keeps the demo quickstart friction-free while
// making sure a production operator can't run open by accident.
func warnOpenControlPlane(cfg *config) {
	if admin.PolicySet(cfg.InternalPolicies) != admin.PolicySetDemo {
		return
	}
	slog.Warn("control plane is running the open `demo` policy set: "+
		"anonymous callers can list/export policies, run dry-runs, and write to the proposal queue",
		"fix", "set --internal-policies=simple or production for anything beyond a local demo")
}

// listenerMode returns the short label slog uses on the boot line so
// `journalctl | grep listening` is enough to confirm whether the
// listener is mitm'd or not.
func listenerMode(cfg *config) string {
	if cfg.MITM {
		return "mitm"
	}
	return "path-prefix"
}

// setupObservability installs the global slog logger + tracer from
// the already-typed observability fields on cfg. Parsing happened at
// config-load time, so this is a pure pass-through.
func setupObservability(cfg *config) (observability.Shutdown, error) {
	return observability.Setup(context.Background(), observability.Config{
		ServiceName:    cfg.OTelService,
		ServiceVersion: cfg.OTelVersion,
		LogLevel:       cfg.LogLevel,
		LogFormat:      cfg.LogFormat,
		Exporter:       cfg.OTelExporter,
	})
}

// newHTTPServer wires an `http.Server` from cfg's timeout fields.
// Factored out of `main` so a test can construct the same server (with
// the same Read* timeouts) and verify a slowloris client is closed
// within the budget.
func newHTTPServer(cfg *config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		ReadHeaderTimeout: cfg.InboundReadHeaderTimeout,
		ReadTimeout:       cfg.InboundReadTimeout,
		WriteTimeout:      cfg.InboundWriteTimeout,
		IdleTimeout:       cfg.InboundIdleTimeout,
	}
}
