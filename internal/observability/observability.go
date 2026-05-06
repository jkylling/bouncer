// Package observability sets up structured logging (slog) and
// distributed tracing (OpenTelemetry) for the binary. One Setup call
// at boot installs the slog default logger, the global tracer, and the
// global propagator; the returned Shutdown drains spans before the
// process exits.
//
// The slog handler is wrapped so any log line emitted with a context
// carrying an active span gets `trace_id` / `span_id` attributes for
// free — no caller-side bookkeeping. The tracer provider is no-op
// unless an exporter is selected, so every binary that imports this
// package pays only for what it asks for.
//
// Span attribute names live in `attrs.go` so they can be reused by the
// future traffic viewer (strategy/follow-ups/04) without a second copy
// drifting from the tracing taxonomy.
package observability

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
)

// Exporter selects how spans leave the process. `none` keeps the
// global tracer no-op (zero overhead, default); `stdout` prints
// human-readable spans for local debugging; `otlphttp` ships them to
// an OTLP/HTTP collector configured via the standard OTEL_* env vars.
type Exporter string

const (
	ExporterNone     Exporter = "none"
	ExporterStdout   Exporter = "stdout"
	ExporterOTLPHTTP Exporter = "otlphttp"
)

// LogFormat selects the slog handler shape.
type LogFormat string

const (
	LogFormatText LogFormat = "text"
	LogFormatJSON LogFormat = "json"
)

// Config gathers the knobs Setup needs. ServiceName + ServiceVersion
// flow into the OTel Resource so spans are searchable by service in
// the collector.
type Config struct {
	ServiceName    string
	ServiceVersion string
	LogLevel       slog.Level
	LogFormat      LogFormat
	Exporter       Exporter
}

// Shutdown drains pending spans and tears down the tracer provider.
// Always call it at process exit (typically via `defer`).
type Shutdown func(context.Context) error

// Setup installs the slog default logger, the global TracerProvider,
// and the W3C trace-context propagator. Returns a Shutdown that should
// be invoked before the process exits so any buffered spans flush.
//
// Errors come from exporter construction (e.g. malformed OTLP env
// vars) — slog setup is infallible.
func Setup(ctx context.Context, cfg Config) (Shutdown, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "bouncer"
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = LogFormatText
	}
	if cfg.Exporter == "" {
		cfg.Exporter = ExporterNone
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}

	tp, err := newTracerProvider(ctx, cfg.Exporter, res)
	if err != nil {
		return nil, err
	}
	otel.SetTracerProvider(tp)
	// W3C Baggage is deliberately NOT installed: the propagator
	// forwards arbitrary `Baggage:` headers from the inbound caller
	// onto every outbound upstream call, which is an attacker-
	// controlled metadata channel a Google API or other upstream
	// might log, index, or use to colour a request. TraceContext is
	// safe (server-generated trace+span ids only) and is what the
	// otelhttp instrumentation needs for cross-process correlation.
	otel.SetTextMapPropagator(propagation.TraceContext{})

	slog.SetDefault(newLogger(os.Stderr, cfg))

	return func(ctx context.Context) error { return tp.Shutdown(ctx) }, nil
}

// newTracerProvider builds the SDK provider for the chosen exporter.
// `none` returns a real provider with no span processors so the
// tracer API (Start/End, attributes) keeps working but spans never
// reach a backend — equivalent to the default no-op without forcing
// callers to special-case ctx propagation.
func newTracerProvider(ctx context.Context, exp Exporter, res *resource.Resource) (*sdktrace.TracerProvider, error) {
	opts := []sdktrace.TracerProviderOption{sdktrace.WithResource(res)}
	switch exp {
	case ExporterNone:
		// No span processor → no exports. The provider is still real
		// so spans created by the application carry valid IDs that the
		// slog handler can pick up and tag onto log records.
	case ExporterStdout:
		exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("stdout exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	case ExporterOTLPHTTP:
		// otlptracehttp.New honours the standard OTEL_EXPORTER_OTLP_*
		// env vars (endpoint, headers, compression, timeout) so an
		// operator who already speaks the OTel-collector dialect needs
		// no extra flags.
		exporter, err := otlptrace.New(ctx, otlptracehttp.NewClient())
		if err != nil {
			return nil, fmt.Errorf("otlphttp exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	default:
		return nil, fmt.Errorf("unknown otel exporter %q (none|stdout|otlphttp)", exp)
	}
	return sdktrace.NewTracerProvider(opts...), nil
}

// newLogger picks a base text/JSON handler and wraps it so any log
// line emitted with a context carrying an active span gets the
// span's trace and span IDs attached as attributes. Exposed only for
// tests; production callers should use Setup which calls slog.SetDefault.
func newLogger(w io.Writer, cfg Config) *slog.Logger {
	hopts := &slog.HandlerOptions{Level: cfg.LogLevel}
	var base slog.Handler
	if cfg.LogFormat == LogFormatJSON {
		base = slog.NewJSONHandler(w, hopts)
	} else {
		base = slog.NewTextHandler(w, hopts)
	}
	return slog.New(&traceHandler{inner: base})
}

// traceHandler injects trace_id / span_id from the record's context
// when a span is active. Implemented as a thin wrapper rather than a
// new handler: every other concern (level filtering, formatting,
// stderr writing) belongs to the inner handler.
type traceHandler struct {
	inner slog.Handler
}

func (h *traceHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.inner.Enabled(ctx, lvl)
}

func (h *traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.inner.Handle(ctx, r)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
	return &traceHandler{inner: h.inner.WithGroup(name)}
}

// UnmarshalText lets LogFormat satisfy encoding.TextUnmarshaler so a
// caller can parse a CLI/env value directly into the typed field
// without a separate validator. slog.Level already implements the
// same interface in the standard library, so the three observability
// knobs share one parsing convention.
func (f *LogFormat) UnmarshalText(b []byte) error {
	switch strings.ToLower(strings.TrimSpace(string(b))) {
	case "text":
		*f = LogFormatText
	case "json":
		*f = LogFormatJSON
	default:
		return fmt.Errorf("invalid log format %q (text|json)", b)
	}
	return nil
}

// UnmarshalText lets Exporter satisfy encoding.TextUnmarshaler.
// `otlp` is accepted as a friendly alias for `otlphttp` since
// otlphttp is the only OTLP transport this binary supports.
func (e *Exporter) UnmarshalText(b []byte) error {
	switch strings.ToLower(strings.TrimSpace(string(b))) {
	case "none":
		*e = ExporterNone
	case "stdout":
		*e = ExporterStdout
	case "otlphttp", "otlp":
		*e = ExporterOTLPHTTP
	default:
		return fmt.Errorf("invalid otel exporter %q (none|stdout|otlphttp)", b)
	}
	return nil
}

// ShutdownWithTimeout invokes s with a fresh deadline-bounded context
// so a stuck collector cannot block process exit. Returns whatever s
// returns (the OTel SDK forwards the deadline error on its own).
func ShutdownWithTimeout(s Shutdown, d time.Duration) error {
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return s(ctx)
}
