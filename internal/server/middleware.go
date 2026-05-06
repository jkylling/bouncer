package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// accessLog emits one structured slog line per inbound HTTP request.
// Fields follow the de-facto access-log shape (method, path, status,
// duration, bytes, remote_ip, user_agent), which keeps the output
// usable from any tool that already understands one of the standard
// log formats.
//
// trace_id / span_id are added by the global slog handler whenever
// the record's context carries an active span (otelhttp installs one
// before this middleware runs), so the access log line doubles as
// the request-id index — no separate request-id middleware needed.
//
// chi's middleware.WrapResponseWriter captures status + bytes without
// the panic-prone "wrap and forward" boilerplate; chi's RealIP runs
// upstream of this so r.RemoteAddr already reflects X-Forwarded-For
// / X-Real-IP when present.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		// Status defaults to 200 if the handler never wrote a header
		// before returning — match net/http's behaviour rather than
		// log "0".
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}

		slog.LogAttrs(r.Context(), accessLogLevel(status), "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("query", redactQuery(r.URL.RawQuery)),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
			slog.Int("bytes", ww.BytesWritten()),
			slog.String("remote_ip", r.RemoteAddr),
			slog.String("user_agent", r.UserAgent()),
		)
	})
}

// sensitiveQueryParams enumerates query keys whose values commonly
// carry credentials (OAuth2 redirect codes, signed download URLs,
// id-token rotations). The access log redacts them in place rather
// than dropping the whole query string so structural debugging
// (which endpoint was hit with which paginator) still works.
//
// Comparison is case-insensitive; the canonical lowercase form
// matches Google's documented param names but covers any client that
// uses an alternate case.
var sensitiveQueryParams = map[string]struct{}{
	"code":          {},
	"access_token":  {},
	"refresh_token": {},
	"id_token":      {},
	"token":         {},
	"api_key":       {},
	"key":           {},
	"client_secret": {},
	"password":      {},
	"secret":        {},
	"assertion":     {},
}

// redactQuery preserves the query-string shape but replaces values
// of sensitive keys with `<redacted>`. On parse failure the function
// returns the sentinel "<unparseable>" rather than the raw input —
// url.ParseQuery may have already consumed credential params before
// hitting the malformed segment (`?code=…&bad=%gg`), and returning
// raw would let those leak into the access log. We trade structural
// debuggability for credential safety.
func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "<unparseable>"
	}
	dirty := false
	for k, vs := range values {
		if _, bad := sensitiveQueryParams[strings.ToLower(k)]; !bad {
			continue
		}
		for i := range vs {
			if vs[i] != "" {
				vs[i] = "<redacted>"
				dirty = true
			}
		}
		values[k] = vs
	}
	if !dirty {
		return raw
	}
	return values.Encode()
}

// recoverer catches panics from downstream handlers, logs the panic
// + stack trace via slog (so it carries the request's trace_id), marks
// the active otel span as errored, and writes a generic 500 to the
// client. Lives *inside* accessLog so the access-log line records
// status=500 instead of the default 0 (which the access logger
// rewrites to 200) when a handler panics.
//
// http.ErrAbortHandler is the stdlib's documented "I want to abort
// this request without logging" sentinel; net/http itself silently
// drops it before reaching the client. We re-panic so the runtime
// keeps that contract.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rv := recover()
			if rv == nil {
				return
			}
			if rv == http.ErrAbortHandler {
				panic(rv)
			}
			err := fmt.Errorf("panic: %v", rv)
			if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
				span.RecordError(err, trace.WithStackTrace(true))
				span.SetStatus(codes.Error, "panic")
			}
			slog.ErrorContext(r.Context(), "panic recovered",
				"method", r.Method,
				"path", r.URL.Path,
				"value", fmt.Sprintf("%v", rv),
				"stack", string(debug.Stack()),
			)
			http.Error(w, "server error", http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// accessLogLevel maps response status to the slog level the access
// line is emitted at: 5xx errors are surfaced louder (Error), 4xx
// stays Info because client-fault responses are normal traffic, and
// success is Info. Operators who want to drop successful traffic can
// raise the global level to Warn without losing 5xx.
func accessLogLevel(status int) slog.Level {
	switch {
	case status >= 500:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
