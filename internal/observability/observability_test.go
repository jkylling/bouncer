package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestLogFormatUnmarshalText(t *testing.T) {
	cases := map[string]LogFormat{
		"text": LogFormatText,
		"TEXT": LogFormatText,
		"json": LogFormatJSON,
		"JSON": LogFormatJSON,
	}
	for in, want := range cases {
		var got LogFormat
		require.NoError(t, got.UnmarshalText([]byte(in)), in)
		require.Equal(t, want, got, in)
	}
	var f LogFormat
	require.Error(t, f.UnmarshalText([]byte("yaml")))
	require.Error(t, f.UnmarshalText([]byte("")))
}

func TestExporterUnmarshalText(t *testing.T) {
	cases := map[string]Exporter{
		"none":     ExporterNone,
		"stdout":   ExporterStdout,
		"otlphttp": ExporterOTLPHTTP,
		"otlp":     ExporterOTLPHTTP,
		"OTLP":     ExporterOTLPHTTP,
	}
	for in, want := range cases {
		var got Exporter
		require.NoError(t, got.UnmarshalText([]byte(in)), in)
		require.Equal(t, want, got, in)
	}
	var e Exporter
	require.Error(t, e.UnmarshalText([]byte("kafka")))
	require.Error(t, e.UnmarshalText([]byte("")))
}

// TestLoggerInjectsTraceID exercises the slog handler chain end-to-end:
// emit a log line within a span and assert the JSON output carries the
// span's trace_id and span_id. Picks JSON so the assertion is exact —
// the text handler escapes differently per platform.
func TestLoggerInjectsTraceID(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	otel.SetTracerProvider(tp)

	var buf bytes.Buffer
	logger := newLogger(&buf, Config{LogFormat: LogFormatJSON})

	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	logger.InfoContext(ctx, "hello")
	span.End()

	var rec map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec))
	require.Equal(t, span.SpanContext().TraceID().String(), rec["trace_id"])
	require.Equal(t, span.SpanContext().SpanID().String(), rec["span_id"])
	require.Equal(t, "hello", rec["msg"])
}

// TestLoggerWithoutSpan: outside a span no trace fields are added.
func TestLoggerWithoutSpan(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf, Config{LogFormat: LogFormatText})
	logger.InfoContext(context.Background(), "no-span")
	out := buf.String()
	require.Contains(t, out, "no-span")
	require.False(t, strings.Contains(out, "trace_id="))
}

// TestSetupShutdownNone: the default exporter is no-op but Setup must
// still install a working tracer + return a Shutdown that succeeds.
func TestSetupShutdownNone(t *testing.T) {
	shutdown, err := Setup(context.Background(), Config{ServiceName: "test"})
	require.NoError(t, err)
	require.NoError(t, shutdown(context.Background()))
}
