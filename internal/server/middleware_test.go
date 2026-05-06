package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAccessLogEmitsFields exercises the middleware in isolation so
// failures here point at the logger rather than the proxy hot path.
// Captures slog output through a JSON handler so the assertion is
// exact: each field by name + type, no string scraping.
func TestAccessLogEmitsFields(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("brewing"))
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/echo?q=1", nil)
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.RemoteAddr = "203.0.113.7:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusTeapot, rec.Code)

	var rec1 map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec1))
	require.Equal(t, "request", rec1["msg"])
	require.Equal(t, "GET", rec1["method"])
	require.Equal(t, "/echo", rec1["path"])
	require.Equal(t, "q=1", rec1["query"])
	require.EqualValues(t, http.StatusTeapot, rec1["status"])
	require.EqualValues(t, len("brewing"), rec1["bytes"])
	require.Equal(t, "203.0.113.7:54321", rec1["remote_ip"])
	require.Equal(t, "test-agent/1.0", rec1["user_agent"])
	require.Contains(t, rec1, "duration")
}

// TestRedactQuery pins the access-log query redaction. The redactor
// scrubs values of known credential-bearing keys but leaves
// structural params (paginators, ids) intact so log lines stay
// debuggable. Comparison is case-insensitive.
func TestRedactQuery(t *testing.T) {
	cases := map[string]string{
		"":                        "",
		"page=2&q=hello":          "page=2&q=hello",
		"code=AUTH&state=xyz":     "code=%3Credacted%3E&state=xyz",
		"access_token=abc&page=2": "access_token=%3Credacted%3E&page=2",
		"refresh_token=abc":       "refresh_token=%3Credacted%3E",
		"Code=ABC":                "Code=%3Credacted%3E", // case-insensitive
		"client_secret=s3cret&grant_type=refresh": "client_secret=%3Credacted%3E&grant_type=refresh",
	}
	for in, want := range cases {
		got := redactQuery(in)
		// url.Values.Encode sorts keys alphabetically — compare via a
		// re-parse so the test doesn't pin the iteration order of
		// untouched query strings (returned verbatim) against a
		// rebuilt one.
		gotV, _ := url.ParseQuery(got)
		wantV, _ := url.ParseQuery(want)
		if got != in && len(gotV) != len(wantV) {
			t.Errorf("redactQuery(%q) = %q; cardinality mismatch with %q", in, got, want)
			continue
		}
		for k, vs := range wantV {
			if gv := gotV[k]; len(gv) != len(vs) || (len(gv) > 0 && gv[0] != vs[0]) {
				t.Errorf("redactQuery(%q): %q = %v, want %v", in, k, gv, vs)
			}
		}
	}
}

// TestAccessLogRedactsSensitiveQuery confirms the redactor is wired
// into the access log path.
func TestAccessLogRedactsSensitiveQuery(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	req := httptest.NewRequest(http.MethodGet, "/oauth/cb?code=secret&state=ok", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	var rec map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec))
	q := rec["query"].(string)
	require.NotContains(t, q, "secret", "raw code value must not be logged")
	require.Contains(t, q, "redacted")
	require.Contains(t, q, "state=ok", "non-sensitive params still logged")
}

// TestAccessLogDefaultsStatusToOK: a handler that returns without
// calling WriteHeader should still log status=200, not 0.
func TestAccessLogDefaultsStatusToOK(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	h := accessLog(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	var rec map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec))
	require.EqualValues(t, http.StatusOK, rec["status"])
}

// TestRecovererCatchesPanic: a panicking handler returns 500 with
// the generic body, logs via slog, and never bubbles the panic past
// the middleware.
func TestRecovererCatchesPanic(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	h := recoverer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	require.NotPanics(t, func() {
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	})

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "server error")

	var entry map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry))
	require.Equal(t, "panic recovered", entry["msg"])
	require.Equal(t, "ERROR", entry["level"])
	require.Equal(t, "boom", entry["value"])
	require.Contains(t, entry, "stack")
}

// TestRecovererRethrowsAbortHandler: net/http relies on a panic with
// http.ErrAbortHandler to abort a connection without logging. The
// recoverer must let it propagate or we silently turn aborts into
// 500s.
func TestRecovererRethrowsAbortHandler(t *testing.T) {
	h := recoverer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	require.PanicsWithValue(t, http.ErrAbortHandler, func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	})
}

// TestAccessLogRecordsPanicAs500: order matters — recoverer is
// inside accessLog, so the access line for a panicking handler
// should report status=500 rather than the default 200.
func TestAccessLogRecordsPanicAs500(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	h := accessLog(recoverer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	})))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	// Two records — the panic recovery and the access log. The
	// access record is "request"; pick it out.
	var access map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var rec map[string]any
		require.NoError(t, json.Unmarshal(line, &rec))
		if rec["msg"] == "request" {
			access = rec
		}
	}
	require.NotNil(t, access, "access log entry not found")
	require.EqualValues(t, http.StatusInternalServerError, access["status"])
	require.Equal(t, "ERROR", access["level"])
}

// TestAccessLogLevelEscalatesOn5xx: 5xx responses are emitted at
// Error level so a server-error filter on the log stream surfaces
// them without parsing the status field.
func TestAccessLogLevelEscalatesOn5xx(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	var rec map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec))
	require.Equal(t, "ERROR", rec["level"])
}
