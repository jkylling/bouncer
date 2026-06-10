package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// buildUploadRuntime compiles a single-action upload API plus the
// given permit policy condition into a Runtime.
func buildUploadRuntime(t *testing.T, baseURL, condition string) *runtime.Runtime {
	t.Helper()
	api := &models.API{
		Name:         "files.api",
		BaseURL:      baseURL,
		PathPrefixes: []string{"/files"},
		Actions: []models.Action{
			{Name: "upload", Method: "POST", Path: "/files/upload"},
		},
	}
	b := runtime.NewBuilder()
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := rt.AddPolicy(&models.Policy{
		API:       "files.api",
		Name:      "allow",
		Result:    models.Permit,
		Condition: condition,
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	return rt
}

// TestBodyBlindAPIStreamsLargeUploads pins the stream-vs-buffer
// split: when nothing on the matched API reads request.body, an
// upload far beyond MaxRequestBody must flow through to the upstream
// intact instead of being buffered and 413'd.
func TestBodyBlindAPIStreamsLargeUploads(t *testing.T) {
	var gotLen int64
	var gotContentLength int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		gotLen, gotContentLength = n, r.ContentLength
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rt := buildUploadRuntime(t, upstream.URL, `request.method == "POST"`)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{
		Runtime:        rt,
		Keys:           keys,
		HTTPClient:     upstream.Client(),
		APIFactory:     gmailFactory,
		MaxRequestBody: 64, // far below the upload size
	})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	payload := bytes.Repeat([]byte("x"), 16*1024)
	req, _ := http.NewRequest("POST", proxy.URL+"/files/upload", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+issueJWT(t, keys, "tok"))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
	}
	if gotLen != int64(len(payload)) {
		t.Errorf("upstream received %d bytes, want %d", gotLen, len(payload))
	}
	if gotContentLength != int64(len(payload)) {
		t.Errorf("upstream Content-Length = %d, want %d (length signal must survive streaming)", gotContentLength, len(payload))
	}
}

// TestBodyUsingAPIKeepsBufferedCap pins the other side of the split:
// when a policy reads request.body, the body must be buffered for
// evaluation and the cap enforced — fail-closed rather than letting
// an oversized body bypass a body-gated policy.
func TestBodyUsingAPIKeepsBufferedCap(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must not be reached when the buffered cap rejects the body")
	}))
	defer upstream.Close()

	rt := buildUploadRuntime(t, upstream.URL, `request.body.?kind.orValue("") == "ok"`)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{
		Runtime:        rt,
		Keys:           keys,
		HTTPClient:     upstream.Client(),
		APIFactory:     gmailFactory,
		MaxRequestBody: 64,
	})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	payload := bytes.Repeat([]byte("x"), 1024)
	req, _ := http.NewRequest("POST", proxy.URL+"/files/upload", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+issueJWT(t, keys, "tok"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 413; body = %s", resp.StatusCode, body)
	}
}
