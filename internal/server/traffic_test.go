package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/server/admin"
)

// adminBearer is the local helper for traffic e2e tests that need
// to hit admin-tier endpoints. Mirrors the admin package's test
// helper.
func adminBearer(t *testing.T, keys *auth.ServerKeys) string {
	t.Helper()
	tok, err := auth.IssueAccessToken(keys, "test-admin",
		auth.AccessCreds{AccessToken: "x"}, time.Hour, true)
	if err != nil {
		t.Fatalf("issue admin: %v", err)
	}
	return "Bearer " + tok
}

// notifyingRecorder wraps a Recorder and signals every Record call.
// The proxy flushes the response to the client before the handler's
// deferred recorder commit runs, so a test can't treat
// request-completion as commit-completion; blocking on the Record
// signal and then draining the inner AsyncRecorder via Close() makes
// the store contents deterministic without polling.
type notifyingRecorder struct {
	inner    Recorder
	recorded chan struct{}
}

func newNotifyingRecorder(inner Recorder) *notifyingRecorder {
	return &notifyingRecorder{inner: inner, recorded: make(chan struct{}, 16)}
}

func (n *notifyingRecorder) Record(ctx context.Context, ev traffic.Event) {
	n.inner.Record(ctx, ev)
	n.recorded <- struct{}{}
}

// wait blocks until one Record call has happened. The timeout is a
// failure guard, not a poll interval.
func (n *notifyingRecorder) wait(t *testing.T) {
	t.Helper()
	select {
	case <-n.recorded:
	case <-time.After(5 * time.Second):
		t.Fatal("recorder was never invoked")
	}
}

// TestTrafficEndToEndCaptureAndQuery exercises the full Phase 2 flow:
// a real proxy request flows through the recorder, lands in the store,
// and is then queryable through the admin /_api/traffic endpoints on
// the same listener. Pinning round-trips via PUT /pin.
func TestTrafficEndToEndCaptureAndQuery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)

	s := traffic.NewMemoryStore(traffic.Options{})
	defer s.Close()
	rec := traffic.NewAsyncRecorder(s, traffic.RecorderOptions{})
	defer rec.Close()
	nrec := newNotifyingRecorder(rec)

	srv := NewServer(Dependencies{
		Runtime:      rt,
		Keys:         keys,
		HTTPClient:   upstream.Client(),
		APIFactory:   gmailFactory,
		Recorder:     nrec,
		TrafficStore: s,
	})

	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	// Drive one permitted request through the data plane.
	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("data plane: %v", err)
	}
	resp.Body.Close()

	// Wait for the deferred commit to hand the event to the
	// AsyncRecorder, then drain its writer goroutine into the store.
	nrec.wait(t)
	if err := rec.Close(); err != nil {
		t.Fatalf("rec close: %v", err)
	}

	// List rows via the admin endpoint.
	listReq, _ := http.NewRequest(http.MethodGet, proxy.URL+admin.TrafficListPath, nil)
	listReq.Header.Set("Authorization", adminBearer(t, keys))
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != 200 {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("list status = %d, body = %s", listResp.StatusCode, body)
	}
	var listed struct {
		Rows []traffic.Summary `json:"rows"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Rows) != 1 {
		t.Fatalf("listed %d rows, want 1", len(listed.Rows))
	}
	row := listed.Rows[0]
	if row.API != "google.gmail" || row.Decision != traffic.DecisionPermit {
		t.Errorf("row = %+v, want gmail/permit", row)
	}
	if row.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", row.Subject)
	}

	// Fetch the full event.
	getReq, _ := http.NewRequest(http.MethodGet, proxy.URL+"/_api/traffic/"+row.ID.String(), nil)
	getReq.Header.Set("Authorization", adminBearer(t, keys))
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer getResp.Body.Close()
	var ev traffic.Event
	if err := json.NewDecoder(getResp.Body).Decode(&ev); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if ev.UpstreamStatus != http.StatusOK {
		t.Errorf("upstream_status = %d, want 200", ev.UpstreamStatus)
	}
	// The gmail "read" policy binds `message` and `mailbox`; the
	// condition reads outputs on both, so both meta side calls
	// should land in the captured fetch list and both bound values
	// should round-trip in the recorded JSON.
	if ev.Action != "get_message" {
		t.Errorf("event.action = %q, want get_message", ev.Action)
	}
	if ev.Policy != "read" {
		t.Errorf("event.policy = %q, want read", ev.Policy)
	}
	bindNames := map[string]bool{}
	for _, b := range ev.Binds {
		bindNames[b.Name] = true
	}
	for _, want := range []string{"google.gmail.message", "google.gmail.mailbox"} {
		if !bindNames[want] {
			t.Errorf("missing bind %q in %v", want, bindNames)
		}
	}
	wantPaths := map[string]bool{
		"/gmail/v1/users/42/messages/abc?format=metadata": false,
		"/gmail/v1/users/42/profile":                      false,
	}
	for _, f := range ev.MetaFetches {
		if _, ok := wantPaths[f.Path]; !ok {
			t.Errorf("unexpected meta fetch path %q", f.Path)
			continue
		}
		wantPaths[f.Path] = true
		if f.Status != http.StatusOK {
			t.Errorf("fetch %q status = %d, want 200", f.Path, f.Status)
		}
	}
	for path, seen := range wantPaths {
		if !seen {
			t.Errorf("missing meta fetch for %q", path)
		}
	}
}

// TestTrafficRoutesUnmountedWithoutStore is a regression guard: when
// no store is configured, the /_api/traffic routes must not exist —
// otherwise they would 500 against a nil store.
func TestTrafficRoutesUnmountedWithoutStore(t *testing.T) {
	rt := loadGmailRuntime(t, "")
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	// Deliberately leave SetTrafficStore unset.
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + admin.TrafficListPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	// chi falls through to the proxy's catch-all (`/*`), which then
	// fails authentication — i.e. we get 401 rather than 200/500. The
	// point is that the traffic handler is not reached.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("status = 200, want non-200 (route should be unmounted)")
	}
}

// TestTrafficCaptureLatency covers a tiny lifecycle assertion: the
// LatencyMS field is populated and non-negative for a request that
// actually flows through evaluate.
func TestTrafficCaptureLatency(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Millisecond)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)

	s := traffic.NewMemoryStore(traffic.Options{})
	defer s.Close()
	rec := traffic.NewAsyncRecorder(s, traffic.RecorderOptions{})
	nrec := newNotifyingRecorder(rec)
	srv := NewServer(Dependencies{
		Runtime:    rt,
		Keys:       keys,
		HTTPClient: upstream.Client(),
		APIFactory: gmailFactory,
		Recorder:   nrec,
	})

	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	nrec.wait(t)
	rec.Close()

	rows, _, _ := s.List(context.Background(), traffic.ListOpts{})
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].LatencyMS < 1 {
		t.Errorf("LatencyMS = %d, want >= 1 (upstream slept 2ms)", rows[0].LatencyMS)
	}
}

// TestTrafficSkipsNoMatchRequests pins that paths no API claims
// (favicon, typo'd URLs, browser auto-fetches) never make it into
// the store. The recorder filters them at commit so the byte budget
// stays focused on policy-evaluated traffic.
func TestTrafficSkipsNoMatchRequests(t *testing.T) {
	rt := loadGmailRuntime(t, "")
	keys := mustKeys(t)

	s := traffic.NewMemoryStore(traffic.Options{})
	defer s.Close()
	rec := traffic.NewAsyncRecorder(s, traffic.RecorderOptions{})
	srv := NewServer(Dependencies{
		Runtime:    rt,
		Keys:       keys,
		APIFactory: gmailFactory,
		Recorder:   rec,
	})

	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	// A path no API claims, with a valid JWT so authenticate
	// succeeds and the request reaches the no_match branch in
	// handle. /favicon.ico has its own admin route now, so use a
	// generic typo path.
	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/totally/unknown/path", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no API claims this path)", resp.StatusCode)
	}
	rec.Close()

	rows, _, _ := s.List(context.Background(), traffic.ListOpts{})
	if len(rows) != 0 {
		t.Errorf("rows = %d, want 0 — no_match must not record", len(rows))
	}
}

// TestFaviconBypassesAuth pins the route ordering: /favicon.ico
// resolves at the admin layer, so a browser auto-fetch with no
// Authorization header succeeds rather than landing on the
// catch-all proxy handler that would 401 it.
func TestFaviconBypassesAuth(t *testing.T) {
	rt := loadGmailRuntime(t, "")
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/favicon.ico")
	if err != nil {
		t.Fatalf("get favicon: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("Content-Type = %q, want image/svg+xml", ct)
	}
}
