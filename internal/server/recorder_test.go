package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jkylling/bouncer/internal/control/traffic"
)

// captureRecorder is a tiny in-process Recorder that lets tests
// inspect the events the server hands to the recorder hook. Channel-
// less so a single Record-then-assert in a test stays linear without
// goroutine bookkeeping.
type captureRecorder struct {
	mu     sync.Mutex
	events []traffic.Event
}

func (c *captureRecorder) Record(_ context.Context, ev traffic.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *captureRecorder) snapshot() []traffic.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]traffic.Event, len(c.events))
	copy(out, c.events)
	return out
}

func TestRecorderCapturesPermitForwardedRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // distinctive status
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(rt, keys, upstream.Client(), gmailFactory, 0)
	rec := &captureRecorder{}
	srv.SetRecorder(rec)
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc?q=label:inbox", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("captured %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.Method != "GET" || ev.API != "gmail" {
		t.Errorf("event = %+v, want method GET / api gmail", ev)
	}
	if ev.Decision != traffic.DecisionPermit {
		t.Errorf("decision = %q, want permit", ev.Decision)
	}
	if ev.UpstreamStatus != http.StatusTeapot {
		t.Errorf("upstream_status = %d, want %d", ev.UpstreamStatus, http.StatusTeapot)
	}
	if ev.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", ev.Subject)
	}
	if ev.URL != "/gmail/v1/users/42/messages/abc?q=label:inbox" {
		t.Errorf("url = %q, want path+query", ev.URL)
	}
	if ev.LatencyMS < 0 {
		t.Errorf("latency = %d, want >= 0", ev.LatencyMS)
	}
	if ev.ID == "" {
		t.Error("ID empty, want non-empty")
	}
}

func TestRecorderCapturesUnauthorized(t *testing.T) {
	rt := loadGmailRuntime(t, "")
	keys := mustKeys(t)
	srv := NewServer(rt, keys, nil, gmailFactory, 0)
	rec := &captureRecorder{}
	srv.SetRecorder(rec)
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/gmail/v1/users/42/profile")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("captured %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.Decision != traffic.DecisionError {
		t.Errorf("decision = %q, want %q", ev.Decision, traffic.DecisionError)
	}
	if ev.UpstreamStatus != 0 {
		t.Errorf("upstream_status = %d, want 0 on auth failure", ev.UpstreamStatus)
	}
	if ev.Subject != "" {
		t.Errorf("subject = %q, want empty (unauthorized)", ev.Subject)
	}
	if ev.Error == "" {
		t.Error("error empty, want a populated error string for unauthorized")
	}
}

// TestRecorderCapturesPolicyEvaluations pins the per-request policy
// evaluation trace: every (policy, action) condition the runtime ran
// shows up in Event.PolicyEvaluations in order, with the deciding
// policy as the last entry (Fired=true). The fixture has two gmail
// policies (read, delete); a get_message hits the `read` policy and
// fires it.
func TestRecorderCapturesPolicyEvaluations(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(rt, keys, upstream.Client(), gmailFactory, 0)
	rec := &captureRecorder{}
	srv.SetRecorder(rec)
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("captured %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.Decision != traffic.DecisionPermit {
		t.Fatalf("decision = %q, want permit", ev.Decision)
	}
	if len(ev.PolicyEvaluations) == 0 {
		t.Fatal("PolicyEvaluations empty, want at least the firing entry")
	}
	last := ev.PolicyEvaluations[len(ev.PolicyEvaluations)-1]
	if !last.Fired {
		t.Errorf("last entry %+v, want Fired=true", last)
	}
	if last.Policy != "read" || last.Action != "get_message" || last.Result != "permit" {
		t.Errorf("last entry = %+v, want (read, get_message, permit)", last)
	}
}

// TestCloneRequestHeadersStripsCredentials pins S2: the recorder's
// channel-buffered Event must never carry plaintext bearer tokens
// or session cookies even before Sanitize runs.
func TestCloneRequestHeadersStripsCredentials(t *testing.T) {
	h := http.Header{
		"Authorization":       []string{"Bearer secret-jwt"},
		"Cookie":              []string{"sid=secret"},
		"Set-Cookie":          []string{"sid=different"},
		"Proxy-Authorization": []string{"Basic xxx"},
		"X-Trace":             []string{"abc"},
		"User-Agent":          []string{"test/1.0"},
	}
	got := cloneRequestHeaders(h)
	for _, kv := range got {
		switch strings.ToLower(kv.Key) {
		case "authorization", "cookie", "set-cookie", "proxy-authorization":
			t.Errorf("credential header %q survived clone: %q", kv.Key, kv.Value)
		}
	}
	// And the surviving headers are sorted by key.
	for i := 1; i < len(got); i++ {
		if strings.ToLower(got[i-1].Key) > strings.ToLower(got[i].Key) {
			t.Errorf("not sorted: %q before %q", got[i-1].Key, got[i].Key)
		}
	}
}

func TestRecorderNilSafe(t *testing.T) {
	rt := loadGmailRuntime(t, "")
	keys := mustKeys(t)
	srv := NewServer(rt, keys, nil, gmailFactory, 0)
	// Deliberately leave srv.recorder == nil — handle must not
	// panic and must work normally.
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/gmail/v1/users/42/profile")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}
