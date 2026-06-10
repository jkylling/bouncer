package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/apiclient"
	"github.com/jkylling/bouncer/internal/auth"
	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// fakeGmailAPI feeds the gmail `read` policy: profile.messagesTotal == 100
// and message.labelIds contains Label_1234.
type fakeGmailAPI struct{}

var _ compiled.PhysicalAPI = fakeGmailAPI{}

func (fakeGmailAPI) Call(_ context.Context, req *pb.MetaRequest) (*pb.Response, error) {
	var body map[string]any
	if req.GetPath() == "/gmail/v1/users/42/profile" {
		body = map[string]any{
			"emailAddress":  "abc@gmail.com",
			"messagesTotal": 100.0,
			"threadsTotal":  2.0,
			"historyId":     "1",
		}
	} else {
		body = map[string]any{
			"id":           "abc",
			"threadId":     "thread-1",
			"labelIds":     []any{"Label_1234"},
			"snippet":      "snippet",
			"historyId":    "100",
			"internalDate": "0",
			"sizeEstimate": 0.0,
			"payload": map[string]any{
				"mimeType": "text/plain",
				"headers":  []any{},
			},
		}
	}
	v, err := structpb.NewValue(body)
	if err != nil {
		return nil, err
	}
	return &pb.Response{Body: v}, nil
}

func mustKeys(t *testing.T) *auth.ServerKeys {
	t.Helper()
	var s [32]byte
	for i := range s {
		s[i] = 9
	}
	keys, err := auth.FromSecret(s)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	return keys
}

func issueJWT(t *testing.T, keys *auth.ServerKeys, upstreamToken string) string {
	t.Helper()
	tok, err := auth.IssueAccessToken(keys, "user-1", auth.AccessCreds{AccessToken: upstreamToken}, time.Minute, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

// loadGmailRuntime builds a Runtime fronting just the gmail API. If
// baseURL is non-empty, it overrides the YAML-declared upstream so
// tests can point the proxy at an httptest server.
func loadGmailRuntime(t *testing.T, baseURL string) *runtime.Runtime {
	t.Helper()
	repoRoot := filepath.Join("..", "..")
	apis, err := models.FromYAMLDir[models.API](filepath.Join(repoRoot, "testdata", "apis"))
	if err != nil {
		t.Fatalf("apis: %v", err)
	}
	policies, err := models.FromYAMLDir[models.Policy](filepath.Join(repoRoot, "testdata", "policies"))
	if err != nil {
		t.Fatalf("policies: %v", err)
	}
	var gmail *models.API
	for i := range apis {
		if apis[i].Name == "google.gmail" {
			gmail = &apis[i]
		}
	}
	if gmail == nil {
		t.Fatal("gmail missing")
	}
	if baseURL != "" {
		gmail.BaseURL = baseURL
	}
	b := runtime.NewBuilder()
	if err := b.AddAPI(gmail); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i := range policies {
		if policies[i].API != "google.gmail" {
			continue
		}
		if err := rt.AddPolicy(&policies[i]); err != nil {
			t.Fatalf("add policy %q: %v", policies[i].Name, err)
		}
	}
	return rt
}

// gmailFactory returns the canonical fake-physical factory used by
// most server tests. It ignores the api name (every test only fronts
// gmail) and the bearer.
func gmailFactory(string, auth.AccessCreds) (compiled.PhysicalAPI, error) {
	return fakeGmailAPI{}, nil
}

func TestPermitsAndForwards(t *testing.T) {
	var gotAuth, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if !strings.Contains(gotAuth, "fake-upstream-token") {
		t.Errorf("upstream auth = %q, want bearer fake-upstream-token", gotAuth)
	}
	if gotPath != "/gmail/v1/users/42/messages/abc" {
		t.Errorf("upstream path = %q", gotPath)
	}
}

// TestAccessDeniedStatusOverrideRemapsDeny pins the per-API status
// override on the policy-deny path: an API configured with
// access_denied_status=200 (the Slack convention) returns 200 +
// {ok:false, ...} where the default API would return 403. This
// mirrors how Slack's Web API surfaces application-level errors so
// Slack-aware SDKs can read body.ok without a transport-level
// failure layered on top.
func TestAccessDeniedStatusOverrideRemapsDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("upstream should not be reached on a deny")
	}))
	defer upstream.Close()

	api := &models.API{
		Name:               "slack.api",
		BaseURL:            upstream.URL,
		PathPrefixes:       []string{"/api"},
		AccessDeniedStatus: 200,
		Actions: []models.Action{
			{Name: "post_message", Method: "POST", Path: "/api/chat.postMessage"},
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

	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("POST", proxy.URL+"/api/chat.postMessage", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (per-API override); body = %s", resp.StatusCode, body)
	}
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, raw)
	}
	if got, ok := body["ok"]; !ok || got != false {
		t.Errorf("ok = %v (present=%v), want false", got, ok)
	}
	if body["api"] != "slack.api" {
		t.Errorf("api = %v, want slack", body["api"])
	}
	// Wire status remapped to 200, but the semantic label stays
	// "Forbidden" — `error: "OK"` would be self-contradictory next
	// to `ok: false`.
	if body["error"] != "Forbidden" {
		t.Errorf("error = %v, want Forbidden", body["error"])
	}
}

// TestAccessDeniedStatusOverrideRemapsAuthFail pins the same
// override on the 401 path: a missing Authorization header on a
// route claimed by an override-configured API returns the override
// status, not 401. The handler also drops the WWW-Authenticate
// challenge in that case (a 200 + Bearer challenge would be
// nonsensical to a Slack-style client).
func TestAccessDeniedStatusOverrideRemapsAuthFail(t *testing.T) {
	api := &models.API{
		Name:               "slack.api",
		BaseURL:            "https://slack.example",
		PathPrefixes:       []string{"/api"},
		AccessDeniedStatus: 200,
	}
	b := runtime.NewBuilder()
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/api/chat.postMessage", nil)
	// No Authorization header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 (per-API override on auth-fail)", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want empty when override remapped 401", got)
	}
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, raw)
	}
	if body["error"] != "Unauthorized" {
		t.Errorf("error = %v, want Unauthorized (semantic label preserved)", body["error"])
	}
}

// TestAuthFail401StaysWhenNoAPIMatched pins the fallback: a request
// to a path no API claims still 401s on missing auth (the override
// path needs an API to look the override up on).
func TestAuthFail401StaysWhenNoAPIMatched(t *testing.T) {
	rt := loadGmailRuntime(t, "https://example.invalid")
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/no-such-api/foo", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Errorf("WWW-Authenticate missing on natural 401")
	}
}

// TestFormUrlencodedBodyDoesNotFailParse pins the Slack-SDK case:
// a POST with `application/x-www-form-urlencoded` body must not
// 400 at the body-parse stage. The previous JSON-only path made
// every Slack-SDK call (slack-go, @slack/web-api, slack-sdk-python)
// trip on parse before policy ever ran, returning a plain-text
// "bad request" instead of policy-shaped output.
func TestFormUrlencodedBodyDoesNotFailParse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("POST",
		proxy.URL+"/gmail/v1/users/42/messages/abc",
		strings.NewReader("channel=C0123456789&text=hi"))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("400 at parse stage on form body: %s", body)
	}
}

// TestForwardStripsCookieAndProxyAuth pins the strip set: a Cookie
// or Proxy-Authorization header on the inbound request must not
// reach the upstream. The proxy is a Bearer endpoint; a stray
// session cookie that piggybacked on the JWT request would
// otherwise leak across a trust boundary the operator did not opt
// into.
func TestForwardStripsCookieAndProxyAuth(t *testing.T) {
	got := http.Header{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.Header {
			got.Set(k, r.Header.Get(k))
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-upstream-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Cookie", "session=secret")
	req.Header.Set("Proxy-Authorization", "Basic xxx")
	req.Header.Set("X-Trace", "keep-me")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if v := got.Get("Cookie"); v != "" {
		t.Errorf("upstream saw Cookie = %q, must be stripped", v)
	}
	if v := got.Get("Proxy-Authorization"); v != "" {
		t.Errorf("upstream saw Proxy-Authorization = %q, must be stripped", v)
	}
	if v := got.Get("X-Trace"); v != "keep-me" {
		t.Errorf("non-sensitive header dropped: X-Trace = %q", v)
	}
}

// TestForwardAppliesHeadersAndCookies pins the new credential
// surface: a token issued with extra Headers + Cookies stamps them
// on the outbound request, and operator-supplied headers override
// whatever the client sent (Set, not Add). The Slack browser-token
// case end-to-end through the proxy.
func TestForwardAppliesHeadersAndCookies(t *testing.T) {
	got := http.Header{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.Header {
			got.Set(k, r.Header.Get(k))
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt, err := auth.IssueAccessToken(keys, "u", auth.AccessCreds{
		AccessToken: "xoxc-fake",
		Headers: []auth.Header{
			{Name: "Origin", Value: "https://app.slack.com"},
			{Name: "Referer", Value: "https://app.slack.com/"},
			{Name: "Cookie", Value: "d=xoxd-fake"},
		},
	}, time.Minute, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Origin", "https://attacker.example") // must be overwritten
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if v := got.Get("Authorization"); v != "Bearer xoxc-fake" {
		t.Errorf("upstream Authorization = %q", v)
	}
	if v := got.Get("Origin"); v != "https://app.slack.com" {
		t.Errorf("upstream Origin = %q (client value not overwritten)", v)
	}
	if v := got.Get("Referer"); v != "https://app.slack.com/" {
		t.Errorf("upstream Referer = %q", v)
	}
	if v := got.Get("Cookie"); !strings.Contains(v, "d=xoxd-fake") {
		t.Errorf("upstream Cookie = %q, want d=xoxd-fake", v)
	}
}

// TestForwardWorksWithoutAccessToken pins the headers-only flow:
// a token can ride with no Authorization header at all if the
// upstream's auth model is purely cookie- or header-based (a `Cookie`
// row in Headers does the job).
func TestForwardWorksWithoutAccessToken(t *testing.T) {
	got := http.Header{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.Header {
			got.Set(k, r.Header.Get(k))
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt, err := auth.IssueAccessToken(keys, "u", auth.AccessCreds{
		Headers: []auth.Header{{Name: "Cookie", Value: "d=xoxd-only"}},
	}, time.Minute, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if v := got.Get("Authorization"); v != "" {
		t.Errorf("upstream Authorization = %q, want empty (no access token configured)", v)
	}
	if v := got.Get("Cookie"); !strings.Contains(v, "d=xoxd-only") {
		t.Errorf("upstream Cookie = %q", v)
	}
}

// TestUpstreamMetaErrorMaps verifies the apiclient.UpstreamError
// classification: a meta side call returning 401 surfaces as 401
// to the client (so the client knows to refresh its embedded
// upstream credential), 503 surfaces as 502 (bad gateway from the
// proxy's perspective), and a non-upstream eval bug surfaces as a
// structured 403 denial whose body stays generic — the raw CEL
// error (meta/policy names, JSON offsets) is log-only.
func TestUpstreamMetaErrorMaps(t *testing.T) {
	cases := []struct {
		name           string
		api            compiled.PhysicalAPI
		wantStatus     int
		wantBodyPrefix string
	}{
		{
			name:           "401 surfaces as 401",
			api:            errorAPI{err: &apiclient.UpstreamError{Status: 401, Body: "Invalid Credentials"}},
			wantStatus:     http.StatusUnauthorized,
			wantBodyPrefix: "upstream credentials invalid",
		},
		{
			name:           "503 surfaces as 502",
			api:            errorAPI{err: &apiclient.UpstreamError{Status: 503, Body: "down"}},
			wantStatus:     http.StatusBadGateway,
			wantBodyPrefix: "upstream meta request",
		},
		{
			name:           "404 surfaces as 404",
			api:            errorAPI{err: &apiclient.UpstreamError{Status: 404, Body: "Requested entity was not found."}},
			wantStatus:     http.StatusNotFound,
			wantBodyPrefix: "upstream object not found",
		},
		{
			name:           "non-upstream eval err fails closed as 403",
			api:            errorAPI{err: errors.New("CEL exploded")},
			wantStatus:     http.StatusForbidden,
			wantBodyPrefix: "policy evaluation error",
		},
	}
	rt := loadGmailRuntime(t, "")
	keys := mustKeys(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			factory := func(string, auth.AccessCreds) (compiled.PhysicalAPI, error) { return tc.api, nil }
			srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: factory})
			proxy := httptest.NewServer(srv.Router())
			defer proxy.Close()

			jwt := issueJWT(t, keys, "fake")
			req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
			req.Header.Set("Authorization", "Bearer "+jwt)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want %d, body = %s", resp.StatusCode, tc.wantStatus, body)
			}
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), "CEL exploded") {
				t.Errorf("body = %q leaks the internal eval error; detail must stay in the logs", body)
			}
			if !strings.Contains(string(body), tc.wantBodyPrefix) {
				t.Errorf("body = %q, want prefix %q", body, tc.wantBodyPrefix)
			}
		})
	}
}

// errorAPI fakes a meta side call that always errors with err.
type errorAPI struct{ err error }

func (e errorAPI) Call(_ context.Context, _ *pb.MetaRequest) (*pb.Response, error) {
	return nil, e.err
}

func TestMissingAuthReturns401(t *testing.T) {
	rt := loadGmailRuntime(t, "")
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/anything")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestRequestBodyOverCapReturns413 pins the fix on the
// inbound side: a POST whose body exceeds MaxRequestBodyBytes is
// rejected at the proxy edge instead of buffered in full. The
// upstream is intentionally unreachable — the test passes only if the
// proxy refuses the request before ever forwarding.
func TestRequestBodyOverCapReturns413(t *testing.T) {
	rt := loadGmailRuntime(t, "http://upstream.invalid")
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-token")
	body := strings.NewReader(strings.Repeat("a", int(MaxRequestBodyBytes)+1))
	req, _ := http.NewRequest("POST", proxy.URL+"/gmail/v1/users/42/messages/abc", body)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

// TestErrorResponsesDoNotLeakInternals pins a malformed
// JSON body triggers the parse-error path that previously surfaced
// `json: ...` diagnostics to the client. The fix turns those four
// `http.Error(w, "<context>: "+err.Error(), ...)` call sites into a
// generic message + structured server-side log, so an
// unauthenticated client can't probe internals via deliberate bad
// inputs.
func TestErrorResponsesDoNotLeakInternals(t *testing.T) {
	rt := loadGmailRuntime(t, "http://upstream.invalid")
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-token")
	// `{"a":` is valid Content-Type but invalid JSON — drives
	// parseJSONBody → buildPolicyRequest → the "bad request" path.
	body := strings.NewReader(`{"a":`)
	req, _ := http.NewRequest("POST", proxy.URL+"/gmail/v1/users/42/messages/abc", body)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	respBody, _ := io.ReadAll(resp.Body)
	got := strings.TrimSpace(string(respBody))
	if got != "bad request" {
		t.Fatalf("body = %q, want exactly \"bad request\" (no internal diagnostics)", got)
	}
}

func TestDenyReturns403(t *testing.T) {
	// An API with no actions routes (its path_prefix claims the
	// request) but cannot match any policy → Deny → 403. The
	// path_prefix is what distinguishes this case from the unrouted
	// 404: routing succeeds, evaluation denies.
	api := &models.API{
		Name:         "empty",
		BaseURL:      "http://example.invalid",
		PathPrefixes: []string{"/anything"},
	}
	b := runtime.NewBuilder()
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/anything", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403, body = %s", resp.StatusCode, body)
	}

	// The denial body is structured JSON with `next_steps` pointing
	// at the discovery endpoints — agents and operators get an
	// in-band breadcrumb instead of a plain "forbidden" string.
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	body0, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body0, &body); err != nil {
		t.Fatalf("decode denial body: %v (raw=%s)", err, body0)
	}
	steps, ok := body["next_steps"].(map[string]any)
	if !ok {
		t.Fatalf("denial body missing next_steps: %v", body)
	}
	for _, key := range []string{"supported_apis", "policies", "docs"} {
		if v, _ := steps[key].(string); v == "" {
			t.Errorf("next_steps.%s missing or empty: %+v", key, steps)
		}
	}
}

// TestDenyBodyCarriesMatchedActions pins the contract that a
// 403 from policy denial includes the api the request routed to
// and every action whose match logic fired. Agents reading the
// body draft a permitting policy off this list rather than
// re-walking /_api/apis to figure out what they hit.
func TestDenyBodyCarriesMatchedActions(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "http://example.invalid",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "read_thing", Method: "GET", Path: "/svc/things/{id}"},
			{Name: "list_things", Method: "GET", Path: "/svc/things"},
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
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/svc/things/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403, body = %s", resp.StatusCode, body)
	}
	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, raw)
	}
	if body["api"] != "svc" {
		t.Errorf("api = %v, want svc", body["api"])
	}
	matched, _ := body["matched_actions"].([]any)
	if len(matched) != 1 || matched[0] != "read_thing" {
		t.Errorf("matched_actions = %v, want [read_thing]", matched)
	}
	// Slack-aware clients branch on body.ok — pin the field so a
	// future denial-shape refactor doesn't silently drop it.
	if got, ok := body["ok"]; !ok || got != false {
		t.Errorf("ok = %v (present=%v), want false", got, ok)
	}
}

// TestDoubleSlashIsForbidden exercises the path-segment boundary
// end-to-end: a request whose path contains `//` produces an empty
// segment in `path_segments`, which makes the request length differ
// from any non-degenerate template — so no action matches, no policy
// permits, and the server returns 403. The point of the test is that
// the path *cannot* slip past `gmail/v1/users/{user}/profile` by
// collapsing the `//`: SplitPath now sees the empty segment, the
// proxy and the upstream agree on the path's shape. The double slash
// sits *after* the path_prefix so routing still claims the request —
// otherwise we'd see the 404 (no route) path instead of the 403
// (policy denied) path that this test exists to cover.
func TestDoubleSlashIsForbidden(t *testing.T) {
	rt := loadGmailRuntime(t, "")
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "fake-token")
	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1//users/42/profile", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// TestRoutesAcrossMultipleApis exercises the multi-API server: one
// process fronts two APIs, each with its own upstream URL, and the
// proxy dispatches every request to the API whose actions claim the
// path. Both upstreams record what they saw so the test can assert
// the right one was hit.
func TestRoutesAcrossMultipleApis(t *testing.T) {
	var aHits, bHits int
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aHits++
		_, _ = io.WriteString(w, "A:"+r.URL.Path)
	}))
	defer upstreamA.Close()
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHits++
		_, _ = io.WriteString(w, "B:"+r.URL.Path)
	}))
	defer upstreamB.Close()

	apiA := &models.API{
		Name:         "alpha",
		BaseURL:      upstreamA.URL,
		PathPrefixes: []string{"/alpha"},
		Actions:      []models.Action{{Name: "any", Method: "GET", Path: "/alpha/{id}"}},
	}
	apiB := &models.API{
		Name:         "beta",
		BaseURL:      upstreamB.URL,
		PathPrefixes: []string{"/beta"},
		Actions:      []models.Action{{Name: "any", Method: "GET", Path: "/beta/{id}"}},
	}
	b := runtime.NewBuilder()
	if err := b.AddAPI(apiA); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if err := b.AddAPI(apiB); err != nil {
		t.Fatalf("add beta: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, p := range []models.Policy{
		{API: "alpha", Name: "open_alpha", Action: `action.name == "any"`, Condition: "true", Result: models.Permit},
		{API: "beta", Name: "open_beta", Action: `action.name == "any"`, Condition: "true", Result: models.Permit},
	} {
		if err := rt.AddPolicy(&p); err != nil {
			t.Fatalf("add policy: %v", err)
		}
	}

	keys := mustKeys(t)
	srv := NewServer(Dependencies{
		Runtime:    rt,
		Keys:       keys,
		HTTPClient: http.DefaultClient,
		APIFactory: func(string, auth.AccessCreds) (compiled.PhysicalAPI, error) {
			return fakeGmailAPI{}, nil
		},
	})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "tok")
	do := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", proxy.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do %s: %v", path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	if status, body := do("/alpha/1"); status != 200 || body != "A:/alpha/1" {
		t.Errorf("alpha route: status=%d body=%q", status, body)
	}
	if status, body := do("/beta/2"); status != 200 || body != "B:/beta/2" {
		t.Errorf("beta route: status=%d body=%q", status, body)
	}
	// Unrouted requests get 404, distinct from policy-denied 403, so
	// operators can tell a misrouted request from one that was actively
	// rejected.
	if status, _ := do("/gamma/3"); status != http.StatusNotFound {
		t.Errorf("unmatched route: status=%d, want 404", status)
	}
	if aHits != 1 || bHits != 1 {
		t.Errorf("hits: alpha=%d beta=%d, want 1 each", aHits, bHits)
	}
}

// parseJSONBody must accept any JSON shape (object, array, scalar) and
// reject malformed JSON so the proxy can respond 400 at the boundary.
// Empty bodies stay nil (indistinguishable from "no body").
// TestBuildPrincipal pins the JWT-subject → *pb.Principal mapping the
// proxy uses as the runtime caller identity. Authenticated callers
// stamp kind=agent; the anonymous branch (auth: optional path) zeros
// the subject and stamps kind=anonymous so a policy can gate on it.
func TestBuildPrincipal(t *testing.T) {
	got := buildPrincipal("user-1", false)
	if got == nil {
		t.Fatal("nil principal")
	}
	if got.GetSubject() != "user-1" {
		t.Errorf("subject = %q, want user-1", got.GetSubject())
	}
	if got.GetKind() != "agent" {
		t.Errorf("kind = %q, want agent", got.GetKind())
	}
	anon := buildPrincipal("user-1", true)
	if anon.GetSubject() != "" {
		t.Errorf("anon subject = %q, want empty", anon.GetSubject())
	}
	if anon.GetKind() != "anonymous" {
		t.Errorf("anon kind = %q, want anonymous", anon.GetKind())
	}
}

func TestParseRequestBody(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        string
		wantNil     bool
		wantErr     bool
		wantField   string // dot-notation lookup applied to GetStructValue
		wantString  string // when wantField is set, the expected string value at that field
	}{
		{name: "empty_body_default_ct", body: "", wantNil: true},
		{name: "empty_body_form_ct", contentType: "application/x-www-form-urlencoded", body: "", wantNil: true},
		{name: "json_object_no_ct", body: `{"x":1}`, wantField: "x"},
		{name: "json_object_with_ct", contentType: "application/json", body: `{"x":1}`, wantField: "x"},
		{name: "json_with_charset", contentType: "application/json; charset=utf-8", body: `{"x":1}`, wantField: "x"},
		{name: "json_array", body: `[1,2,3]`},
		{name: "json_scalar_number", body: `42`},
		{name: "json_malformed", body: `{not json`, wantErr: true},

		{
			name:        "form_single_value_to_string",
			contentType: "application/x-www-form-urlencoded",
			body:        "channel=C0123456789&text=hello",
			wantField:   "channel",
			wantString:  "C0123456789",
		},
		{
			// One of the variants from the report: a Slack-SDK-style
			// urlencoded body must surface `request.body.channel` to
			// CEL conditions. This is the load-bearing case.
			name:        "form_slack_post_message",
			contentType: "application/x-www-form-urlencoded",
			body:        "token=xoxb-fake&channel=C0123456789&text=hi",
			wantField:   "channel",
			wantString:  "C0123456789",
		},
		{
			name:        "form_with_charset_param",
			contentType: "application/x-www-form-urlencoded; charset=utf-8",
			body:        "channel=Cabc",
			wantField:   "channel",
			wantString:  "Cabc",
		},
		{
			name:        "form_malformed",
			contentType: "application/x-www-form-urlencoded",
			body:        "%zz=invalid",
			wantErr:     true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := parseRequestBody(tc.contentType, []byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if tc.wantNil != (v == nil) {
				t.Fatalf("nil mismatch: got nil=%v, want nil=%v", v == nil, tc.wantNil)
			}
			if tc.wantField != "" {
				field := v.GetStructValue().GetFields()[tc.wantField]
				if field == nil {
					t.Fatalf("expected field %q in struct body", tc.wantField)
				}
				if tc.wantString != "" && field.GetStringValue() != tc.wantString {
					t.Errorf("field %q = %q, want %q", tc.wantField, field.GetStringValue(), tc.wantString)
				}
			}
		})
	}
}

// TestParseFormBodyMultiValueIsList pins the multi-value form
// case: when the same key repeats, the body shape is a list (so
// CEL `request.body.scope[0]` works) rather than collapsed.
func TestParseFormBodyMultiValueIsList(t *testing.T) {
	v, err := parseRequestBody(
		"application/x-www-form-urlencoded",
		[]byte("scope=read&scope=write&channel=C1"),
	)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	scope := v.GetStructValue().GetFields()["scope"]
	if scope == nil || scope.GetListValue() == nil {
		t.Fatalf("scope field = %+v, want list", scope)
	}
	got := scope.GetListValue().GetValues()
	if len(got) != 2 || got[0].GetStringValue() != "read" || got[1].GetStringValue() != "write" {
		t.Errorf("scope list = %+v", got)
	}
	if c := v.GetStructValue().GetFields()["channel"]; c.GetStringValue() != "C1" {
		t.Errorf("channel = %v, want C1", c)
	}
}

// buildMultipart returns a (body, content-type) pair for the named
// fields. Text fields go in textParts (name → value); file fields
// go in fileParts (name → {filename, content-type, payload}).
// Pulled out of the test bodies so the assertions stay focused on
// the projection rather than the multipart-encoding ceremony.
func buildMultipart(t *testing.T, textParts map[string]string, fileParts map[string]struct {
	Filename    string
	ContentType string
	Payload     string
}) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range textParts {
		if err := w.WriteField(k, v); err != nil {
			t.Fatalf("write text part %q: %v", k, err)
		}
	}
	for k, f := range fileParts {
		hdr := make(textproto.MIMEHeader)
		hdr.Set("Content-Disposition", `form-data; name="`+k+`"; filename="`+f.Filename+`"`)
		if f.ContentType != "" {
			hdr.Set("Content-Type", f.ContentType)
		}
		part, err := w.CreatePart(hdr)
		if err != nil {
			t.Fatalf("create file part %q: %v", k, err)
		}
		if _, err := part.Write([]byte(f.Payload)); err != nil {
			t.Fatalf("write file part %q: %v", k, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return buf.Bytes(), w.FormDataContentType()
}

// TestParseRequestBodyDropsJSONNulls pins the "no such overload"
// fix: a JSON body with `{"name": null}` parses into a request.body
// that has *no* `name` field, so a CEL pattern like
// `request.body.?name.orValue("")` short-circuits to "" rather
// than to a null that breaks `.startsWith()` downstream.
func TestParseRequestBodyDropsJSONNulls(t *testing.T) {
	v, err := parseRequestBody("application/json", []byte(`{"name":null,"channel":"C1","nested":{"x":null,"y":2}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fields := v.GetStructValue().GetFields()
	if _, ok := fields["name"]; ok {
		t.Errorf("name survived: %v", fields)
	}
	if fields["channel"].GetStringValue() != "C1" {
		t.Errorf("channel = %v", fields["channel"])
	}
	nested := fields["nested"].GetStructValue().GetFields()
	if _, ok := nested["x"]; ok {
		t.Errorf("nested.x survived: %v", nested)
	}
	if nested["y"].GetNumberValue() != 2 {
		t.Errorf("nested.y = %v", nested["y"])
	}
}

// TestParseMultipartBodyTextAndFileParts pins the projection: text
// parts surface as strings on `request.body`; file parts surface as
// {filename, content_type, size} so a policy can gate on those
// without seeing the upload bytes. Slack's `files.upload` sends
// channels / filename / filetype as text parts and the bytes as
// `file` — both halves are reachable from CEL.
func TestParseMultipartBodyTextAndFileParts(t *testing.T) {
	body, ct := buildMultipart(t,
		map[string]string{"channels": "C0123456789", "filetype": "txt"},
		map[string]struct {
			Filename, ContentType, Payload string
		}{
			"file": {Filename: "notes.txt", ContentType: "text/plain", Payload: "hello world"},
		},
	)
	v, err := parseRequestBody(ct, body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fields := v.GetStructValue().GetFields()
	if got := fields["channels"].GetStringValue(); got != "C0123456789" {
		t.Errorf("channels = %q", got)
	}
	if got := fields["filetype"].GetStringValue(); got != "txt" {
		t.Errorf("filetype = %q", got)
	}
	file := fields["file"].GetStructValue().GetFields()
	if file["filename"].GetStringValue() != "notes.txt" {
		t.Errorf("filename = %v", file["filename"])
	}
	if file["content_type"].GetStringValue() != "text/plain" {
		t.Errorf("content_type = %v", file["content_type"])
	}
	if got := file["size"].GetNumberValue(); got != float64(len("hello world")) {
		t.Errorf("size = %v, want %d", got, len("hello world"))
	}
}

// TestParseMultipartBodyMissingBoundaryFails pins the malformed-
// header case: `Content-Type: multipart/form-data` without a
// boundary= param is RFC-illegal, and silently parsing nothing
// would mask a real client bug rather than surface it.
func TestParseMultipartBodyMissingBoundaryFails(t *testing.T) {
	_, err := parseRequestBody("multipart/form-data", []byte("anything"))
	if err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Fatalf("err = %v, want one mentioning 'boundary'", err)
	}
}

// TestParseMultipartBodyRepeatedTextFieldIsList pins the multi-value
// case for multipart text parts: same name repeating produces a list
// (parity with the urlencoded form-body path).
func TestParseMultipartBodyRepeatedTextFieldIsList(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("channel", "C1")
	_ = w.WriteField("channel", "C2")
	_ = w.Close()
	v, err := parseRequestBody(w.FormDataContentType(), buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	channels := v.GetStructValue().GetFields()["channel"]
	if channels.GetListValue() == nil {
		t.Fatalf("channel field = %+v, want list", channels)
	}
	got := channels.GetListValue().GetValues()
	if len(got) != 2 || got[0].GetStringValue() != "C1" || got[1].GetStringValue() != "C2" {
		t.Errorf("channel list = %+v", got)
	}
}

// TestAuthOptionalAdmitsAnonymous pins the auth: optional path: a
// request to an API marked `auth: optional` without a Bearer is
// admitted, runs through policy with kind=anonymous, and reaches the
// upstream without an Authorization header. A policy gating on
// `principal.kind == "anonymous"` permits.
func TestAuthOptionalAdmitsAnonymous(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	api := &models.API{
		Name:         "public",
		BaseURL:      upstream.URL,
		PathPrefixes: []string{"/public"},
		Auth:         "optional",
		Actions:      []models.Action{{Name: "get", Method: "GET", Path: "/public/v1/health"}},
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
		API: "public", Name: "open", Principal: `principal.kind == "anonymous"`,
		Action: `true`, Condition: `true`, Result: models.Permit,
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	keys := mustKeys(t)
	factory := func(string, auth.AccessCreds) (compiled.PhysicalAPI, error) {
		return fakeGmailAPI{}, nil
	}
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: factory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/public/v1/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if gotAuth != "" {
		t.Errorf("upstream saw Authorization = %q, want empty on anonymous path", gotAuth)
	}
}

// TestAuthRequiredStill401sWithoutBearer pins the negative: an API
// without `auth: optional` rejects a bearer-less request even though
// the auth: optional path exists for other APIs.
func TestAuthRequiredStill401sWithoutBearer(t *testing.T) {
	rt := loadGmailRuntime(t, "https://example.invalid")
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/gmail/v1/users/me/profile")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestConnectionNamedHeadersAreStripped pins RFC 7230 §6.1 in both
// directions: a header the Connection header declares hop-by-hop must
// not cross the proxy, even though it isn't in the well-known strip
// set.
func TestConnectionNamedHeadersAreStripped(t *testing.T) {
	var gotHop, gotKept string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHop = r.Header.Get("X-Hop")
		gotKept = r.Header.Get("X-Kept")
		w.Header().Set("Connection", "X-Resp-Hop")
		w.Header().Set("X-Resp-Hop", "secret")
		w.Header().Set("X-Resp-Kept", "ok")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+issueJWT(t, keys, "tok"))
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "secret")
	req.Header.Set("X-Kept", "ok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if gotHop != "" {
		t.Errorf("upstream received Connection-named header X-Hop = %q, want stripped", gotHop)
	}
	if gotKept != "ok" {
		t.Errorf("upstream X-Kept = %q, want ok (ordinary headers must pass)", gotKept)
	}
	if v := resp.Header.Get("X-Resp-Hop"); v != "" {
		t.Errorf("client received Connection-named response header X-Resp-Hop = %q, want stripped", v)
	}
	if v := resp.Header.Get("X-Resp-Kept"); v != "ok" {
		t.Errorf("client X-Resp-Kept = %q, want ok", v)
	}
}
