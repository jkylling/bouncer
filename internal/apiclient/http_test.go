package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// TestJoinPathRejectsAbsoluteReference pins B2: a `requestPath` that
// parses as an absolute URL must not be allowed to replace the base
// origin via ResolveReference. This is the SSRF guard for inputs
// flowing in via meta CEL `request:` paths.
func TestJoinPathRejectsAbsoluteReference(t *testing.T) {
	base, err := url.Parse("https://api.example.com/v1")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	// `///x/y` survives the TrimPrefix-of-one-slash and parses as
	// `//x/y` whose URL has Host="x" — a network-host-host swap.
	cases := []string{
		"https://attacker.com/foo",
		"http://attacker.com/foo",
		"///attacker.com/foo",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := JoinPath(base, in); err == nil {
				t.Errorf("JoinPath(%q) = nil err, want rejection", in)
			}
		})
	}
}

// TestJoinPathPreservesDotSegments pins the proxy
// forwards the bytes the policy evaluated, including `..`, `.`,
// `//`. ResolveReference would collapse these via RFC 3986 §5.2.4
// and silently let a "/messages/../labels/Trash" request that the
// policy approved as a message-delete actually delete a label
// upstream.
func TestJoinPathPreservesDotSegments(t *testing.T) {
	base, _ := url.Parse("https://api.example.com/v1")
	cases := map[string]string{
		"/users/me/messages/../labels/Trash": "https://api.example.com/v1/users/me/messages/../labels/Trash",
		"/a/./b":                             "https://api.example.com/v1/a/./b",
		"/a//b":                              "https://api.example.com/v1/a//b",
		"/.":                                 "https://api.example.com/v1/.",
		"/..":                                "https://api.example.com/v1/..",
	}
	for in, want := range cases {
		got, err := JoinPath(base, in)
		if err != nil {
			t.Errorf("JoinPath(%q): %v", in, err)
			continue
		}
		// String() must surface the raw path verbatim, not a
		// normalised form. http.NewRequest with this URL will hit
		// the upstream as-is — net/http does not re-normalise.
		if got.String() != want {
			t.Errorf("JoinPath(%q) = %q, want %q", in, got.String(), want)
		}
	}
}

// TestJoinPathPreservesPercentEscapes pins that a percent-encoded
// byte in the input reaches the upstream percent-encoded once, not
// twice. Clearing RawPath would force URL.String() to re-escape
// Path's `%` bytes, turning `%2F` into `%252F` on the wire.
func TestJoinPathPreservesPercentEscapes(t *testing.T) {
	base, _ := url.Parse("https://api.example.com/v1")
	cases := map[string]string{
		// Encoded slash inside an id (Drive accepts these).
		"/files/abc%2Fdef": "https://api.example.com/v1/files/abc%2Fdef",
		// Encoded `#` inside the path (rare but legal).
		"/files/abc%23def": "https://api.example.com/v1/files/abc%23def",
		// Pre-encoded space in a query value.
		"/v3/files?q=name%20contains%20%27y%27": "https://api.example.com/v1/v3/files?q=name%20contains%20%27y%27",
		// Encoded comma in a fields= list.
		"/files/x?fields=name%2CmimeType": "https://api.example.com/v1/files/x?fields=name%2CmimeType",
	}
	for in, want := range cases {
		got, err := JoinPath(base, in)
		if err != nil {
			t.Errorf("JoinPath(%q): %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("JoinPath(%q) = %q, want %q", in, got.String(), want)
		}
		// The bytes that net/http will write to the wire must match
		// the expected upstream URL — RequestURI() is what
		// Transport sends.
		req, err := http.NewRequest(http.MethodGet, got.String(), nil)
		if err != nil {
			t.Errorf("NewRequest(%q): %v", in, err)
			continue
		}
		if reqURI := req.URL.RequestURI(); !strings.HasSuffix(want, reqURI) {
			t.Errorf("RequestURI(%q) = %q, want suffix of %q", in, reqURI, want)
		}
	}
}

// TestJoinPathAcceptsRelative confirms the fix doesn't break the
// happy paths: paths with and without leading slashes still join.
func TestJoinPathAcceptsRelative(t *testing.T) {
	base, _ := url.Parse("https://api.example.com/v1")
	cases := map[string]string{
		"/v3/files":         "https://api.example.com/v1/v3/files",
		"v3/files":          "https://api.example.com/v1/v3/files",
		"v3/files?fields=*": "https://api.example.com/v1/v3/files?fields=*",
	}
	for in, want := range cases {
		got, err := JoinPath(base, in)
		if err != nil {
			t.Errorf("JoinPath(%q): %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("JoinPath(%q) = %q, want %q", in, got.String(), want)
		}
	}
}

func TestCallGetForwardsBearerAndDecodesBody(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		_, _ = w.Write([]byte(`{"name":"Alice","age":30}`))
	}))
	defer srv.Close()

	api, err := New(srv.Client(), srv.URL+"/api", "tok-123", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	resp, err := api.Call(t.Context(), &pb.MetaRequest{Method: "GET", Path: "/v1/users/me"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if gotMethod != "GET" {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("auth header = %q, want Bearer tok-123", gotAuth)
	}
	if gotPath != "/api/v1/users/me" {
		t.Errorf("path = %q, want /api/v1/users/me", gotPath)
	}
	if got := resp.GetBody().GetStructValue().GetFields()["name"].GetStringValue(); got != "Alice" {
		t.Errorf("body.name = %q, want Alice", got)
	}
}

// TestCallStampsExtraHeaders pins that the JWT-bundled extras
// (Cookie / Origin / Referer for Slack-style browser-session creds,
// X-API-Key for header tokens) reach every meta side call. Without
// this the outer forward path authenticates correctly but a
// `conversations.info` side fetch lands at Slack with only
// Authorization and gets `invalid_auth` back.
func TestCallStampsExtraHeaders(t *testing.T) {
	got := http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.Header {
			got.Set(k, r.Header.Get(k))
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	api, err := New(srv.Client(), srv.URL, "xoxc-fake", []Header{
		{Name: "Cookie", Value: "d=xoxd-fake"},
		{Name: "Origin", Value: "https://app.slack.com"},
		{Name: "Referer", Value: "https://app.slack.com/"},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := api.Call(t.Context(), &pb.MetaRequest{Method: "POST", Path: "/api/auth.test"}); err != nil {
		t.Fatalf("call: %v", err)
	}
	if v := got.Get("Authorization"); v != "Bearer xoxc-fake" {
		t.Errorf("Authorization = %q, want Bearer xoxc-fake", v)
	}
	if v := got.Get("Cookie"); v != "d=xoxd-fake" {
		t.Errorf("Cookie = %q, want d=xoxd-fake", v)
	}
	if v := got.Get("Origin"); v != "https://app.slack.com" {
		t.Errorf("Origin = %q", v)
	}
	if v := got.Get("Referer"); v != "https://app.slack.com/" {
		t.Errorf("Referer = %q", v)
	}
}

// TestCallFormEncodedBody pins post_form's wire shape: top-level
// scalar fields land as raw key=value pairs, nested objects/arrays
// JSON-stringify into a single field — the Slack convention for
// compound parameters like `profile=` on users.profile.set. The
// Content-Type header switches to application/x-www-form-urlencoded.
func TestCallFormEncodedBody(t *testing.T) {
	var gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	api, err := New(srv.Client(), srv.URL, "", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	body, _ := structpb.NewValue(map[string]any{
		"channel": "C0123",
		"profile": map[string]any{"status_text": "hi", "status_emoji": ":wave:"},
		"users":   []any{"U1", "U2"},
		"count":   float64(5),
	})
	_, err = api.Call(t.Context(), &pb.MetaRequest{
		Method:      "POST",
		Path:        "/api/users.profile.set",
		Body:        body,
		ContentType: "application/x-www-form-urlencoded",
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	form, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("parse body: %v\nbody: %s", err, gotBody)
	}
	if form.Get("channel") != "C0123" {
		t.Errorf("channel = %q", form.Get("channel"))
	}
	if form.Get("count") != "5" {
		t.Errorf("count = %q, want 5", form.Get("count"))
	}
	// Profile + users are JSON-stringified.
	var prof map[string]any
	if err := json.Unmarshal([]byte(form.Get("profile")), &prof); err != nil {
		t.Errorf("profile decode: %v\nraw: %q", err, form.Get("profile"))
	} else if prof["status_text"] != "hi" {
		t.Errorf("profile.status_text = %v", prof["status_text"])
	}
	var users []any
	if err := json.Unmarshal([]byte(form.Get("users")), &users); err != nil {
		t.Errorf("users decode: %v\nraw: %q", err, form.Get("users"))
	} else if len(users) != 2 {
		t.Errorf("users len = %d", len(users))
	}
}

func TestCallSetsAcceptHeader(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	api, err := New(srv.Client(), srv.URL, "", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := api.Call(t.Context(), &pb.MetaRequest{Method: "GET", Path: "/x"}); err != nil {
		t.Fatalf("call: %v", err)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
}

func TestCallAcceptsArrayBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[1, 2, 3]`))
	}))
	defer srv.Close()
	api, err := New(srv.Client(), srv.URL, "", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	resp, err := api.Call(t.Context(), &pb.MetaRequest{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	got := resp.GetBody().GetListValue().GetValues()
	if len(got) != 3 || got[0].GetNumberValue() != 1 {
		t.Errorf("body = %v, want [1,2,3]", got)
	}
}

func TestCallPostSendsJSONBody(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	api, err := New(srv.Client(), srv.URL, "", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	body, _ := structpb.NewValue(map[string]any{"x": float64(1)})
	if _, err := api.Call(t.Context(), &pb.MetaRequest{Method: "POST", Path: "/p", Body: body}); err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(gotBody, `"x":1`) {
		t.Errorf("body = %q, want contain x:1", gotBody)
	}
}

func TestCallReturnsErrorOn4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	api, err := New(srv.Client(), srv.URL, "", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, err = api.Call(t.Context(), &pb.MetaRequest{Method: "GET", Path: "/x"})
	if err == nil {
		t.Fatalf("expected error for 403")
	}
	var ue *UpstreamError
	if !errors.As(err, &ue) {
		t.Fatalf("error is not *UpstreamError: %v", err)
	}
	if ue.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", ue.Status)
	}
	if ue.Body != "nope" {
		t.Errorf("body = %q, want %q", ue.Body, "nope")
	}
}

// TestCallPropagatesContextCancellation verifies that cancelling the
// context aborts the in-flight upstream request rather than racing
// it to completion. Without context propagation, a cancelled inbound
// request would continue spending an upstream API quota slot until
// the network call returns on its own schedule.
func TestCallPropagatesContextCancellation(t *testing.T) {
	started := make(chan struct{})
	finish := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(finish)
	}))
	defer srv.Close()

	api, err := New(srv.Client(), srv.URL, "", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		_, callErr := api.Call(ctx, &pb.MetaRequest{Method: "GET", Path: "/x"})
		errCh <- callErr
	}()

	<-started
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Call err = %v, want context.Canceled", err)
	}
	<-finish
}

// TestCallRejectsResponseAboveCap pins a runaway
// upstream that streams more than maxResponseBodyBytes is refused
// with a clear error rather than buffered in full.
func TestCallRejectsResponseAboveCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write one byte more than the cap.
		buf := make([]byte, maxResponseBodyBytes+1)
		_, _ = w.Write(buf)
	}))
	defer srv.Close()

	api, err := New(srv.Client(), srv.URL, "", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, err = api.Call(t.Context(), &pb.MetaRequest{Method: "GET", Path: "/x"})
	if err == nil {
		t.Fatal("expected error for oversize response, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("error = %v, want one mentioning the cap", err)
	}
}

// TestDropJSONNullsRemovesObjectNulls pins the policy-ergonomics
// fix: a struct field set to JSON null is removed entirely so a CEL
// optional select short-circuits to none (matching missing-field
// semantics). Lists keep nulls in place — list lookup doesn't have
// the same optional-vs-missing distinction.
func TestDropJSONNullsRemovesObjectNulls(t *testing.T) {
	in := map[string]any{
		"keep": "x",
		"drop": nil,
		"nested": map[string]any{
			"inner":    nil,
			"alsokept": 1.0,
			"deeplist": []any{nil, "v", nil},
		},
		"top_list": []any{nil, map[string]any{"a": nil, "b": 2.0}},
	}
	got := DropJSONNulls(in).(map[string]any)
	if got["keep"] != "x" {
		t.Errorf("keep dropped: %v", got)
	}
	if _, ok := got["drop"]; ok {
		t.Errorf("drop survived: %v", got)
	}
	nested := got["nested"].(map[string]any)
	if _, ok := nested["inner"]; ok {
		t.Errorf("nested.inner survived: %v", nested)
	}
	if nested["alsokept"] != 1.0 {
		t.Errorf("nested.alsokept dropped: %v", nested)
	}
	dl := nested["deeplist"].([]any)
	if len(dl) != 3 || dl[0] != nil || dl[1] != "v" || dl[2] != nil {
		t.Errorf("list mutated: %v", dl)
	}
	tl := got["top_list"].([]any)
	if len(tl) != 2 || tl[0] != nil {
		t.Errorf("top_list mutated: %v", tl)
	}
	tlMap := tl[1].(map[string]any)
	if _, ok := tlMap["a"]; ok {
		t.Errorf("top_list[1].a survived: %v", tlMap)
	}
	if tlMap["b"] != 2.0 {
		t.Errorf("top_list[1].b dropped: %v", tlMap)
	}
}
