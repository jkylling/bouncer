package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// buildFilesRuntime compiles a one-action `GET /files/{id}` API with a
// permit policy whose action predicate gates on the captured id.
func buildFilesRuntime(t *testing.T, baseURL, predicate string) *runtime.Runtime {
	t.Helper()
	api := &models.API{
		Name:         "files.api",
		BaseURL:      baseURL,
		PathPrefixes: []string{"/files"},
		Actions: []models.Action{
			{Name: "get_file", Method: "GET", Path: "/files/{id}"},
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
		Action:    predicate,
		Condition: "true",
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	return rt
}

// TestEncodedSlashStaysInSegment pins the %2F round trip: a file ID
// with an encoded slash is one path segment to the policy engine (the
// capture holds the literal slash) and reaches the upstream with its
// original encoding intact, instead of being decoded into a real
// separator on either side.
func TestEncodedSlashStaysInSegment(t *testing.T) {
	var upstreamPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// The predicate only fires when the capture carries the decoded
	// ID *with* the literal slash — pinning the policy-side view.
	rt := buildFilesRuntime(t, upstream.URL, `match.id == "abc/def"`)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	req, _ := http.NewRequest("GET", proxy.URL+"/files/abc%2Fdef", nil)
	req.Header.Set("Authorization", "Bearer "+issueJWT(t, keys, "tok"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (capture must see the decoded ID); body = %s", resp.StatusCode, body)
	}
	if upstreamPath != "/files/abc%2Fdef" {
		t.Errorf("upstream path = %q, want %q (encoding must survive the forward)", upstreamPath, "/files/abc%2Fdef")
	}
}

// TestEncodedSlashCannotForgeSegments pins the negatives: an encoded
// slash must not create segment boundaries, neither to slip extra
// segments past a one-param template nor to fake a route prefix.
func TestEncodedSlashCannotForgeSegments(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must not be reached")
	}))
	defer upstream.Close()

	rt := buildFilesRuntime(t, upstream.URL, `match.id == "abc"`)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	jwt := issueJWT(t, keys, "tok")
	cases := []struct {
		path string
		want int
	}{
		// One segment "abc/def" — template matches but the predicate
		// (id == "abc") rejects: deny, not a smuggled "abc".
		{"/files/abc%2Fdef", http.StatusForbidden},
		// "files/abc" is a single segment, so the /files prefix does
		// not route: no API claims the path.
		{"/files%2Fabc", http.StatusNotFound},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest("GET", proxy.URL+tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do %s: %v", tc.path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("GET %s: status = %d, want %d", tc.path, resp.StatusCode, tc.want)
		}
	}
}
