package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/services"
)

// tokensVariantHarness mounts the tokens issue endpoints with a
// registry whose `google` service has one variant requiring `token`
// and one whose fields are all optional.
func tokensVariantHarness(t *testing.T) (*httptest.Server, *auth.ServerKeys) {
	t.Helper()
	keys := mustKeys(t)
	loaded := []bundles.LoadedService{{
		Service: &bundles.Service{Slug: "google", Title: "Google"},
		TokenVariants: []bundles.TokenVariant{
			{
				ID:     "required",
				Title:  "Required field",
				Fields: []bundles.TokenField{{Name: "token", Required: true, Kind: "secret"}},
			},
			{
				ID:     "optional",
				Title:  "Optional field",
				Fields: []bundles.TokenField{{Name: "extra", Kind: "secret"}},
			},
		},
		BundleName: "bouncer-gws",
	}}
	r := testRouter(keys)
	MountTokensPage(r, keys, services.New(loaded))
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, keys
}

func postVariantIssue(t *testing.T, ts *httptest.Server, keys *auth.ServerKeys, body map[string]any) (*http.Response, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+TokensIssuePath, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", adminBearer(t, keys))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, string(out)
}

// TestVariantIssueCallerFaultsAre400s pins the status tier for the
// variant flow: bad input (missing required field, every field left
// empty, unknown service) is the caller's fault and must come back
// 4xx — not a logged 500 that pages an operator for a client typo.
func TestVariantIssueCallerFaultsAre400s(t *testing.T) {
	ts, keys := tokensVariantHarness(t)
	cases := []struct {
		name string
		body map[string]any
		want int
		msg  string
	}{
		{
			name: "missing required field",
			body: map[string]any{"subject": "ci", "service": "google", "variant": "required", "fields": map[string]string{}},
			want: http.StatusBadRequest,
			msg:  `is required`, // quotes are JSON-escaped in the body
		},
		{
			name: "all optional fields empty",
			body: map[string]any{"subject": "ci", "service": "google", "variant": "optional", "fields": map[string]string{}},
			want: http.StatusBadRequest,
			msg:  "no field values supplied",
		},
		{
			name: "unknown service",
			body: map[string]any{"subject": "ci", "service": "nope", "variant": "x", "fields": map[string]string{}},
			want: http.StatusNotFound,
			msg:  "",
		},
		{
			name: "happy path still issues",
			body: map[string]any{"subject": "ci", "service": "google", "variant": "required", "fields": map[string]string{"token": "sk-x"}},
			want: http.StatusOK,
			msg:  `"token"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := postVariantIssue(t, ts, keys, tc.body)
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, tc.want, body)
			}
			if tc.msg != "" && !strings.Contains(body, tc.msg) {
				t.Errorf("body = %q, want one containing %q", body, tc.msg)
			}
		})
	}
}
