package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestDocsServesMarkdown pins the docs endpoint contract: a fetch
// against each of the three doc paths returns the embedded Markdown
// with a markdown content-type so an agent's parser can branch on
// it. Spot-check a few headings rather than the whole body — the
// detailed wording is reviewable in the embedded files.
func TestDocsServesMarkdown(t *testing.T) {
	r := chi.NewRouter()
	MountDocs(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	cases := []struct {
		path  string
		needs []string
	}{
		{
			path: DocsPath,
			needs: []string{
				"# bouncer",
				"## Authentication",
				"## Authoring",
				"## Discovering supported APIs",
			},
		},
		{
			path: DocsPoliciesPath,
			needs: []string{
				"# Authoring policies",
				"## YAML schema",
				"## CEL primer",
			},
		},
		{
			path: DocsAPIsPath,
			needs: []string{
				"# Authoring an API integration",
				"## What you produce",
				"## Process",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
				t.Errorf("Content-Type = %q, want text/markdown", ct)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if len(body) == 0 {
				t.Fatal("body empty")
			}
			for _, want := range tc.needs {
				if !strings.Contains(string(body), want) {
					t.Errorf("docs missing %q", want)
				}
			}
		})
	}
}
