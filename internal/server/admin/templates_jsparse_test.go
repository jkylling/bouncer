package admin

import (
	"bytes"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// scriptBlockRE matches every inline <script> element with its
// opening attributes and body. The opening attribute string lets us
// skip `<script src=…>` (no inline body) and JSON-typed blobs that
// aren't expected to parse as JS.
var scriptBlockRE = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)

// TestRenderedPagesJSParses renders every registered admin page
// through the live template stack and validates that each inline
// <script> block is syntactically valid JavaScript. Catches the
// "Go template expanded into JS" footgun at make-ci time rather
// than via a runtime "page stuck at Loading…" report.
//
// The Go html/template engine *does* context-escape values
// interpolated into a <script>, but it does NOT parse the JS itself
// — so a stray {{template "html_block" .}} reference inside a JS
// comment expands and dumps HTML into the script body. The Go
// compiler can't see that; this test can.
func TestRenderedPagesJSParses(t *testing.T) {
	for name := range pages {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			renderPage(w, name)
			if w.Code != 200 {
				t.Fatalf("renderPage(%s): status=%d body=%s", name, w.Code, w.Body.String())
			}
			body := w.Body.String()
			matches := scriptBlockRE.FindAllStringSubmatchIndex(body, -1)
			seen := 0
			for _, idx := range matches {
				attrs := body[idx[2]:idx[3]]
				inner := body[idx[4]:idx[5]]
				if strings.Contains(attrs, "src=") {
					// external script — no inline body to parse.
					continue
				}
				if strings.Contains(attrs, `type="application/json"`) ||
					strings.Contains(attrs, `type='application/json'`) {
					// JSON blob (SSR data) — not JavaScript.
					continue
				}
				if strings.TrimSpace(inner) == "" {
					continue
				}
				seen++
				if err := parseJS(inner); err != nil {
					// Reproduce a few lines of context so the failure
					// message is actionable without rerunning anything.
					t.Errorf("page %q script block (chars %d-%d) failed to parse: %v\n--- offending script ---\n%s\n--- end ---",
						name, idx[4], idx[5], err, snippet(inner, 12))
				}
			}
			t.Logf("parsed %d inline <script> blocks in page %s", seen, name)
		})
	}
}

func parseJS(src string) error {
	in := parse.NewInput(bytes.NewReader([]byte(src)))
	_, err := js.Parse(in, js.Options{})
	return err
}

// snippet returns the first `n` lines of src so the failure message
// shows enough context to locate the problem without flooding the
// test output with the whole 10k-line script block.
func snippet(src string, n int) string {
	lines := strings.SplitN(src, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
		lines = append(lines, "    … (truncated)")
	}
	return strings.Join(lines, "\n")
}
