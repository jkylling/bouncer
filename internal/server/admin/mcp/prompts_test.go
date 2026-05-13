package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

func TestPromptsListIncludesBouncerSetup(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "prompts/list", nil)
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(raw), `"name":"`+PromptBouncerSetup+`"`) {
		t.Errorf("list missing %q: %s", PromptBouncerSetup, raw)
	}
}

func TestPromptsGetBouncerSetupSubstitutesURLAndBearer(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	bearer := issueAccess(t, keys, false)
	resp := rpc(t, ts.URL, bearer, "prompts/get", map[string]any{"name": PromptBouncerSetup})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	body := promptText(t, resp)
	if !strings.Contains(body, ts.URL+"/install/bouncer-wrap") {
		t.Errorf("prompt body missing install URL %q:\n%s", ts.URL+"/install/bouncer-wrap", body)
	}
	if !strings.Contains(body, ts.URL+"/install/ca.pem") {
		t.Errorf("prompt body missing ca URL %q:\n%s", ts.URL+"/install/ca.pem", body)
	}
	if !strings.Contains(body, "Bearer "+bearer) {
		t.Errorf("prompt body missing bearer substitution:\n%s", body)
	}
	if !strings.Contains(body, "## bouncer") {
		t.Errorf("prompt body missing FRAGMENT marker:\n%s", body)
	}
}

func TestPromptsGetUnknownNameReturnsInvalidParams(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "prompts/get", map[string]any{"name": "no-such-prompt"})
	if resp.Error == nil {
		t.Fatal("want error for unknown prompt, got nil")
	}
	if resp.Error.Code != codeInvalidParams {
		t.Errorf("code = %d, want %d", resp.Error.Code, codeInvalidParams)
	}
}

func TestPromptsGetMissingNameRejects(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "prompts/get", map[string]any{})
	if resp.Error == nil {
		t.Fatal("want error for missing name, got nil")
	}
	if resp.Error.Code != codeInvalidParams {
		t.Errorf("code = %d, want %d", resp.Error.Code, codeInvalidParams)
	}
}

// TestPromptsGetTokenPromptKeepsLiteralBraces verifies that the
// token-prompt renderer uses non-{{ }} delimiters so example JSON
// blocks like `"file_template": "{{ .AccessToken }}"` (which describe
// the get_*_token tool's response shape) pass through unchanged.
// Regression: previously the body was parsed as a default-delimiter
// text/template and execution failed on {{ .AccessToken }} / .Path
// because those fields don't exist on the prompt template struct.
func TestPromptsGetTokenPromptKeepsLiteralBraces(t *testing.T) {
	body := "preface\n" +
		`    "file_template": "{{ .AccessToken }}",` + "\n" +
		`    "env": { "X": "{{ .Path }}" }` + "\n" +
		"path is [[ .CredentialPath ]] for [[ .Service ]]\n"
	bundle := &bundles.BundleToken{
		BundleName: "bouncer-fake",
		PromptBody: []byte(body),
		Spec: &bundles.Service{
			Slug: "fake",
			Credential: bundles.CredentialSpec{
				Path: "~/.config/bouncer/fake-token",
			},
		},
	}
	ts, keys, _ := tokenTestServer(t, []*bundles.BundleToken{bundle}, nil)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "prompts/get", map[string]any{"name": "fake-token"})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	got := promptText(t, resp)
	for _, want := range []string{
		`"file_template": "{{ .AccessToken }}"`,
		`"X": "{{ .Path }}"`,
		"path is ~/.config/bouncer/fake-token for fake",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("body missing %q:\n%s", want, got)
		}
	}
}

func TestPromptsGetAnonymousFallsBackToPlaceholderBearer(t *testing.T) {
	ts, _, _, _ := testServer(t)
	resp := rpc(t, ts.URL, "", "prompts/get", map[string]any{"name": PromptBouncerSetup})
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	body := promptText(t, resp)
	if !strings.Contains(body, "<tenant-token>") {
		t.Errorf("anonymous request should yield placeholder bearer:\n%s", body)
	}
}

// promptText unwraps a prompts/get result back to its first message's
// text, sidestepping the html-style escaping the JSON encoder applies
// to `<` / `>` when the caller compares against the raw marshaled
// envelope.
func promptText(t *testing.T, resp Response) string {
	t.Helper()
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var got getPromptResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode getPromptResult: %v", err)
	}
	if len(got.Messages) == 0 {
		t.Fatal("no messages")
	}
	return got.Messages[0].Content.Text
}
