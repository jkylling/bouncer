package mcp

import (
	"bytes"
	"net/http"
	"text/template"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// tokenBundles returns the loaded token-bundle data keyed by service
// slug. The Deps caller pre-sorts; we re-key here for O(1) lookup in
// prompts/get and tool dispatch.
func (d Deps) tokenBundles() map[string]*bundles.BundleToken {
	out := make(map[string]*bundles.BundleToken, len(d.TokenBundles))
	for _, b := range d.TokenBundles {
		if b == nil || b.Spec == nil {
			continue
		}
		out[b.Spec.Slug] = b
	}
	return out
}

// tokenPromptVars derives the template substitutions for a per-
// service `/{service}-token` prompt body. CredentialPath echoes the
// manifest so the prompt body and the `get_{service}_token` tool
// agree on where to write.
func tokenPromptVars(_ *http.Request, b *bundles.BundleToken) tokenPromptTmpl {
	return tokenPromptTmpl{
		Service:        b.Spec.Slug,
		CredentialPath: b.Spec.Credential.Path,
	}
}

type tokenPromptTmpl struct {
	Service        string
	CredentialPath string
}

// renderTokenPrompt treats the bundle's prompt-body bytes as a Go
// text/template and renders them with v. Delimiters are `[[ ]]` so
// the body can show example `{{ .AccessToken }}` / `{{ .Path }}`
// strings verbatim — those describe the get_*_token tool's response
// shape, which itself uses {{ }} for its file-template substitution.
// Errors here mean the bundle author shipped a broken template —
// surface verbatim so it's easy to root-cause.
func renderTokenPrompt(b *bundles.BundleToken, v tokenPromptTmpl) (string, error) {
	tmpl, err := template.New("token-prompt-"+b.Spec.Slug).
		Delims("[[", "]]").
		Parse(string(b.PromptBody))
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}
