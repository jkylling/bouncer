// Package internalapis embeds the bouncer-internal API spec and the
// three operator-selectable policy sets (demo / simple / production)
// that gate the control-plane HTTP surface. The middleware in
// internal/server/admin loads one set at boot based on the
// --internal-policies flag and evaluates every /_admin and /_api
// request through the resulting runtime.
package internalapis

import (
	"embed"
	"fmt"
	"io/fs"
)

// APISpec is the embedded YAML for the bouncer-internal API. Loaded
// once via Spec(); kept as raw bytes here so callers do their own
// strict-fields decoding to *models.API.
//
//go:embed api.yaml
var APISpec []byte

// policyFS holds the three policy sets indexed by file name
// (`<set>.yaml`). The /policies subdir keeps the API spec at the
// package root and lets a future second-API spec slot in alongside
// it without renaming.
//
//go:embed policies/*.yaml
var policyFS embed.FS

// PolicySet identifies one of the embedded policy bundles.
type PolicySet string

const (
	PolicySetDemo       PolicySet = "demo"
	PolicySetSimple     PolicySet = "simple"
	PolicySetProduction PolicySet = "production"
)

// Sets returns the recognised policy-set names in display order.
// Used by the CLI flag's help text and by validate() to reject typos
// at config-load time.
func Sets() []PolicySet {
	return []PolicySet{PolicySetDemo, PolicySetSimple, PolicySetProduction}
}

// Validate reports whether s is one of the recognised PolicySet
// names. Returns the canonical value on success so a typo'd flag
// surfaces as a load-time error with the available choices.
func (s PolicySet) Validate() error {
	for _, known := range Sets() {
		if s == known {
			return nil
		}
	}
	return fmt.Errorf("unknown internal-policies set %q (want one of: %v)", string(s), Sets())
}

// Policies returns the YAML bytes for the named policy set. Caller
// is expected to feed these into the same multi-document policy
// decoder the file-store uses (one policy per `---`-separated
// document).
func Policies(s PolicySet) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	name := "policies/" + string(s) + ".yaml"
	body, err := fs.ReadFile(policyFS, name)
	if err != nil {
		return nil, fmt.Errorf("read embedded policies %q: %w", name, err)
	}
	return body, nil
}
