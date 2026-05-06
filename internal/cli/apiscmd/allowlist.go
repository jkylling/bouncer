package apiscmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// allowlistFile is the optional `bouncer.yaml` an operator drops
// at the root of their data dir to constrain which refs `apis add`
// will install. Filename only; the file lives directly under the
// data dir.
const allowlistFile = "bouncer.yaml"

// allowlistConfig mirrors only the keys we care about — the
// `apis.allowlist` block. Anything else is allowed through (and
// ignored) so the same file can carry future config without forcing
// every CLI build to know about it.
type allowlistConfig struct {
	APIs struct {
		Allowlist []string `yaml:"allowlist"`
	} `yaml:"apis"`
}

// loadAllowlist reads <dataDir>/bouncer.yaml and returns the
// allowlist patterns. Missing file is fine — the caller treats an
// empty result as "no constraint." Other errors are propagated so
// the operator notices a malformed file.
func loadAllowlist(dataDir string) ([]string, error) {
	if dataDir == "" {
		return nil, nil
	}
	path := filepath.Join(dataDir, allowlistFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg allowlistConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg.APIs.Allowlist, nil
}

// matchAllowlist reports whether ref matches any pattern in the
// allowlist. Patterns are slug-based ("github.com/acme/*"); a single
// trailing "*" matches any repo under the prefix. Empty allowlist
// means "no constraint" — every ref is allowed.
//
// We intentionally support only "<host>/<owner>/*" and exact slug
// matches: globbing across owners is rare in practice and a more
// elaborate pattern syntax invites mismatches between operator
// expectations and actual matching. If a real need surfaces, swap
// this for path/match.Match — the contract from the caller's side
// is just a bool.
func matchAllowlist(allowlist []string, ref bundles.Ref) bool {
	if len(allowlist) == 0 {
		return true
	}
	slug := ref.Slug()
	for _, pat := range allowlist {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if pat == slug {
			return true
		}
		if strings.HasSuffix(pat, "/*") {
			prefix := strings.TrimSuffix(pat, "/*")
			if strings.HasPrefix(slug, prefix+"/") {
				return true
			}
		}
	}
	return false
}

// enforceAllowlist returns an error if ref isn't allowed. Used by
// `apis add` and `apis fetch` (any verb that introduces a new ref to
// the operator's environment). `apis remove` / `apis upgrade` work
// against already-installed bundles, so they don't run this check —
// removing or refreshing a bundle that snuck through pre-allowlist
// is the operator's problem to revisit at install time.
func enforceAllowlist(dataDir string, ref bundles.Ref) error {
	allow, err := loadAllowlist(dataDir)
	if err != nil {
		return err
	}
	if !matchAllowlist(allow, ref) {
		return fmt.Errorf("ref %s is not in the apis.allowlist of %s\n\nadd a matching entry under `apis.allowlist:` in %s, or pass --skip-allowlist (not recommended) to override",
			ref, filepath.Join(dataDir, allowlistFile), allowlistFile)
	}
	return nil
}
