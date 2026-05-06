package models

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FromYAMLDir reads every `.yaml` / `.yml` file in dir and concatenates
// *all* the `---`-separated documents from each. Mirrors the Rust
// `from_yaml_dir` helper, including its multi-document behaviour. Both
// extensions are accepted because YAML's own spec lists `.yaml` as the
// canonical form but `.yml` is widespread on Windows-leaning toolchains
// and we'd rather not have a config silently skipped over a one-letter
// difference.
func FromYAMLDir[T any](dir string) ([]T, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", dir, err)
	}
	var out []T
	for _, e := range entries {
		// e.Type().IsRegular() is true only for plain files —
		// false for directories, symlinks, devices, sockets, and
		// pipes. Skipping every non-regular entry stops a stray
		// symlink in the config dir from being followed to an
		// arbitrary host file (whose contents would otherwise be
		// fed to the YAML decoder).
		if !e.Type().IsRegular() || !isYAML(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		docs, err := decodeMulti[T](path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, docs...)
	}
	return out, nil
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// FromYAMLFile decodes a single YAML file into a slice of T —
// every `---`-separated document in the file becomes one element.
// Strict-field decoding (KnownFields) is the same as FromYAMLDir.
//
// Used by callers that already know which file to load (e.g. the
// `apis verify` command resolving a path from a manifest's
// `apis: [...]` list) and don't want a directory walk.
func FromYAMLFile[T any](path string) ([]T, error) {
	return decodeMulti[T](path)
}

func decodeMulti[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	// Reject unknown fields so a typo in config (`conditon:` for
	// `condition:`, `base_ulr:` for `base_url:`) fails at load with
	// line context instead of decoding to a zero-valued field that
	// surfaces later as "policy never fires" or "every meta call
	// hits an empty URL."
	dec.KnownFields(true)
	var out []T
	for {
		var v T
		err := dec.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
