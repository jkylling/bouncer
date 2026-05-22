package bundles

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// LoadedAPI pairs a parsed API spec with diagnostic context. Source
// paths flow into name-conflict messages so an operator can pinpoint
// the offending file without grep.
type LoadedAPI struct {
	Spec models.API

	// Source is the absolute path to the YAML file the API came from.
	Source string

	// BundleDir is the absolute bundle directory, or "" for loose APIs.
	BundleDir string

	// BundleName is the manifest's name for vendored APIs, or "".
	BundleName string

	// Readme is the bundle's README.md bytes when present, else nil.
	// Same value across LoadedAPI from the same bundle.
	Readme []byte

	// Service, when set, is the bundle's service block (slug, title,
	// description). Same pointer-value across LoadedAPI from the same
	// bundle.
	Service *Service

	// TokenVariants is the bundle's `token:` list (bring-your-own-
	// token variants). Empty for bundles that only carry API specs.
	TokenVariants []TokenVariant
}

type LoadOptions struct {
	APIsDir string
}

// LoadAll walks APIsDir: top-level *.yaml are loose specs (lex order),
// then bundles (name order). Cross-set name conflicts (post-rename)
// are rejected here.
//
// Path-prefix overlap is checked by the runtime Builder, not here.
func LoadAll(opt LoadOptions) ([]LoadedAPI, error) {
	if opt.APIsDir == "" {
		return nil, nil
	}
	entries, err := readDirOrEmpty(opt.APIsDir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var loose, bundleDirs []string
	for _, e := range entries {
		if e.IsDir() {
			// Skip in-flight install scratch dirs (`.tmp.*`,
			// `.upgrade-old.*`) and hidden dirs in general.
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			candidate := filepath.Join(opt.APIsDir, e.Name())
			if _, err := os.Stat(filepath.Join(candidate, ManifestFile)); err == nil {
				bundleDirs = append(bundleDirs, candidate)
			}
			continue
		}
		if isYAMLFile(e.Name()) {
			loose = append(loose, filepath.Join(opt.APIsDir, e.Name()))
		}
	}

	var out []LoadedAPI
	for _, path := range loose {
		docs, err := decodeAPIDocs(path)
		if err != nil {
			return nil, err
		}
		for i := range docs {
			out = append(out, LoadedAPI{Spec: docs[i], Source: path})
		}
	}
	for _, dir := range bundleDirs {
		apis, err := loadOneBundle(dir)
		if err != nil {
			return nil, err
		}
		out = append(out, apis...)
	}
	if err := assertUniqueNames(out); err != nil {
		return nil, err
	}
	return out, nil
}

// LoadedService pairs a bundle's Service block with its token-variant
// list and the names of the API specs the same bundle ships. One per
// bundle that declares a service.
type LoadedService struct {
	Service       *Service
	TokenVariants []TokenVariant
	APIs          []string
	BundleName    string
}

// Services returns one LoadedService per bundle that declared a
// `service:` block. Each entry carries the (sorted, deduplicated)
// list of API names shipped by the same bundle so consumers can
// filter live policies and traffic to "events for this service."
// Sorted by slug.
func Services(loaded []LoadedAPI) []LoadedService {
	byBundle := map[string]*LoadedService{}
	for _, l := range loaded {
		if l.Service == nil {
			continue
		}
		entry, ok := byBundle[l.BundleName]
		if !ok {
			entry = &LoadedService{
				Service:       l.Service,
				TokenVariants: l.TokenVariants,
				BundleName:    l.BundleName,
			}
			byBundle[l.BundleName] = entry
		}
		entry.APIs = append(entry.APIs, l.Spec.Name)
	}
	out := make([]LoadedService, 0, len(byBundle))
	for _, v := range byBundle {
		sort.Strings(v.APIs)
		v.APIs = dedupeStrings(v.APIs)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service.Slug < out[j].Service.Slug })
	return out
}

func dedupeStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// Readmes returns per-bundle README bytes keyed by manifest name.
// Bundles without a README and loose APIs are skipped.
func Readmes(loaded []LoadedAPI) map[string][]byte {
	out := map[string][]byte{}
	for _, l := range loaded {
		if l.BundleName == "" || len(l.Readme) == 0 {
			continue
		}
		out[l.BundleName] = l.Readme
	}
	return out
}

// APIBundles maps api-name → bundle-name. Loose APIs are omitted.
func APIBundles(loaded []LoadedAPI) map[string]string {
	out := map[string]string{}
	for _, l := range loaded {
		if l.BundleName == "" {
			continue
		}
		out[l.Spec.Name] = l.BundleName
	}
	return out
}

func readDirOrEmpty(dir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	return entries, nil
}

// loadOneBundle parses the manifest + source.yaml, applies renames,
// and returns LoadedAPI entries. Manifests pointing at missing files
// fail loudly — half a bundle is worse than none.
func loadOneBundle(dir string) ([]LoadedAPI, error) {
	manifest, err := LoadManifest(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, err
	}
	source, err := LoadSource(filepath.Join(dir, SourceFile))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	bundleRoot := filepath.Clean(dir)
	readme, _ := os.ReadFile(filepath.Join(bundleRoot, ReadmeFile))
	var out []LoadedAPI
	for _, rel := range manifest.APIs {
		paths, err := ResolveManifestEntry(bundleRoot, rel)
		if err != nil {
			return nil, fmt.Errorf("bundle %s: %w", manifest.Name, err)
		}
		for _, full := range paths {
			docs, err := decodeAPIDocs(full)
			if err != nil {
				return nil, fmt.Errorf("bundle %s: %w", manifest.Name, err)
			}
			for i := range docs {
				if newName, ok := source.APIRenames[docs[i].Name]; ok {
					docs[i].Name = newName
				}
				out = append(out, LoadedAPI{
					Spec:          docs[i],
					Source:        full,
					BundleDir:     dir,
					BundleName:    manifest.Name,
					Readme:        readme,
					Service:       manifest.Service,
					TokenVariants: manifest.Token,
				})
			}
		}
	}
	return out, nil
}

// ResolveManifestEntry turns a manifest entry into concrete YAML
// files. Exported so CLI verbs (`apis verify`, `apis pack`) walk the
// manifest with the same semantics the loader uses at boot.
func ResolveManifestEntry(bundleRoot, rel string) ([]string, error) {
	full := filepath.Join(bundleRoot, filepath.FromSlash(rel))
	if !strings.HasPrefix(full, bundleRoot+string(os.PathSeparator)) && full != bundleRoot {
		return nil, fmt.Errorf("api path %q escapes bundle directory", rel)
	}
	info, err := os.Stat(full)
	if err != nil {
		return nil, fmt.Errorf("api path %q: %w", rel, err)
	}
	if !info.IsDir() {
		if !isYAMLFile(filepath.Base(full)) {
			return nil, fmt.Errorf("api path %q: not a YAML file", rel)
		}
		return []string{full}, nil
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, fmt.Errorf("api dir %q: %w", rel, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !isYAMLFile(e.Name()) {
			continue
		}
		out = append(out, filepath.Join(full, e.Name()))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("api dir %q: contains no YAML files", rel)
	}
	sort.Strings(out)
	return out, nil
}

func assertUniqueNames(loaded []LoadedAPI) error {
	seen := map[string]string{}
	for _, l := range loaded {
		if prev, ok := seen[l.Spec.Name]; ok {
			return fmt.Errorf("api %q declared twice:\n  - %s\n  - %s\n\nrename one bundle's copy via source.yaml#api_renames or pass --rename on `apis add`",
				l.Spec.Name, prev, l.Source)
		}
		seen[l.Spec.Name] = l.Source
	}
	return nil
}

// decodeAPIDocs reads a (possibly multi-document) API YAML.
// KnownFields(true) rejects typo'd field names at decode.
func decodeAPIDocs(path string) ([]models.API, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var out []models.API
	for {
		var v models.API
		if err := dec.Decode(&v); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, v)
	}
	return out, nil
}

func isYAMLFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
