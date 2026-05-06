package policies

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// FileStore persists policies as YAML files under a directory, one
// canonical file per API at `<dir>/<api>_policy.yaml`. The format
// matches today's hand-edited layout so an operator can switch
// between editing files and using the API without converting.
//
// On List the store walks every `.yaml` / `.yml` file in the
// directory (matching the existing FromYAMLDir behaviour). On Put or
// Delete it rewrites the canonical file for the affected API
// atomically (write-temp + rename). Non-canonical files are read but
// never written: an operator with policies spread across legacy
// filenames sees both on List, and a Put to one of those policies
// migrates it into the canonical file. The legacy entry stays on disk
// (so a hand-edit isn't silently dropped) — the operator removes the
// stale file when ready.
type FileStore struct {
	mu  sync.Mutex
	dir string
}

// NewFileStore returns a FileStore rooted at dir. The directory must
// exist; we don't auto-create it because a typo'd flag value
// silently writing to a fresh directory is exactly the failure mode
// most likely to confuse an operator. A future `--init` command can
// MkdirAll on demand.
func NewFileStore(dir string) (*FileStore, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("policies dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("policies dir %q is not a directory", dir)
	}
	return &FileStore{dir: dir}, nil
}

// List reads every YAML file in the dir and returns the union of
// their policies. Duplicates (same api+name across files) are
// returned as-is — the caller (Service.LoadFromStore) feeds them
// through ReplacePolicy so the last one wins.
func (f *FileStore) List(_ context.Context) ([]models.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readAll()
}

// Put rewrites the canonical file for p.API with p replacing any
// existing entry of the same name. The full set of policies for that
// API is read first (including those in legacy filenames), modified
// in memory, then written atomically.
//
// If the same (api, name) appears in any non-canonical file (a
// legacy hand-edited layout), Put scrubs that entry from the legacy
// file *after* the canonical write succeeds. Without this, the next
// Load could resurrect the stale value: readAll sorts files
// alphabetically and replays them through ReplacePolicy, so a
// legacy file whose name sorts after `<api>_policy.yaml` would
// silently overwrite the just-PUT version. Ordering matters: a
// scrub that runs first and then fails before the canonical write
// would mutate the operator's hand-edited file with no replacement
// on disk. With scrub-after-write, a partial scrub failure leaves
// the canonical authoritative — the duplicate-resolution bug it
// would have prevented is at worst still present, never made
// destructive. Scrub failures are logged and do not fail Put.
func (f *FileStore) Put(_ context.Context, p models.Policy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	all, err := f.readAll()
	if err != nil {
		return err
	}
	apiPolicies := filterByAPI(all, p.API)
	apiPolicies = upsert(apiPolicies, p)
	if err := f.writeAPIFile(p.API, apiPolicies); err != nil {
		return err
	}
	if err := f.scrubLegacyEntry(p.API, p.Name); err != nil {
		slog.Warn("policies/file: legacy scrub failed; canonical is authoritative",
			"api", p.API, "name", p.Name, "err", err)
	}
	return nil
}

// Delete rewrites the canonical file for the API with the named
// policy removed. Same legacy-scrub as Put: if a stale copy of
// (api, name) lives in a non-canonical file, drop it so the
// operator's hand-edit can't reanimate the deleted policy on next
// boot. Idempotent on a missing entry (returns ErrNotFound) and on a
// scrub-time failure (the canonical is already authoritative).
func (f *FileStore) Delete(_ context.Context, api, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	all, err := f.readAll()
	if err != nil {
		return err
	}
	scoped := filterByAPI(all, api)
	apiPolicies := remove(scoped, name)
	if len(apiPolicies) == len(scoped) {
		// Nothing matched. Mirror the proposals/sqlite contract so
		// a bypass-Service caller can distinguish "already gone"
		// from "deleted just now".
		return fmt.Errorf("%w: %s/%s", ErrNotFound, api, name)
	}
	if err := f.writeAPIFile(api, apiPolicies); err != nil {
		return err
	}
	if err := f.scrubLegacyEntry(api, name); err != nil {
		slog.Warn("policies/file: legacy scrub failed; canonical is authoritative",
			"api", api, "name", name, "err", err)
	}
	return nil
}

// scrubLegacyEntry walks every non-canonical YAML in the directory
// and removes any entry matching (api, name). The canonical file
// (`<api>_policy.yaml`) is skipped — Put / Delete already wrote it
// as a whole.
//
// A legacy file whose only entry was the one we just replaced is
// kept on disk with the entry filtered out (zero entries → empty
// file) rather than unlinked. The package-doc contract is "operator
// hand-edits aren't silently dropped": deleting the file would
// surprise an operator whose `git status` suddenly shows their
// curated file gone with no audit trail. Leaving an empty file in
// place lets them see the divergence at the next `ls`, see what was
// removed in `git diff`, and clean up themselves.
func (f *FileStore) scrubLegacyEntry(api, name string) error {
	canonical := api + "_policy.yaml"
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !isYAML(e) || e.Name() == canonical {
			continue
		}
		path := filepath.Join(f.dir, e.Name())
		// Cheap skim first: scan the file for the literal name
		// before paying the YAML decode + KnownFields strict
		// pass. Saves the strict-mode cost on the common case
		// where a directory has many YAMLs but only one carries
		// the entry being scrubbed. False positives still pay the
		// decode but the worst case stays at O(matching files).
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		if !mightContainEntry(raw, api, name) {
			continue
		}
		policies, err := decodePoliciesFile(path)
		if err != nil {
			return fmt.Errorf("decode %s: %w", e.Name(), err)
		}
		kept := withoutEntry(policies, api, name)
		if len(kept) == len(policies) {
			continue // no match after decode
		}
		var buf bytes.Buffer
		if len(kept) > 0 {
			enc := yaml.NewEncoder(&buf)
			enc.SetIndent(2)
			for i := range kept {
				if err := enc.Encode(kept[i]); err != nil {
					return fmt.Errorf("encode in %s: %w", e.Name(), err)
				}
			}
			if err := enc.Close(); err != nil {
				return fmt.Errorf("close encoder for %s: %w", e.Name(), err)
			}
		}
		if err := atomicWrite(path, buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// mightContainEntry is the cheap pre-scan that lets scrubLegacyEntry
// skip the YAML decode for files that obviously can't carry the
// matching entry. Both substrings must appear; false positives still
// pay the decode-then-no-match cost, but the common case (most
// legacy files don't carry the just-PUT name) skips it entirely.
func mightContainEntry(raw []byte, api, name string) bool {
	return bytes.Contains(raw, []byte(api)) && bytes.Contains(raw, []byte(name))
}

// withoutEntry returns the input slice with any entry matching
// (api, name) removed. Verb-named to keep call-sites readable
// (`kept := withoutEntry(...)`) and to avoid shadowing common
// helper names.
func withoutEntry(in []models.Policy, api, name string) []models.Policy {
	out := make([]models.Policy, 0, len(in))
	for _, p := range in {
		if p.API == api && p.Name == name {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (f *FileStore) readAll() ([]models.Policy, error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}
	// Stable order across operating systems (ReadDir's order is not
	// guaranteed). Sort by filename so the "last write wins" rule
	// for duplicates is deterministic and reproducible.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var all []models.Policy
	for _, e := range entries {
		if !e.Type().IsRegular() || !isYAML(e) {
			continue
		}
		path := filepath.Join(f.dir, e.Name())
		policies, err := decodePoliciesFile(path)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", e.Name(), err)
		}
		all = append(all, policies...)
	}
	return all, nil
}

// writeAPIFile writes policies (already scoped to api) atomically to
// `<dir>/<api>_policy.yaml`. If policies is empty, the file is removed
// — keeping a zero-policy file would be misleading on next List.
func (f *FileStore) writeAPIFile(api string, policies []models.Policy) error {
	if !validAPIName(api) {
		// Defense in depth against path traversal: the policies
		// Service already rejects unregistered names, but a future
		// rewiring that bypasses Service would otherwise turn this
		// file write into a `..`/separator primitive. Cheap to check
		// at the boundary instead of trusting the caller.
		return fmt.Errorf("invalid api name %q (must be a single path component)", api)
	}
	path := filepath.Join(f.dir, api+"_policy.yaml")
	if len(policies) == 0 {
		// Remove rather than leave an empty file behind. ENOENT is
		// fine: nothing to clean up.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove empty %s: %w", path, err)
		}
		return nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	for i := range policies {
		if err := enc.Encode(policies[i]); err != nil {
			return fmt.Errorf("encode policy %q: %w", policies[i].Name, err)
		}
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close encoder: %w", err)
	}
	return atomicWrite(path, buf.Bytes())
}

// atomicWrite writes data to path via a sibling temp file + rename so
// a crash mid-write never leaves a half-rewritten policy file. fsync
// before rename guarantees the data is durable; fsync on the parent
// directory after rename guarantees the rename itself is durable.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".policy.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func decodePoliciesFile(path string) ([]models.Policy, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	var out []models.Policy
	for {
		var p models.Policy
		if err := dec.Decode(&p); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// validAPIName mirrors the single-component check in
// store.fsBackend: empty / `.` / `..` / paths containing separators
// or absolute paths are rejected. Anything that survives this check
// is safe to interpolate into `<dir>/<api>_policy.yaml`.
func validAPIName(api string) bool {
	if api == "" || api == "." || api == ".." {
		return false
	}
	if strings.ContainsAny(api, `/\`) {
		return false
	}
	if filepath.IsAbs(api) {
		return false
	}
	return true
}

func isYAML(e fs.DirEntry) bool {
	n := strings.ToLower(e.Name())
	return strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")
}

func filterByAPI(all []models.Policy, api string) []models.Policy {
	var out []models.Policy
	for _, p := range all {
		if p.API == api {
			out = append(out, p)
		}
	}
	return out
}

func upsert(ps []models.Policy, p models.Policy) []models.Policy {
	for i := range ps {
		if ps[i].Name == p.Name {
			ps[i] = p
			return ps
		}
	}
	return append(ps, p)
}

func remove(ps []models.Policy, name string) []models.Policy {
	for i := range ps {
		if ps[i].Name == name {
			return append(ps[:i], ps[i+1:]...)
		}
	}
	return ps
}
