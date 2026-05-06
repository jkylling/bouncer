package policies

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

func newFileStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	return store, dir
}

func TestFileStorePutThenList(t *testing.T) {
	store, _ := newFileStore(t)
	policies := []models.Policy{
		{API: "svc", Name: "p1", Action: "true", Condition: "true", Result: models.Permit},
		{API: "svc", Name: "p2", Action: "true", Condition: "false", Result: models.Deny},
	}
	for _, p := range policies {
		if err := store.Put(context.Background(), p); err != nil {
			t.Fatalf("put %q: %v", p.Name, err)
		}
	}
	got, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	if !reflect.DeepEqual(got, policies) {
		t.Errorf("got %+v, want %+v", got, policies)
	}
}

func TestFileStorePutOverwritesByName(t *testing.T) {
	store, dir := newFileStore(t)
	first := models.Policy{API: "svc", Name: "p1", Action: "true", Condition: "true", Result: models.Permit}
	if err := store.Put(context.Background(), first); err != nil {
		t.Fatalf("first put: %v", err)
	}
	updated := first
	updated.Condition = "1 == 1"
	if err := store.Put(context.Background(), updated); err != nil {
		t.Fatalf("second put: %v", err)
	}
	got, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Condition != "1 == 1" {
		t.Errorf("after overwrite got %+v", got)
	}
	// File rewritten in place — only one entry on disk.
	body, err := os.ReadFile(filepath.Join(dir, "svc_policy.yaml"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if want := "1 == 1"; !strings.Contains(string(body), want) {
		t.Errorf("file body = %q, want contains %q", body, want)
	}
}

func TestFileStoreDeleteRemovesFileWhenEmpty(t *testing.T) {
	store, dir := newFileStore(t)
	p := models.Policy{API: "svc", Name: "only", Action: "true", Condition: "true", Result: models.Permit}
	if err := store.Put(context.Background(), p); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Delete(context.Background(), "svc", "only"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "svc_policy.yaml")); !os.IsNotExist(err) {
		t.Errorf("file still exists: stat err = %v", err)
	}
}

// TestFileStorePutScrubsLegacyDuplicate pins a stale
// legacy file whose lex order is later than the canonical must not
// resurrect a previous value on next List. Put walks every YAML in
// the directory and drops any entry matching the (api, name) it
// just authored.
func TestFileStorePutScrubsLegacyDuplicate(t *testing.T) {
	store, dir := newFileStore(t)
	// Seed a non-canonical file whose name sorts AFTER svc_policy.yaml
	// (so the resurrection bug would fire on next List).
	body := []byte("api: svc\nname: p1\naction: 'true'\ncondition: 'false'\nresult: deny\n")
	if err := os.WriteFile(filepath.Join(dir, "zfoo.yaml"), body, 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Put V1 of svc/p1 via the API path.
	if err := store.Put(context.Background(), models.Policy{
		API: "svc", Name: "p1", Action: "true", Condition: "true", Result: models.Permit,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// On next List, the version in the canonical file must win —
	// the legacy file should have been scrubbed of svc/p1.
	got, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Condition != "true" {
		t.Errorf("got %+v, want one Permit copy of svc/p1", got)
	}
	// The legacy file is rewritten without the scrubbed entry, but
	// the file itself stays on disk: silently
	// unlinking an operator-written file is the worse failure mode.
	data, err := os.ReadFile(filepath.Join(dir, "zfoo.yaml"))
	if err != nil {
		t.Fatalf("legacy file unlinked, but contract is keep-it-empty: %v", err)
	}
	if strings.Contains(string(data), "name: p1") {
		t.Errorf("legacy file still carries svc/p1: %q", data)
	}
}

// TestFileStorePutPreservesOtherEntriesInLegacyFile pins that the
// scrub only removes the matching (api, name) — sibling entries in
// the same legacy file survive intact.
func TestFileStorePutPreservesOtherEntriesInLegacyFile(t *testing.T) {
	store, dir := newFileStore(t)
	body := []byte(
		"api: svc\nname: p1\naction: 'true'\ncondition: 'false'\nresult: deny\n" +
			"---\n" +
			"api: svc\nname: keepme\naction: 'true'\ncondition: 'true'\nresult: permit\n",
	)
	if err := os.WriteFile(filepath.Join(dir, "zfoo.yaml"), body, 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := store.Put(context.Background(), models.Policy{
		API: "svc", Name: "p1", Action: "true", Condition: "true", Result: models.Permit,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	if !names["p1"] || !names["keepme"] {
		t.Errorf("List = %+v, want both p1 and keepme", got)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "zfoo.yaml"))
	if !strings.Contains(string(data), "name: keepme") {
		t.Errorf("scrub clobbered sibling entry: %q", data)
	}
}

func TestFileStoreReadsLegacyFilenames(t *testing.T) {
	store, dir := newFileStore(t)
	// Operator writes a file with a non-canonical name (matches the
	// existing live policies/gmail_policy.yaml convention from
	// before the file store landed).
	body := []byte("api: svc\nname: legacy\naction: 'true'\ncondition: 'true'\nresult: permit\n")
	if err := os.WriteFile(filepath.Join(dir, "legacy_things.yaml"), body, 0644); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	got, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Name != "legacy" {
		t.Errorf("legacy policy not surfaced: got %+v", got)
	}
}

// TestFileStoreRejectsTraversalInAPIName pins the defense-in-depth
// guard: even if a caller bypasses the policy Service's validator,
// the FileStore refuses to write outside its root.
func TestFileStoreRejectsTraversalInAPIName(t *testing.T) {
	store, _ := newFileStore(t)
	cases := []string{
		"../escape",
		"/abs/path",
		"a/b",
		"a\\b",
		"..",
		".",
		"",
	}
	for _, api := range cases {
		t.Run(api, func(t *testing.T) {
			err := store.Put(context.Background(), models.Policy{
				API: api, Name: "p", Action: "true", Condition: "true", Result: models.Permit,
			})
			if err == nil {
				t.Errorf("Put with api=%q must reject", api)
			}
		})
	}
}

func TestFileStoreRefusesNonDirectory(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "f")
	if err := os.WriteFile(notDir, []byte{}, 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := NewFileStore(notDir); err == nil {
		t.Fatal("expected error pointing at a regular file")
	}
}
