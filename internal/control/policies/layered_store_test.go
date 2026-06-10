package policies

import (
	"context"
	"errors"
	"testing"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

func layeredFixture(t *testing.T) (*LayeredStore, Store, Store) {
	t.Helper()
	primary, seed := NewMemoryStore(), NewMemoryStore()
	return NewLayeredStore(primary, seed), primary, seed
}

func mustPut(t *testing.T, s Store, p models.Policy) {
	t.Helper()
	if err := s.Put(context.Background(), p); err != nil {
		t.Fatalf("put %s/%s: %v", p.API, p.Name, err)
	}
}

// TestLayeredStoreListSeedFirstPrimaryLast pins the merge contract:
// seed entries precede primary entries so a LoadFromStore replay
// (last wins) gives the store's version precedence over the file's.
func TestLayeredStoreListSeedFirstPrimaryLast(t *testing.T) {
	l, primary, seed := layeredFixture(t)
	mustPut(t, seed, models.Policy{API: "svc", Name: "from-file", Result: models.Permit, Condition: "true"})
	mustPut(t, seed, models.Policy{API: "svc", Name: "shared", Result: models.Permit, Condition: "file-version"})
	mustPut(t, primary, models.Policy{API: "svc", Name: "shared", Result: models.Permit, Condition: "store-version"})
	mustPut(t, primary, models.Policy{API: "svc", Name: "from-store", Result: models.Permit, Condition: "true"})

	got, err := l.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Union of both layers, duplicates included with the primary last.
	if len(got) != 4 {
		t.Fatalf("list returned %d policies, want 4 (union with duplicate): %+v", len(got), got)
	}
	last := map[string]string{}
	for _, p := range got {
		last[p.Name] = string(p.Condition)
	}
	if last["shared"] != "store-version" {
		t.Errorf("shared resolves to %q after replay, want the primary's version", last["shared"])
	}
	if _, ok := last["from-file"]; !ok {
		t.Error("seed-only policy missing from List")
	}
	if _, ok := last["from-store"]; !ok {
		t.Error("primary-only policy missing from List")
	}
}

// TestLayeredStorePutGoesToPrimary pins that writes never touch the
// seed layer — the YAML file is the operator's, not ours to rewrite.
func TestLayeredStorePutGoesToPrimary(t *testing.T) {
	l, primary, seed := layeredFixture(t)
	mustPut(t, l, models.Policy{API: "svc", Name: "p", Result: models.Permit, Condition: "true"})

	if got, _ := primary.List(context.Background()); len(got) != 1 {
		t.Errorf("primary has %d policies, want 1", len(got))
	}
	if got, _ := seed.List(context.Background()); len(got) != 0 {
		t.Errorf("seed has %d policies, want 0 (writes must not reach the file layer)", len(got))
	}
}

// TestLayeredStoreDeleteRefusesSeededPolicies pins the lifecycle
// rule: while a YAML file defines a policy, the control plane cannot
// delete it — removing only a store override would resurrect the
// shadowed file version at the next boot.
func TestLayeredStoreDeleteRefusesSeededPolicies(t *testing.T) {
	l, primary, seed := layeredFixture(t)
	mustPut(t, seed, models.Policy{API: "svc", Name: "seeded", Result: models.Permit, Condition: "true"})
	mustPut(t, primary, models.Policy{API: "svc", Name: "seeded", Result: models.Permit, Condition: "override"})
	mustPut(t, primary, models.Policy{API: "svc", Name: "store-only", Result: models.Permit, Condition: "true"})

	if err := l.Delete(context.Background(), "svc", "seeded"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("delete of seeded policy: err = %v, want ErrReadOnly", err)
	}
	if got, _ := primary.List(context.Background()); len(got) != 2 {
		t.Errorf("primary has %d policies after refused delete, want 2 (override must survive)", len(got))
	}

	if err := l.Delete(context.Background(), "svc", "store-only"); err != nil {
		t.Errorf("delete of store-only policy: %v", err)
	}
	if err := l.Delete(context.Background(), "svc", "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete of absent policy: err = %v, want ErrNotFound", err)
	}
}
