package policies

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// LayeredStore merges a read-only seed layer (hand-edited YAML under
// --policies-dir) with a writable primary (the sqlite store). It is
// what lets a data-dir deployment use *both* policy sources: files
// dropped into <data-dir>/policies/ load at boot, and control-plane
// edits persist to sqlite.
//
// Semantics:
//   - List returns seed entries first, primary entries last. Callers
//     replay the list through ReplacePolicy (last wins, the same
//     duplicate contract FileStore.List documents), so a primary
//     entry overrides a seed entry with the same (api, name).
//   - Put goes to the primary only. An edit to a seeded policy
//     therefore shadows the YAML file from then on — the file is
//     never rewritten behind the operator's back.
//   - Delete refuses (ErrReadOnly) whenever the seed defines the
//     policy, even if a primary override also exists: removing only
//     the override would resurrect the shadowed file version at the
//     next boot, and removing a seed-only policy can't stick at all.
//     The file's lifecycle belongs to the file — delete the YAML,
//     then (if an override row remains) delete via the API.
type LayeredStore struct {
	primary Store
	seed    Store
}

// NewLayeredStore returns primary with seed layered underneath.
func NewLayeredStore(primary, seed Store) *LayeredStore {
	return &LayeredStore{primary: primary, seed: seed}
}

// List returns the seed policies followed by the primary's. Each
// seed policy shadowed by a same-named primary entry is logged once
// per List so an operator who edits the YAML file and sees nothing
// change has a trail to follow.
func (l *LayeredStore) List(ctx context.Context) ([]models.Policy, error) {
	seeded, err := l.seed.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("seed layer: %w", err)
	}
	stored, err := l.primary.List(ctx)
	if err != nil {
		return nil, err
	}
	overridden := make(map[[2]string]bool, len(stored))
	for _, p := range stored {
		overridden[[2]string{p.API, p.Name}] = true
	}
	for _, p := range seeded {
		if overridden[[2]string{p.API, p.Name}] {
			slog.Warn("policy file shadowed by a store edit; the YAML version is ignored",
				"api", p.API, "policy", p.Name)
		}
	}
	return append(seeded, stored...), nil
}

func (l *LayeredStore) Put(ctx context.Context, policy models.Policy) error {
	return l.primary.Put(ctx, policy)
}

func (l *LayeredStore) Delete(ctx context.Context, api, name string) error {
	seeded, err := l.seed.List(ctx)
	if err != nil {
		return fmt.Errorf("seed layer: %w", err)
	}
	for _, p := range seeded {
		if p.API == api && p.Name == name {
			return fmt.Errorf("policy %s/%s is defined in the policies directory; delete its YAML file instead: %w", api, name, ErrReadOnly)
		}
	}
	return l.primary.Delete(ctx, api, name)
}
