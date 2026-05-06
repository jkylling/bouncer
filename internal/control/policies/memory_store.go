package policies

import (
	"context"
	"fmt"
	"sync"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// MemoryStore is an in-memory Store. It is the default backend in
// tests and a sensible default for ephemeral deployments — a process
// restart loses everything written through Put / Delete. The file
// backend (FileStore) is the right choice when persistence is wanted.
type MemoryStore struct {
	mu       sync.Mutex
	policies map[memKey]models.Policy
}

// memKey is the (api, name) tuple keyed into MemoryStore. Using a
// struct rather than `api + "/" + name` removes any encoding
// ambiguity — `(api="a", name="b/c")` and `(api="a/b", name="c")`
// share no key — without paying a separator-escaping tax. The CRUD
// path does no ranged scans, so map iteration cost is unchanged.
type memKey struct{ api, name string }

// NewMemoryStore returns an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{policies: map[memKey]models.Policy{}}
}

func (m *MemoryStore) List(_ context.Context) ([]models.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]models.Policy, 0, len(m.policies))
	for _, p := range m.policies {
		out = append(out, p)
	}
	return out, nil
}

func (m *MemoryStore) Put(_ context.Context, p models.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[memKey{api: p.API, name: p.Name}] = p
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, api, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memKey{api: api, name: name}
	if _, ok := m.policies[key]; !ok {
		return fmt.Errorf("%w: %s/%s", ErrNotFound, api, name)
	}
	delete(m.policies, key)
	return nil
}
