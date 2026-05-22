package proposals

import (
	"fmt"

	"github.com/jkylling/bouncer/internal/control/store"
)

// Open returns a sqlite-backed Store sharing b's *sql.DB. In-memory
// deployments call NewMemoryStore directly. Other backend kinds
// (including FSBackend) return ErrUnsupportedBackend: a per-proposal
// yaml file would buy nothing over sqlite for the small (~hundreds)
// volumes proposals see, and the small/medium deployment story for
// proposals is "memory" anyway.
func Open(b store.Backend) (Store, error) {
	backend, ok := b.(store.SQLBackend)
	if !ok {
		return nil, fmt.Errorf("proposals: %w (got %T)", store.ErrUnsupportedBackend, b)
	}
	return newSQLiteStore(backend)
}
