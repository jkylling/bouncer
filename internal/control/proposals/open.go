package proposals

import (
	"fmt"

	"github.com/jkylling/bouncer/internal/control/store"
)

// Open returns a Store backed by b. Dispatch is by backend type:
//
//   - store.SQLBackend → sqlite-backed store sharing b's *sql.DB
//   - store.MemoryBackend → in-process map, ephemeral
//
// FSBackend is intentionally unsupported: a per-proposal yaml file
// would buy nothing over sqlite for the small (~hundreds) volumes
// proposals see, and the small/medium deployment story for proposals
// is "memory" anyway.
func Open(b store.Backend) (Store, error) {
	switch backend := b.(type) {
	case store.SQLBackend:
		return newSQLiteStore(backend)
	case store.MemoryBackend:
		return NewMemoryStore(), nil
	default:
		return nil, fmt.Errorf("proposals: %w (got %T)", store.ErrUnsupportedBackend, b)
	}
}
