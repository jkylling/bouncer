package policies

import (
	"fmt"

	"github.com/jkylling/bouncer/internal/control/store"
)

// Open returns a Store backed by b. Dispatch is by backend type:
//
//   - store.SQLBackend → sqlite-backed store sharing b's *sql.DB
//   - store.FSBackend → YAML files under <root>/policies, matching
//     the existing hand-edited layout (one canonical file per API)
//
// In-memory deployments call NewMemoryStore directly. Other backend
// kinds return ErrUnsupportedBackend so a misconfigured deployment
// fails at boot rather than silently degrading.
func Open(b store.Backend) (Store, error) {
	switch backend := b.(type) {
	case store.SQLBackend:
		return newSQLiteStore(backend)
	case store.FSBackend:
		dir, err := backend.Subdir("policies")
		if err != nil {
			return nil, fmt.Errorf("policies: subdir: %w", err)
		}
		return NewFileStore(dir)
	default:
		return nil, fmt.Errorf("policies: %w (got %T)", store.ErrUnsupportedBackend, b)
	}
}
