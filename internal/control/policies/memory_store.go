package policies

import (
	"fmt"

	"github.com/jkylling/bouncer/internal/control/store"
)

// NewMemoryStore returns an ephemeral Store backed by a private
// `:memory:` SQLite database. Same code path as the on-disk backend
// — what differs is only where the bytes live, so the runtime
// contract (ErrNotFound semantics, JSON payload round-trip, etc.) is
// uniform across the two.
//
// The backend is owned by the returned store and never reused; tests
// can drop their reference and let GC reclaim the connection pool.
// Panics on open/migrate failure because `:memory:` cannot fail for
// either reason on a healthy modernc.org/sqlite build — a panic here
// surfaces a genuinely broken dependency rather than a recoverable
// runtime condition.
func NewMemoryStore() Store {
	b, err := store.OpenSQLite(":memory:")
	if err != nil {
		panic(fmt.Errorf("policies: open :memory:: %w", err))
	}
	s, err := newSQLiteStore(b)
	if err != nil {
		_ = b.Close()
		panic(fmt.Errorf("policies: migrate :memory:: %w", err))
	}
	return s
}
