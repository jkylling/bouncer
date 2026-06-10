package traffic

import (
	"fmt"
	"time"

	"github.com/jkylling/bouncer/internal/control/store"
)

// Options configure the traffic store regardless of backend. Zero
// values pick the package-level defaults so callers can pass
// `Options{}` for development.
type Options struct {
	// MaxBytes caps the summed size of stored events.
	MaxBytes int

	// MaxAge evicts rows older than this regardless of byte
	// pressure. Zero falls back to DefaultMaxAge.
	MaxAge time.Duration
}

// Open returns a sqlite-backed Store sharing b's *sql.DB. Use
// NewMemoryStore for the in-process variant; the two share no
// state, so picking one is a deployment decision rather than a
// backend-pool question.
//
// Non-SQL backends return ErrUnsupportedBackend — traffic's
// append-heavy filtering needs indexed storage that the FS backend
// can't provide cheaply, so a misconfigured deployment fails at
// boot rather than degrading silently.
func Open(b store.Backend, opts Options) (Store, error) {
	backend, ok := b.(store.SQLBackend)
	if !ok {
		return nil, fmt.Errorf("traffic: %w (got %T)", store.ErrUnsupportedBackend, b)
	}
	return newSQLiteStore(backend, opts)
}

// NewMemoryStore returns an ephemeral in-process Store. The
// implementation is a bounded ring buffer with eviction tuned to
// match the sqlite store's byte/age budget semantics; tests and the
// `--traffic-store=memory` deployment path both land here.
func NewMemoryStore(opts Options) Store {
	return newMemoryStore(opts)
}
