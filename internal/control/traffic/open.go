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
	// MaxBytes caps the summed size of non-pinned events. Pinned
	// rows live by the pinned-count cap instead.
	MaxBytes int

	// MaxAge evicts non-pinned rows older than this regardless of
	// byte pressure. Zero falls back to DefaultMaxAge.
	MaxAge time.Duration

	// MaxPinned is the hard cap on pinned rows. Pin returns
	// ErrPinnedFull past the cap.
	MaxPinned int
}

// Open returns a Store backed by b. The dispatch is by backend type:
//
//   - store.SQLBackend → sqlite-backed store sharing b's *sql.DB
//   - store.MemoryBackend → in-process map+list store
//
// Other backend kinds (e.g. FSBackend) return ErrUnsupportedBackend
// — traffic's append-heavy filtering needs indexed storage that the
// FS backend can't provide cheaply, so a misconfigured deployment
// fails at boot rather than degrading silently.
func Open(b store.Backend, opts Options) (Store, error) {
	switch backend := b.(type) {
	case store.SQLBackend:
		return newSQLiteStore(backend, opts)
	case store.MemoryBackend:
		return newMemoryStore(opts), nil
	default:
		return nil, fmt.Errorf("traffic: %w (got %T)", store.ErrUnsupportedBackend, b)
	}
}
