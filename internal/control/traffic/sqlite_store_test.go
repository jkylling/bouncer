package traffic_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/control/store"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/control/traffic/storetest"
)

// TestSQLiteStoreContract drives the shared behavioural suite
// against a fresh on-disk sqlite file per subtest. Each subtest
// gets its own path so the storetest.Run loop can be reordered or
// parallelised without cross-contamination.
func TestSQLiteStoreContract(t *testing.T) {
	const maxBytes = 64 * 1024
	const maxAge = time.Hour
	storetest.Run(t, storetest.Config{
		New: func(t *testing.T) traffic.Store {
			path := filepath.Join(t.TempDir(), "traffic.db")
			b, err := store.OpenSQLite(path)
			if err != nil {
				t.Fatalf("store.OpenSQLite: %v", err)
			}
			t.Cleanup(func() { _ = b.Close() })
			s, err := traffic.Open(b, traffic.Options{MaxBytes: maxBytes, MaxAge: maxAge})
			if err != nil {
				t.Fatalf("traffic.Open: %v", err)
			}
			return s
		},
		MaxBytes: maxBytes,
		MaxAge:   maxAge,
	})
}

// TestSQLiteSchemaSurvivesReopen asserts the migration ladder is
// idempotent — opening the same file twice does not double-apply
// migrations or drop existing rows.
func TestSQLiteSchemaSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.db")
	b1, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("first OpenSQLite: %v", err)
	}
	if _, err := traffic.Open(b1, traffic.Options{}); err != nil {
		t.Fatalf("first traffic.Open: %v", err)
	}
	if err := b1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}
	b2, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("second OpenSQLite: %v", err)
	}
	if _, err := traffic.Open(b2, traffic.Options{}); err != nil {
		t.Fatalf("second traffic.Open: %v", err)
	}
	if err := b2.Close(); err != nil {
		t.Fatalf("close 2: %v", err)
	}
}
