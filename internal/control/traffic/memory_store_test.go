package traffic_test

import (
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/control/store"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/control/traffic/storetest"
)

// TestMemoryStoreContract drives the shared behavioural suite
// against the in-memory backend with a budget tight enough that the
// eviction subtests trigger.
func TestMemoryStoreContract(t *testing.T) {
	const maxBytes = 64 * 1024
	const maxAge = time.Hour
	storetest.Run(t, storetest.Config{
		New: func(t *testing.T) traffic.Store {
			s, err := traffic.Open(store.Memory(), traffic.Options{MaxBytes: maxBytes, MaxAge: maxAge})
			if err != nil {
				t.Fatalf("traffic.Open: %v", err)
			}
			return s
		},
		MaxBytes: maxBytes,
		MaxAge:   maxAge,
	})
}
