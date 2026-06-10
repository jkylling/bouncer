package traffic

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/control/store"
)

// TestMigrationV2DropsPinnedFromPopulatedV1 pins the upgrade path for
// existing deployments: a database created at schema v1 (with the
// dead pinned column) migrates to v2 with its rows intact, the column
// and index gone, and the store still writable.
func TestMigrationV2DropsPinnedFromPopulatedV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.db")
	b1, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := b1.Migrate(migrationNamespace, trafficMigrations[:1]); err != nil {
		t.Fatalf("apply v1: %v", err)
	}
	if _, err := b1.DB().Exec(
		`INSERT INTO events (id, ts, pinned, size_bytes, payload) VALUES ('e1', 1, 1, 10, '{"id":"e1"}')`,
	); err != nil {
		t.Fatalf("seed v1 row: %v", err)
	}
	if err := b1.Close(); err != nil {
		t.Fatalf("close v1: %v", err)
	}

	b2, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer b2.Close()
	s, err := newSQLiteStore(b2, Options{})
	if err != nil {
		t.Fatalf("open store at v2: %v", err)
	}

	var rows int
	if err := b2.DB().QueryRow(`SELECT count(*) FROM events`).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("rows = %d, want 1 (v1 data must survive the migration)", rows)
	}
	var pinnedCols int
	if err := b2.DB().QueryRow(
		`SELECT count(*) FROM pragma_table_info('events') WHERE name = 'pinned'`,
	).Scan(&pinnedCols); err != nil {
		t.Fatalf("inspect schema: %v", err)
	}
	if pinnedCols != 0 {
		t.Error("pinned column still present after v2 migration")
	}
	if err := s.Insert(context.Background(), Event{ID: "e2", Timestamp: time.Now()}); err != nil {
		t.Errorf("insert after migration: %v", err)
	}
}
