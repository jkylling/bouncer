package policies

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jkylling/bouncer/internal/control/store"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// migrationNamespace is the namespace key the SQLBackend uses to
// track this domain's schema version. Keeping it as a constant means
// callers don't need to know the value — newSQLiteStore is the only
// place that mentions it.
const migrationNamespace = "policies"

// policiesMigrations is the schema ladder. Append-only; each entry
// is one migration script.
var policiesMigrations = []string{
	// v1: one row per (api, name) holding the JSON-encoded policy.
	// The payload column round-trips models.Policy verbatim so the
	// wire shape and the on-disk shape stay in lockstep.
	`CREATE TABLE IF NOT EXISTS policies (
		api     TEXT NOT NULL,
		name    TEXT NOT NULL,
		payload BLOB NOT NULL,
		PRIMARY KEY (api, name)
	)`,
}

// sqliteStore is the SQLite-backed policies.Store. The *sql.DB is
// owned by the supplied store.SQLBackend so multiple domains can
// share one file.
type sqliteStore struct {
	db *sql.DB

	// mu serialises writes so a Put/Delete race can't run
	// migrations and write rows concurrently. Reads run through the
	// *sql.DB pool unlocked.
	mu sync.Mutex
}

// newSQLiteStore wires the supplied SQLBackend to this domain's
// schema ladder and returns the live store.
func newSQLiteStore(b store.SQLBackend) (*sqliteStore, error) {
	if err := b.Migrate(migrationNamespace, policiesMigrations); err != nil {
		return nil, fmt.Errorf("policies: migrate: %w", err)
	}
	return &sqliteStore{db: b.DB()}, nil
}

// List returns every persisted policy. Order is by (api, name) so
// the result is stable across calls — the runtime re-applies in
// the same order on every boot.
func (s *sqliteStore) List(ctx context.Context) ([]models.Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM policies ORDER BY api, name`)
	if err != nil {
		return nil, fmt.Errorf("policies/sqlite: list: %w", err)
	}
	defer rows.Close()
	var out []models.Policy
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("policies/sqlite: scan: %w", err)
		}
		var p models.Policy
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, fmt.Errorf("policies/sqlite: decode: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policies/sqlite: rows: %w", err)
	}
	return out, nil
}

// Put upserts the policy at (api, name). The Service has already
// validated p, so a corrupted payload here is a programmer error —
// the JSON marshal can only fail on a type the runtime would have
// rejected at compile time.
func (s *sqliteStore) Put(ctx context.Context, p models.Policy) error {
	payload, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("policies/sqlite: marshal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO policies (api, name, payload) VALUES (?, ?, ?)
		ON CONFLICT(api, name) DO UPDATE SET payload = excluded.payload
	`, p.API, p.Name, payload)
	if err != nil {
		return fmt.Errorf("policies/sqlite: put: %w", err)
	}
	return nil
}

// Delete removes the policy at (api, name). Returns ErrNotFound
// when no row matched, mirroring the Store contract: bypass-Service
// callers (reconciliation loops, bulk imports) get a clean
// already-deleted signal instead of a silent no-op.
func (s *sqliteStore) Delete(ctx context.Context, api, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE api = ? AND name = ?`, api, name)
	if err != nil {
		return fmt.Errorf("policies/sqlite: delete: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("policies/sqlite: delete rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s/%s", ErrNotFound, api, name)
	}
	return nil
}
