package proposals

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jkylling/bouncer/internal/control/store"
)

// migrationNamespace is the namespace key the SQLBackend uses to
// track this domain's schema version. Independent from the policies
// and traffic namespaces, so the three can coexist in one DB file.
const migrationNamespace = "proposals"

// listHardLimit caps how many proposals a single List query returns.
// The admin UI paginates client-side; the cap exists so a runaway
// table can't OOM the proxy on one call. 10k is well above any
// realistic outstanding-proposal count.
const listHardLimit = 10_000

// proposalsMigrations is the schema ladder. Append-only.
var proposalsMigrations = []string{
	// v1: one row per proposal id. status + api are indexed columns
	// so List filters use SQL rather than a full-table scan; the
	// payload column round-trips Proposal verbatim.
	`CREATE TABLE IF NOT EXISTS proposals (
		id      TEXT PRIMARY KEY,
		status  TEXT NOT NULL DEFAULT '',
		api     TEXT NOT NULL DEFAULT '',
		payload BLOB NOT NULL
	);
	CREATE INDEX IF NOT EXISTS proposals_status ON proposals(status);
	CREATE INDEX IF NOT EXISTS proposals_api ON proposals(api);`,
}

// sqliteStore is the SQLite-backed proposals.Store. Backed by a
// store.SQLBackend so proposals can live in the same file as the
// policies and traffic tables.
//
// No internal mutex: *sql.DB is goroutine-safe for the single
// statement each method runs, and proposals.Service.mu already
// serialises every write across the (find, replace, put) chain. A
// half-locked store (Put/Delete locked, Get/List unlocked) would
// look like a contract that bypass-Service callers could rely on,
// which it isn't — so we don't ship one.
type sqliteStore struct {
	db *sql.DB
}

func newSQLiteStore(b store.SQLBackend) (*sqliteStore, error) {
	if err := b.Migrate(migrationNamespace, proposalsMigrations); err != nil {
		return nil, fmt.Errorf("proposals: migrate: %w", err)
	}
	return &sqliteStore{db: b.DB()}, nil
}

func (s *sqliteStore) Get(ctx context.Context, id ProposalID) (Proposal, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM proposals WHERE id = ?`, id.String()).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Proposal{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Proposal{}, fmt.Errorf("proposals/sqlite: get: %w", err)
	}
	var p Proposal
	if err := json.Unmarshal(payload, &p); err != nil {
		return Proposal{}, fmt.Errorf("proposals/sqlite: decode: %w", err)
	}
	return p, nil
}

func (s *sqliteStore) Put(ctx context.Context, p Proposal) error {
	payload, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("proposals/sqlite: marshal: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO proposals (id, status, api, payload) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			status = excluded.status,
			api = excluded.api,
			payload = excluded.payload
	`, p.ID.String(), string(p.Status), p.Policy.API, payload)
	if err != nil {
		return fmt.Errorf("proposals/sqlite: put: %w", err)
	}
	return nil
}

// Delete removes the proposal at id. ErrNotFound rather than a silent
// no-op: the Service uses Delete for the explicit purge path and a
// missing id likely indicates a stale UI.
func (s *sqliteStore) Delete(ctx context.Context, id ProposalID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM proposals WHERE id = ?`, id.String())
	if err != nil {
		return fmt.Errorf("proposals/sqlite: delete: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("proposals/sqlite: delete rows: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// List returns proposals matching opts. Status and API filters use
// the indexed columns; the payload itself is decoded for every
// returned row.
func (s *sqliteStore) List(ctx context.Context, opts ListOpts) ([]Proposal, error) {
	q := `SELECT payload FROM proposals`
	var where []string
	var args []any
	if opts.Status != "" {
		where = append(where, "status = ?")
		args = append(args, string(opts.Status))
	}
	if opts.API != "" {
		where = append(where, "api = ?")
		args = append(args, opts.API)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	// Cap the result set so a runaway proposal table can't OOM the
	// proxy on a single List call. The cap is high enough that
	// ordinary admin browsing never trips it; pagination is a future
	// addition that would slot in here naturally.
	q += " ORDER BY id LIMIT ?"
	args = append(args, listHardLimit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("proposals/sqlite: list: %w", err)
	}
	defer rows.Close()
	var out []Proposal
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("proposals/sqlite: scan: %w", err)
		}
		var p Proposal
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, fmt.Errorf("proposals/sqlite: decode: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("proposals/sqlite: rows: %w", err)
	}
	return out, nil
}
