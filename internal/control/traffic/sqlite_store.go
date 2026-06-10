package traffic

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jkylling/bouncer/internal/control/store"
)

// migrationNamespace is the per-store namespace key the SQLBackend
// uses to track this domain's migration version. Keeping it as a
// constant means the boot path doesn't need to know the value — the
// constructor below is the single source of truth.
const migrationNamespace = "traffic"

// trafficMigrations is the schema ladder. Each entry is one
// migration script (one or more statements separated by `;`). The
// shared store.SQLBackend.Migrate runs them through a per-namespace
// version tracker, so this slice can grow over time without
// affecting other domains' tables in the same database.
var trafficMigrations = []string{
	// v1: events table + indices.
	`CREATE TABLE IF NOT EXISTS events (
		id TEXT PRIMARY KEY,
		ts INTEGER NOT NULL,
		subject TEXT NOT NULL DEFAULT '',
		method TEXT NOT NULL DEFAULT '',
		url TEXT NOT NULL DEFAULT '',
		api TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT '',
		decision TEXT NOT NULL DEFAULT '',
		policy TEXT NOT NULL DEFAULT '',
		upstream_status INTEGER NOT NULL DEFAULT 0,
		latency_ms INTEGER NOT NULL DEFAULT 0,
		pinned INTEGER NOT NULL DEFAULT 0,
		size_bytes INTEGER NOT NULL DEFAULT 0,
		payload BLOB NOT NULL
	);
	CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC, id DESC);
	CREATE INDEX IF NOT EXISTS events_api_ts ON events(api, ts DESC);
	CREATE INDEX IF NOT EXISTS events_subject_ts ON events(subject, ts DESC);
	CREATE INDEX IF NOT EXISTS events_pinned_ts ON events(pinned, ts ASC);`,

	// v2: drop the pinned column + index. They shipped ahead of any
	// Pin API — nothing ever wrote the column and eviction never
	// consulted it, while the --traffic-budget help promised a
	// pin-aware retention guarantee that didn't exist. Reintroduce
	// alongside a real Pin feature if one lands.
	`DROP INDEX IF EXISTS events_pinned_ts;
	ALTER TABLE events DROP COLUMN pinned;`,
}

// sqliteStore is the SQLite-backed traffic store. It does not own
// the *sql.DB — the supplied store.SQLBackend does — so Close is a
// no-op and the boot path is free to share the same backend across
// other domains' stores.
type sqliteStore struct {
	db   *sql.DB
	opts Options
	// mu serialises Insert so the multi-statement eviction logic stays
	// consistent without relying on SQLite's SERIALIZABLE-by-default-
	// but-not-quite isolation. Reads run through database/sql's pool
	// concurrently.
	mu sync.Mutex
}

// newSQLiteStore wires opts to b's underlying *sql.DB and applies
// the migration ladder. Returns an error only on driver/migration
// failure; a successful call leaves the events table ready.
func newSQLiteStore(b store.SQLBackend, opts Options) (*sqliteStore, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	if err := b.Migrate(migrationNamespace, trafficMigrations); err != nil {
		return nil, fmt.Errorf("traffic: migrate: %w", err)
	}
	return &sqliteStore{db: b.DB(), opts: opts}, nil
}

// Close is a no-op — the *sql.DB is owned by the store.SQLBackend.
func (s *sqliteStore) Close() error { return nil }

// Insert writes ev and runs eviction in one transaction.
func (s *sqliteStore) Insert(ctx context.Context, ev Event) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("traffic/sqlite: marshal event: %w", err)
	}
	size := len(payload)

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("traffic/sqlite: begin: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO events (id, ts, subject, method, url, api, action, decision, policy, upstream_status, latency_ms, size_bytes, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ts = excluded.ts,
			subject = excluded.subject,
			method = excluded.method,
			url = excluded.url,
			api = excluded.api,
			action = excluded.action,
			decision = excluded.decision,
			policy = excluded.policy,
			upstream_status = excluded.upstream_status,
			latency_ms = excluded.latency_ms,
			size_bytes = excluded.size_bytes,
			payload = excluded.payload
		`,
		ev.ID, ev.Timestamp.UnixMilli(), ev.Subject, ev.Method, ev.URL,
		ev.API, ev.Action, ev.Decision, ev.Policy, ev.UpstreamStatus,
		ev.LatencyMS, size, payload,
	)
	if err != nil {
		return fmt.Errorf("traffic/sqlite: insert: %w", err)
	}
	if err := evictTx(ctx, tx, s.opts, time.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

// evictTx removes oldest rows past the byte budget and any rows
// older than the age cutoff. Runs inside the caller's transaction.
func evictTx(ctx context.Context, tx *sql.Tx, opts Options, now time.Time) error {
	ageCutoff := now.Add(-opts.MaxAge).UnixMilli()
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, ageCutoff); err != nil {
		return fmt.Errorf("traffic/sqlite: evict by age: %w", err)
	}
	// Byte budget: sum size_bytes; if over the cap, delete oldest
	// until under. SQLite has no CTE-update, so loop with `LIMIT N`
	// deletes — N grows so we converge fast on large overshoots.
	for n := 32; ; n *= 2 {
		var total int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size_bytes), 0) FROM events`).Scan(&total); err != nil {
			return fmt.Errorf("traffic/sqlite: sum size: %w", err)
		}
		if total <= opts.MaxBytes {
			return nil
		}
		res, err := tx.ExecContext(ctx, `
			DELETE FROM events
			WHERE id IN (
				SELECT id FROM events ORDER BY ts ASC, id ASC LIMIT ?
			)
		`, n)
		if err != nil {
			return fmt.Errorf("traffic/sqlite: evict by bytes: %w", err)
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			// Nothing more to evict — all rows are kept. Caller
			// has to accept that the budget may be exceeded.
			return nil
		}
	}
}

// Get reads the full event back. Returns ErrNotFound for an unknown id.
func (s *sqliteStore) Get(ctx context.Context, id EventID) (Event, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM events WHERE id = ?`, id).Scan(&payload)
	if err == sql.ErrNoRows {
		return Event{}, ErrNotFound
	}
	if err != nil {
		return Event{}, fmt.Errorf("traffic/sqlite: get %q: %w", id, err)
	}
	var ev Event
	if err := json.Unmarshal(payload, &ev); err != nil {
		return Event{}, fmt.Errorf("traffic/sqlite: decode %q: %w", id, err)
	}
	return ev, nil
}

// List runs the filtered, paginated query. Returns the page (newest
// first) and a forward cursor when more rows match than fit.
func (s *sqliteStore) List(ctx context.Context, opts ListOpts) ([]Summary, Cursor, error) {
	curTS, curID, err := DecodeCursor(opts.Cursor)
	if err != nil {
		return nil, "", err
	}
	limit := ClampLimit(opts.Limit)

	// Build the WHERE clause out of structured filters. ?-bind every
	// scalar so a path_prefix containing '%' or '_' cannot be
	// interpreted as a LIKE wildcard against an unrelated column.
	var where []string
	var args []any
	if len(opts.APIs) > 0 {
		// `api IN (?,?,…)` over the deduplicated set. Order doesn't
		// matter (the outer query orders by ts desc).
		placeholders := make([]string, len(opts.APIs))
		for i, a := range opts.APIs {
			placeholders[i] = "?"
			args = append(args, a)
		}
		where = append(where, "api IN ("+strings.Join(placeholders, ",")+")")
	} else if opts.API != "" {
		where = append(where, "api = ?")
		args = append(args, opts.API)
	}
	if opts.Action != "" {
		where = append(where, "action = ?")
		args = append(args, opts.Action)
	}
	if opts.Method != "" {
		where = append(where, "method = ?")
		args = append(args, opts.Method)
	}
	if opts.Decision != "" {
		where = append(where, "decision = ?")
		args = append(args, opts.Decision)
	}
	if opts.PathPrefix != "" {
		where = append(where, "url LIKE ? ESCAPE '\\'")
		args = append(args, escapeLike(opts.PathPrefix)+"%")
	}
	if !opts.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, opts.Since.UnixMilli())
	}
	if !opts.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, opts.Until.UnixMilli())
	}
	if opts.Subject != nil {
		where = append(where, "subject = ?")
		args = append(args, *opts.Subject)
	}
	if curID != "" {
		// Strict (ts, id) keyset pagination: the cursor row was the
		// last row of the previous page; resume strictly after it.
		where = append(where, "(ts < ? OR (ts = ? AND id < ?))")
		args = append(args, curTS.UnixMilli(), curTS.UnixMilli(), curID)
	}
	q := `SELECT id, ts, subject, method, url, api, action, decision, policy, upstream_status, latency_ms FROM events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	// Pull one extra row so we can decide whether to emit a cursor.
	q += " ORDER BY ts DESC, id DESC LIMIT ?"
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("traffic/sqlite: list: %w", err)
	}
	defer rows.Close()

	out := make([]Summary, 0, limit)
	for rows.Next() {
		var sum Summary
		var tsMS int64
		if err := rows.Scan(&sum.ID, &tsMS, &sum.Subject, &sum.Method, &sum.URL, &sum.API, &sum.Action, &sum.Decision, &sum.Policy, &sum.UpstreamStatus, &sum.LatencyMS); err != nil {
			return nil, "", fmt.Errorf("traffic/sqlite: list scan: %w", err)
		}
		sum.Timestamp = time.UnixMilli(tsMS).UTC()
		out = append(out, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("traffic/sqlite: list rows: %w", err)
	}
	var next Cursor
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = EncodeCursor(last.Timestamp, last.ID)
	}
	return out, next, nil
}

// escapeLike escapes the SQL LIKE metacharacters (% and _) plus the
// escape character itself, so a literal path prefix matches as a
// literal even when it contains those characters.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
