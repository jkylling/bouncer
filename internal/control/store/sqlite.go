package store

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// sqliteBackend is the concrete SQLBackend that opens a single
// modernc.org/sqlite database and hands the *sql.DB out to every
// domain. The pure-Go driver keeps cgo out of the build and matches
// the rest of the repo's portability story.
type sqliteBackend struct {
	db *sql.DB

	// closeOnce guards the underlying *sql.DB.Close so a Backend
	// passed to multiple domains is safe to Close exactly once at
	// shutdown.
	closeOnce sync.Once
	closeErr  error

	// migrateMu serialises Migrate calls. Migrations rarely race in
	// practice (boot is sequential) but the migrations table itself
	// is shared across namespaces so concurrent CREATE statements on
	// it can deadlock.
	migrateMu sync.Mutex
}

// OpenSQLite returns a SQLBackend bound to the file at dsn. The file
// is created if it does not exist; an existing file is reopened.
// Pass `:memory:` for an in-process database — useful in tests.
//
// WAL plus normal sync gives durable-enough writes for the control
// plane without the fsync tax of FULL. Pragmas are merged into the
// DSN so they apply to every connection in the pool.
func OpenSQLite(dsn string) (SQLBackend, error) {
	full := dsn
	if !strings.Contains(dsn, "_pragma=") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		full = dsn + sep + "_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", full)
	if err != nil {
		return nil, fmt.Errorf("store/sqlite: open %q: %w", dsn, err)
	}
	// MaxOpenConns=1 caps writer concurrency at one. Matches the
	// previous traffic-store behaviour and avoids `database is
	// locked` races on shared `:memory:` instances.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store/sqlite: ping %q: %w", dsn, err)
	}
	b := &sqliteBackend{db: db}
	if err := b.ensureMigrationsTable(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return b, nil
}

// DB satisfies SQLBackend.
func (b *sqliteBackend) DB() *sql.DB { return b.db }

// Close satisfies Backend.
func (b *sqliteBackend) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.db.Close() })
	return b.closeErr
}

// ensureMigrationsTable creates the per-namespace version tracker.
// `PRAGMA user_version` is a single global int and won't fit
// multiple domains in one file, so we keep our own table.
func (b *sqliteBackend) ensureMigrationsTable() error {
	_, err := b.db.Exec(`CREATE TABLE IF NOT EXISTS _store_migrations (
		namespace TEXT PRIMARY KEY,
		version   INTEGER NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("store/sqlite: create migrations table: %w", err)
	}
	return nil
}

// Migrate applies any unapplied migrations for namespace. Each entry
// in migrations is a SQL script (one or more statements separated by
// `;`) executed atomically — the script and the version bump live in
// one transaction, so a partial failure rolls back both and Migrate
// is safe to retry without leaving "table already exists" wreckage.
// Re-running Migrate with the same slice is a no-op; extending the
// slice appends. Shrinking the slice (i.e. downgrade) returns an
// error rather than silently dropping unknown migrations.
func (b *sqliteBackend) Migrate(namespace string, migrations []string) error {
	b.migrateMu.Lock()
	defer b.migrateMu.Unlock()

	current, err := b.readVersion(namespace)
	if err != nil {
		return err
	}
	if current > len(migrations) {
		return fmt.Errorf("store/sqlite: namespace %q is at version %d, refusing to downgrade to %d",
			namespace, current, len(migrations))
	}
	for v := current; v < len(migrations); v++ {
		if err := b.applyMigration(namespace, v, migrations[v]); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration runs one migration script and bumps the namespace
// version inside a single transaction. Wrapping both steps means a
// failed migration leaves the database exactly as it was — including
// the pre-migration version row, so the next boot retries the same
// step rather than skipping it.
func (b *sqliteBackend) applyMigration(namespace string, idx int, script string) error {
	tx, err := b.db.Begin()
	if err != nil {
		return fmt.Errorf("store/sqlite: begin migration tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(script); err != nil {
		return fmt.Errorf("store/sqlite: namespace %q migration %d: %w", namespace, idx+1, err)
	}
	if _, err := tx.Exec(`INSERT INTO _store_migrations (namespace, version)
		VALUES (?, ?) ON CONFLICT(namespace) DO UPDATE SET version = excluded.version`, namespace, idx+1); err != nil {
		return fmt.Errorf("store/sqlite: bump version for %q: %w", namespace, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store/sqlite: commit migration %d for %q: %w", idx+1, namespace, err)
	}
	return nil
}

func (b *sqliteBackend) readVersion(namespace string) (int, error) {
	var v int
	err := b.db.QueryRow(`SELECT version FROM _store_migrations WHERE namespace = ?`, namespace).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store/sqlite: read version for %q: %w", namespace, err)
	}
	return v, nil
}
