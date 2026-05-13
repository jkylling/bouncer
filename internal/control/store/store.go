// Package store is the shared backend layer the bouncer
// control-plane stores (traffic, policies, proposals) build on top
// of. Each domain still owns its own data shape, schema, and queries
// — what's shared here is *where the bits live*: a SQLite database
// handle or a filesystem root.
//
// A deployment can wire one Backend across every domain (a single
// sqlite file with multiple tables, a single root directory with
// per-domain subdirs) or hand each domain its own — `traffic.Open`
// and `policies.Open` accept any compatible Backend independently,
// so split deployments are first-class. In-memory operation is not a
// Backend; each domain exposes a `NewMemoryStore` constructor whose
// state is private to the returned store.
//
// Backends do not own the lifecycle of the resources they expose.
// The application (typically `cmd/bouncer`) opens a Backend,
// passes it to each domain's `Open`, and `Close`s the Backend when
// the rest of the process is shutting down. Domain stores never
// close the Backend — they only release their own resources.
package store

import (
	"database/sql"
	"errors"
)

// Backend is the marker interface every concrete backend implements.
// It exists so the boot path can keep a homogeneous slice of
// backends to close at shutdown without caring which kind they are.
//
// Domain stores accept the more specific interfaces below
// (SQLBackend, FSBackend) and type-assert at Open time — an
// unsupported pairing (e.g. traffic on FSBackend) becomes a clear
// error at boot rather than a silent degradation later.
type Backend interface {
	// Close releases the backend's underlying resources (DB handle,
	// open file descriptors, etc). Idempotent: subsequent calls
	// after the first are no-ops. Domain stores do not call this;
	// the boot path does.
	Close() error
}

// SQLBackend exposes a *sql.DB plus a small migration helper. The
// concrete implementation (OpenSQLite) returns a *DB shared across
// every domain that gets handed the same SQLBackend, so a single
// sqlite file naturally becomes "the" control-plane database with
// per-domain tables.
type SQLBackend interface {
	Backend

	// DB returns the live *sql.DB. The pool is configured for
	// single-writer use (MaxOpenConns=1) — sqlite's WAL mode handles
	// concurrent readers fine but parallel writers race the
	// migration ladder. Domain stores serialise their own writes
	// behind a sync.Mutex on top of this.
	DB() *sql.DB

	// Migrate applies the slice of CREATE/ALTER statements bound to
	// `namespace` exactly once across the lifetime of this database.
	// The namespace string is opaque to the backend — pick something
	// stable per-domain (e.g. "traffic", "policies"). Re-running
	// Migrate with a longer slice applies just the new entries; a
	// short slice after a longer one (i.e. a downgrade) is rejected
	// rather than silently dropping the unknown migrations.
	Migrate(namespace string, migrations []string) error
}

// FSBackend exposes per-domain subdirectories under a single root.
// Each domain gets a stable, predictable path inside the root so an
// operator can ls/cp/grep across domains without learning a separate
// layout per domain.
type FSBackend interface {
	Backend

	// Subdir returns the absolute path of the directory bound to
	// `namespace`, creating it if missing. Stable across calls — the
	// same namespace always resolves to the same path inside the
	// root.
	Subdir(namespace string) (string, error)
}

// ErrUnsupportedBackend is returned by a domain's Open when the
// supplied Backend is not one of the kinds that domain knows how to
// drive (e.g. traffic given an FSBackend). Domain code wraps with
// fmt.Errorf("...: %w (got %T)", store.ErrUnsupportedBackend, b)
// so errors.Is callers can still classify the failure.
var ErrUnsupportedBackend = errors.New("store: unsupported backend type for this domain")
