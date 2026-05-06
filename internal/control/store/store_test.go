package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSQLiteMigrateAppliesPerNamespace pins that one SQLBackend can
// host two domains' migrations independently — the multi-table
// "single sqlite for everything" deployment shape.
func TestSQLiteMigrateAppliesPerNamespace(t *testing.T) {
	b, err := OpenSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	require.NoError(t, b.Migrate("a", []string{
		`CREATE TABLE a_t (id INTEGER PRIMARY KEY)`,
	}))
	require.NoError(t, b.Migrate("b", []string{
		`CREATE TABLE b_t (id INTEGER PRIMARY KEY)`,
	}))
	// Re-running the same migration list is a no-op — no error,
	// and the table CREATEs would have failed without IF NOT
	// EXISTS guards if the version tracker weren't honoured.
	require.NoError(t, b.Migrate("a", []string{
		`CREATE TABLE a_t (id INTEGER PRIMARY KEY)`,
	}))

	// Both tables should be queryable.
	_, err = b.DB().Exec(`INSERT INTO a_t (id) VALUES (1)`)
	require.NoError(t, err)
	_, err = b.DB().Exec(`INSERT INTO b_t (id) VALUES (1)`)
	require.NoError(t, err)
}

// TestSQLiteMigrateRejectsDowngrade pins that shrinking a
// migration list (from version 2 back to 1) is a hard error rather
// than a silent drop of the unknown migration on disk.
func TestSQLiteMigrateRejectsDowngrade(t *testing.T) {
	b, err := OpenSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	require.NoError(t, b.Migrate("a", []string{
		`CREATE TABLE a_t (id INTEGER PRIMARY KEY)`,
		`ALTER TABLE a_t ADD COLUMN x INTEGER NOT NULL DEFAULT 0`,
	}))
	err = b.Migrate("a", []string{`CREATE TABLE a_t (id INTEGER PRIMARY KEY)`})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to downgrade")
}

// TestSQLiteMigrateRollsBackOnFailure pins B6: a migration script
// whose second statement fails must leave the version row at the
// pre-migration value. Without the per-migration transaction the
// CREATE would commit, the version stay 0, and the next boot
// would re-run the migration and trip on the now-existing table.
func TestSQLiteMigrateRollsBackOnFailure(t *testing.T) {
	b, err := OpenSQLite(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	// First migration succeeds.
	require.NoError(t, b.Migrate("svc", []string{
		`CREATE TABLE t (id INTEGER PRIMARY KEY)`,
	}))

	// Second migration's second statement is bogus. The CREATE must
	// roll back so the next attempt does not trip on "table u
	// already exists".
	bad := []string{
		`CREATE TABLE t (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE u (id INTEGER PRIMARY KEY); INSERT INTO u (id) SELECT id FROM nope`,
	}
	require.Error(t, b.Migrate("svc", bad))

	// Re-running with a corrected step 2 succeeds — proves the
	// failed migration left no orphan table behind.
	good := []string{
		`CREATE TABLE t (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE u (id INTEGER PRIMARY KEY)`,
	}
	require.NoError(t, b.Migrate("svc", good))

	_, err = b.DB().Exec(`INSERT INTO u (id) VALUES (1)`)
	require.NoError(t, err)
}

// TestSQLiteCloseIdempotent: handing a Backend to multiple domains
// means Close may be called more than once over the lifetime of the
// process. Pinning idempotency here keeps the boot path simple.
func TestSQLiteCloseIdempotent(t *testing.T) {
	b, err := OpenSQLite(":memory:")
	require.NoError(t, err)
	require.NoError(t, b.Close())
	require.NoError(t, b.Close())
}

// TestFSSubdirCreatesAndStable: each namespace resolves to a stable
// path under the root. Repeated calls are no-ops.
func TestFSSubdirCreatesAndStable(t *testing.T) {
	root := t.TempDir()
	b, err := OpenFS(root)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	a1, err := b.Subdir("traffic")
	require.NoError(t, err)
	a2, err := b.Subdir("traffic")
	require.NoError(t, err)
	assert.Equal(t, a1, a2)
	assert.Equal(t, filepath.Join(root, "traffic"), a1)

	// A different namespace is a sibling, not nested.
	other, err := b.Subdir("policies")
	require.NoError(t, err)
	assert.NotEqual(t, a1, other)
}

// TestFSRejectsTraversal: a namespace like "../escape" must be
// rejected so a typo'd flag value can't write outside the root.
func TestFSRejectsTraversal(t *testing.T) {
	b, err := OpenFS(t.TempDir())
	require.NoError(t, err)
	for _, bad := range []string{"", "../escape", "/abs/path", "a/../b"} {
		_, err := b.Subdir(bad)
		assert.Error(t, err, "namespace %q must be rejected", bad)
	}
}
