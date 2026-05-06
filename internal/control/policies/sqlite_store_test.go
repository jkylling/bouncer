package policies_test

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/store"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// openSQLiteStore opens a fresh sqlite-backed policies.Store at a
// per-test path. The backend Close runs through t.Cleanup so a
// failure mid-test doesn't leak fds.
func openSQLiteStore(t *testing.T) policies.Store {
	t.Helper()
	b, err := store.OpenSQLite(filepath.Join(t.TempDir(), "policies.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	s, err := policies.Open(b)
	require.NoError(t, err)
	return s
}

func TestSQLitePutThenList(t *testing.T) {
	s := openSQLiteStore(t)
	want := []models.Policy{
		{API: "svc", Name: "p1", Action: "true", Condition: "true", Result: models.Permit},
		{API: "svc", Name: "p2", Action: "true", Condition: "false", Result: models.Deny},
	}
	for _, p := range want {
		require.NoError(t, s.Put(context.Background(), p))
	}
	got, err := s.List(context.Background())
	require.NoError(t, err)
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	assert.Equal(t, want, got)
}

func TestSQLitePutOverwrites(t *testing.T) {
	s := openSQLiteStore(t)
	require.NoError(t, s.Put(context.Background(), models.Policy{
		API: "svc", Name: "p", Action: "true", Condition: "true", Result: models.Permit,
	}))
	require.NoError(t, s.Put(context.Background(), models.Policy{
		API: "svc", Name: "p", Action: "true", Condition: "false", Result: models.Deny,
	}))
	got, err := s.List(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, models.Deny, got[0].Result)
}

func TestSQLiteDeleteIsIdempotent(t *testing.T) {
	s := openSQLiteStore(t)
	// Delete on an unknown row returns ErrNotFound so a
	// bypass-Service caller (reconciliation, bulk import) gets a
	// clean already-deleted signal rather than a silent no-op.
	err := s.Delete(context.Background(), "svc", "missing")
	require.True(t, errors.Is(err, policies.ErrNotFound), "want ErrNotFound, got %v", err)

	require.NoError(t, s.Put(context.Background(), models.Policy{
		API: "svc", Name: "p", Action: "true", Condition: "true", Result: models.Permit,
	}))
	require.NoError(t, s.Delete(context.Background(), "svc", "p"))
	got, err := s.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestSQLiteSchemaSurvivesReopen pins the migration ladder against a
// reopen of the same file — opening twice must not double-apply or
// drop existing rows.
func TestSQLiteSchemaSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.db")

	b1, err := store.OpenSQLite(path)
	require.NoError(t, err)
	s1, err := policies.Open(b1)
	require.NoError(t, err)
	require.NoError(t, s1.Put(context.Background(), models.Policy{
		API: "svc", Name: "p", Action: "true", Condition: "true", Result: models.Permit,
	}))
	require.NoError(t, b1.Close())

	b2, err := store.OpenSQLite(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b2.Close() })
	s2, err := policies.Open(b2)
	require.NoError(t, err)
	got, err := s2.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, got, 1)
}
