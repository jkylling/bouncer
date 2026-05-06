package proposals_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jkylling/bouncer/internal/control/proposals"
	"github.com/jkylling/bouncer/internal/control/store"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// openSQLiteStore opens a fresh sqlite-backed proposals.Store at a
// per-test path.
func openSQLiteStore(t *testing.T) proposals.Store {
	t.Helper()
	b, err := store.OpenSQLite(filepath.Join(t.TempDir(), "proposals.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	s, err := proposals.Open(b)
	require.NoError(t, err)
	return s
}

func sampleProposal(id proposals.ProposalID, status proposals.Status, api string) proposals.Proposal {
	return proposals.Proposal{
		ID:     id,
		Status: status,
		Policy: models.Policy{API: api, Name: "p"},
	}
}

func TestSQLitePutThenGet(t *testing.T) {
	s := openSQLiteStore(t)
	id := proposals.ProposalID("prop_1")
	p := sampleProposal(id, proposals.StatusProposed, "svc")
	require.NoError(t, s.Put(context.Background(), p))
	got, err := s.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, p, got)
}

func TestSQLiteListFiltersByStatusAndAPI(t *testing.T) {
	s := openSQLiteStore(t)
	for _, p := range []proposals.Proposal{
		sampleProposal("prop_a", proposals.StatusProposed, "alpha"),
		sampleProposal("prop_b", proposals.StatusApproved, "alpha"),
		sampleProposal("prop_c", proposals.StatusProposed, "beta"),
	} {
		require.NoError(t, s.Put(context.Background(), p))
	}

	got, err := s.List(context.Background(), proposals.ListOpts{Status: proposals.StatusProposed})
	require.NoError(t, err)
	assert.Len(t, got, 2)

	got, err = s.List(context.Background(), proposals.ListOpts{API: "alpha"})
	require.NoError(t, err)
	assert.Len(t, got, 2)

	got, err = s.List(context.Background(), proposals.ListOpts{Status: proposals.StatusProposed, API: "beta"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, proposals.ProposalID("prop_c"), got[0].ID)
}

func TestSQLiteDeleteReportsNotFound(t *testing.T) {
	s := openSQLiteStore(t)
	err := s.Delete(context.Background(), "missing")
	assert.True(t, errors.Is(err, proposals.ErrNotFound), "want ErrNotFound, got %v", err)
}

func TestSQLiteSchemaSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proposals.db")
	b1, err := store.OpenSQLite(path)
	require.NoError(t, err)
	s1, err := proposals.Open(b1)
	require.NoError(t, err)
	require.NoError(t, s1.Put(context.Background(), sampleProposal("prop_x", proposals.StatusProposed, "svc")))
	require.NoError(t, b1.Close())

	b2, err := store.OpenSQLite(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b2.Close() })
	s2, err := proposals.Open(b2)
	require.NoError(t, err)
	got, err := s2.List(context.Background(), proposals.ListOpts{})
	require.NoError(t, err)
	assert.Len(t, got, 1)
}
