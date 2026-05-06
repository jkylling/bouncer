package proposals

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStore is a simple in-memory Store. The default for tests and
// ephemeral deployments — proposals do not survive a process
// restart. The on-disk backend lives in sqlite_store.go and slots in
// via the same Store interface.
type MemoryStore struct {
	mu        sync.Mutex
	proposals map[ProposalID]Proposal
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{proposals: map[ProposalID]Proposal{}}
}

// cloneProposal deep-copies pointer-typed fields on Proposal so
// callers of Get/List/Put cannot mutate store state through the
// shared *time.Time. Without this, an Approve/Reject path that
// rewrites *DecidedAt would leak across the store boundary.
func cloneProposal(p Proposal) Proposal {
	if p.DecidedAt != nil {
		t := *p.DecidedAt
		p.DecidedAt = &t
	}
	return p
}

func (m *MemoryStore) Get(_ context.Context, id ProposalID) (Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.proposals[id]
	if !ok {
		return Proposal{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return cloneProposal(p), nil
}

func (m *MemoryStore) Put(_ context.Context, p Proposal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proposals[p.ID] = cloneProposal(p)
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, id ProposalID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.proposals[id]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	delete(m.proposals, id)
	return nil
}

func (m *MemoryStore) List(_ context.Context, opts ListOpts) ([]Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Proposal, 0, len(m.proposals))
	for _, p := range m.proposals {
		if opts.Status != "" && p.Status != opts.Status {
			continue
		}
		if opts.API != "" && p.Policy.API != opts.API {
			continue
		}
		out = append(out, cloneProposal(p))
	}
	return out, nil
}
