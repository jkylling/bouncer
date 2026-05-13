package agents

import (
	"errors"
	"testing"
)

func TestRegisterAndList(t *testing.T) {
	s := NewStore(t.TempDir())
	rec, err := s.Register("claude-code", "sha256:abc")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Local-bouncer model: registration lands directly as approved.
	// The approve/reject ceremony only existed to gate anonymous
	// posters in a hosted scenario the proxy doesn't currently run.
	if rec.Status != StatusApproved {
		t.Fatalf("new agent status = %s, want approved", rec.Status)
	}
	if rec.DecidedAt.IsZero() {
		t.Fatalf("decided_at should be set on auto-approve")
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].ID != rec.ID {
		t.Fatalf("list = %+v, want %s", got, rec.ID)
	}
}

func TestRegisterRejectsUnknownHarness(t *testing.T) {
	s := NewStore(t.TempDir())
	_, err := s.Register("nope", "sha256:abc")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

// TestApproveOnAutoApprovedIsNoOp documents the new semantics: the
// approve/reject endpoints stay reachable so existing CLI / HTTP
// callers don't break, but a freshly-registered agent is already
// approved and a second approve call is a no-op-flavoured
// ErrNotPending.
func TestApproveOnAutoApprovedIsNoOp(t *testing.T) {
	s := NewStore(t.TempDir())
	rec, _ := s.Register("claude-code", "sha256:abc")
	if _, err := s.Approve(rec.ID); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approve already-approved: %v, want ErrNotPending", err)
	}
}

func TestRejectOnAutoApprovedIsNoOp(t *testing.T) {
	s := NewStore(t.TempDir())
	rec, _ := s.Register("cursor", "sha256:xyz")
	if _, err := s.Reject(rec.ID); !errors.Is(err, ErrNotPending) {
		t.Fatalf("reject already-approved: %v, want ErrNotPending", err)
	}
}

func TestGetRejectsTraversal(t *testing.T) {
	s := NewStore(t.TempDir())
	_, err := s.Get("../../../etc/passwd")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}
