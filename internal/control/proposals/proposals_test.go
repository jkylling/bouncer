package proposals

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// realService boots a `policies.Service` against an in-memory store
// and a one-API runtime. The proposals tests prefer a real validator
// over a fake because the most interesting bugs are between the
// proposal flow and the runtime's compile path — exercising the real
// thing keeps that contract honest.
func realService(t *testing.T) *policies.Service {
	t.Helper()
	b := runtime.NewBuilder()
	if err := b.AddAPI(&models.API{
		Name:         "svc",
		BaseURL:      "https://svc.invalid",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{{
			Name:   "any",
			Filter: "true",
		}},
	}); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return policies.New(rt, policies.NewMemoryStore())
}

func newService(t *testing.T) *Service {
	t.Helper()
	svc := New(NewMemoryStore(), realService(t))
	svc.SetClock(func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) })
	idCount := 0
	svc.SetIDGen(func() ProposalID {
		idCount++
		return ProposalID(fmt.Sprintf("prop_%03d", idCount))
	})
	return svc
}

func goodPolicy() models.Policy {
	return models.Policy{
		API:       "svc",
		Name:      "p1",
		Action:    "true",
		Condition: "true",
		Result:    models.Permit,
	}
}

// TestProposalsCreateRejectsUnknownOriginKind pins R20 S10: an
// origin.kind outside the documented enum is rejected with
// ErrInvalid rather than silently persisted.
func TestProposalsCreateRejectsUnknownOriginKind(t *testing.T) {
	svc := newService(t)
	in := CreateInput{
		Policy: goodPolicy(),
		Origin: Origin{Kind: "vandal"},
		Author: "a",
	}
	_, err := svc.Create(context.Background(), in)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid for unknown origin kind", err)
	}
}

func TestProposalsCreateValidates(t *testing.T) {
	svc := newService(t)
	bad := goodPolicy()
	bad.Condition = "no_such_var"
	in := CreateInput{Policy: bad, Author: "agent-1", Origin: Origin{Kind: OriginAgent, Agent: "test"}}
	_, err := svc.Create(context.Background(), in)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestProposalsCreateThenGet(t *testing.T) {
	svc := newService(t)
	in := CreateInput{Policy: goodPolicy(), Author: "agent-1", Origin: Origin{Kind: OriginAgent, Agent: "test"}, Rationale: "first try"}
	got, err := svc.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ID == "" || got.Status != StatusProposed {
		t.Errorf("got %+v, want id and proposed status", got)
	}
	round, err := svc.Get(context.Background(), got.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if round.Rationale != "first try" || round.Author != "agent-1" {
		t.Errorf("got %+v, want preserved fields", round)
	}
}

func TestProposalsUpdateRevalidates(t *testing.T) {
	svc := newService(t)
	in := CreateInput{Policy: goodPolicy(), Author: "agent-1", Origin: Origin{Kind: OriginAgent, Agent: "test"}}
	created, err := svc.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	bad := goodPolicy()
	bad.Condition = "no_such_var"
	_, err = svc.Update(context.Background(), created.ID, UpdateInput{Policy: &bad})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
	// And the original record must be untouched (no half-applied edit).
	round, _ := svc.Get(context.Background(), created.ID)
	if round.Policy.Condition != "true" {
		t.Errorf("policy mutated despite failed update: %q", round.Policy.Condition)
	}
}

func TestProposalsUpdateAcceptsValidEdit(t *testing.T) {
	svc := newService(t)
	created, err := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "a"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	updated := goodPolicy()
	updated.Condition = "1 == 1"
	rationale := "tightened equality"
	got, err := svc.Update(context.Background(), created.ID, UpdateInput{Policy: &updated, Rationale: &rationale})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Policy.Condition != "1 == 1" || got.Rationale != "tightened equality" {
		t.Errorf("got %+v, want updated fields", got)
	}
	if !got.UpdatedAt.After(created.UpdatedAt) && !got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("updated_at should not move backwards: created=%v updated=%v", created.UpdatedAt, got.UpdatedAt)
	}
}

func TestProposalsUpdateRejectedAfterDecision(t *testing.T) {
	svc := newService(t)
	created, _ := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "a"})
	if _, err := svc.Reject(context.Background(), created.ID, "reviewer", "no thanks"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	rationale := "second thought"
	_, err := svc.Update(context.Background(), created.ID, UpdateInput{Rationale: &rationale})
	if !errors.Is(err, ErrBadTransition) {
		t.Errorf("err = %v, want ErrBadTransition", err)
	}
}

func TestProposalsApprovePromotesPolicy(t *testing.T) {
	policySvc := realService(t)
	store := NewMemoryStore()
	svc := New(store, policySvc)
	created, err := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "agent-1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.Approve(context.Background(), created.ID, "reviewer-1", false)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got.Status != StatusApproved {
		t.Errorf("status = %q, want approved", got.Status)
	}
	if got.DecidedBy != "reviewer-1" {
		t.Errorf("decided_by = %q, want reviewer-1", got.DecidedBy)
	}
	// Live policy was promoted into the runtime via the policy service.
	if _, err := policySvc.Get("svc", "p1"); err != nil {
		t.Errorf("live policy missing after approve: %v", err)
	}
}

// TestProposalsApprovePreservesPolicyDescription pins the contract
// that an optional Description on the policy survives the proposal
// → approve → live-policy round-trip. A reviewer who reads the
// approved set later should see the same note the agent attached
// when proposing.
func TestProposalsApprovePreservesPolicyDescription(t *testing.T) {
	policySvc := realService(t)
	svc := New(NewMemoryStore(), policySvc)

	withDesc := goodPolicy()
	withDesc.Description = "Substituted from suggested_policies/agent_messages.\nOwner: oncall."

	created, err := svc.Create(context.Background(), CreateInput{Policy: withDesc, Author: "agent-1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Policy.Description != withDesc.Description {
		t.Errorf("proposal description = %q, want %q", created.Policy.Description, withDesc.Description)
	}
	if _, err := svc.Approve(context.Background(), created.ID, "reviewer-1", false); err != nil {
		t.Fatalf("approve: %v", err)
	}
	live, err := policySvc.Get("svc", "p1")
	if err != nil {
		t.Fatalf("get live: %v", err)
	}
	if live.Description != withDesc.Description {
		t.Errorf("live policy description = %q, want %q", live.Description, withDesc.Description)
	}
}

// TestProposalsCreateDeleteSkipsCELValidation pins that a proposal
// with Kind=delete only requires api+name. The other policy fields
// (action, condition, result) aren't compiled — a delete proposal
// has no policy body to validate against the live runtime.
func TestProposalsCreateDeleteSkipsCELValidation(t *testing.T) {
	policySvc := realService(t)
	svc := New(NewMemoryStore(), policySvc)

	// Bare api+name; no Action/Condition/Result. Apply-kind would
	// fail Validate (the policy compiler would reject empty fields);
	// delete-kind must accept it.
	in := CreateInput{
		Kind:   KindDelete,
		Policy: models.Policy{API: "svc", Name: "p1"},
		Author: "agent-1",
	}
	got, err := svc.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("create delete: %v", err)
	}
	if got.Kind != KindDelete {
		t.Errorf("kind = %q, want delete", got.Kind)
	}
}

// TestProposalsCreateDeleteRequiresAPIAndName pins the only
// validation a delete-kind proposal carries: api + name must be
// non-empty.
func TestProposalsCreateDeleteRequiresAPIAndName(t *testing.T) {
	policySvc := realService(t)
	svc := New(NewMemoryStore(), policySvc)

	for _, missing := range []string{"api", "name"} {
		in := CreateInput{
			Kind:   KindDelete,
			Policy: models.Policy{API: "svc", Name: "p1"},
			Author: "agent-1",
		}
		switch missing {
		case "api":
			in.Policy.API = ""
		case "name":
			in.Policy.Name = ""
		}
		_, err := svc.Create(context.Background(), in)
		if err == nil {
			t.Errorf("missing %s: expected error, got nil", missing)
			continue
		}
		if !strings.Contains(err.Error(), "api and name are required") {
			t.Errorf("missing %s: err = %v, want one mentioning api+name", missing, err)
		}
	}
}

// TestProposalsApproveDeleteRemovesLivePolicy pins the post-approval
// effect of a delete proposal: the live policy at (api, name) is
// gone. Idempotent on missing — covered by the next test.
func TestProposalsApproveDeleteRemovesLivePolicy(t *testing.T) {
	policySvc := realService(t)
	svc := New(NewMemoryStore(), policySvc)

	// Seed a live policy via an approved Apply proposal so the
	// delete has a target.
	seed := goodPolicy()
	created, err := svc.Create(context.Background(), CreateInput{Policy: seed, Author: "operator"})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	if _, err := svc.Approve(context.Background(), created.ID, "reviewer", false); err != nil {
		t.Fatalf("seed approve: %v", err)
	}
	if _, err := policySvc.Get("svc", "p1"); err != nil {
		t.Fatalf("seed sanity: %v", err)
	}

	// Now propose deletion and approve it.
	delProp, err := svc.Create(context.Background(), CreateInput{
		Kind:   KindDelete,
		Policy: models.Policy{API: "svc", Name: "p1"},
		Author: "operator",
	})
	if err != nil {
		t.Fatalf("create delete: %v", err)
	}
	if _, err := svc.Approve(context.Background(), delProp.ID, "reviewer", false); err != nil {
		t.Fatalf("approve delete: %v", err)
	}
	if _, err := policySvc.Get("svc", "p1"); !errors.Is(err, policies.ErrNotFound) {
		t.Errorf("live policy still present after approve-delete: %v", err)
	}
}

// TestProposalsApproveDeleteIdempotentOnMissing pins idempotency:
// approving a delete proposal whose target is already gone succeeds.
// A reviewer's intent ("the post-condition is: policy absent") is
// satisfied either way.
func TestProposalsApproveDeleteIdempotentOnMissing(t *testing.T) {
	policySvc := realService(t)
	svc := New(NewMemoryStore(), policySvc)

	delProp, err := svc.Create(context.Background(), CreateInput{
		Kind:   KindDelete,
		Policy: models.Policy{API: "svc", Name: "ghost"},
		Author: "operator",
	})
	if err != nil {
		t.Fatalf("create delete: %v", err)
	}
	got, err := svc.Approve(context.Background(), delProp.ID, "reviewer", false)
	if err != nil {
		t.Fatalf("approve delete on missing target: %v", err)
	}
	if got.Status != StatusApproved {
		t.Errorf("status = %q, want approved", got.Status)
	}
}

func TestProposalsApproveRejectsOnExistingPolicyWithoutOverwrite(t *testing.T) {
	policySvc := realService(t)
	// Seed an existing policy with the same (api, name).
	existing := goodPolicy()
	if err := policySvc.Create(context.Background(), &existing); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := New(NewMemoryStore(), policySvc)
	created, _ := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "a"})
	_, err := svc.Approve(context.Background(), created.ID, "reviewer", false)
	if !errors.Is(err, ErrPolicyConflict) {
		t.Errorf("err = %v, want ErrPolicyConflict", err)
	}
	// Overwrite=true wins.
	if _, err := svc.Approve(context.Background(), created.ID, "reviewer", true); err != nil {
		t.Errorf("overwrite approve: %v", err)
	}
}

func TestProposalsApproveOnNonProposedFails(t *testing.T) {
	svc := newService(t)
	created, _ := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "a"})
	if _, err := svc.Approve(context.Background(), created.ID, "r", false); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	_, err := svc.Approve(context.Background(), created.ID, "r", false)
	if !errors.Is(err, ErrBadTransition) {
		t.Errorf("err = %v, want ErrBadTransition", err)
	}
}

// TestProposalsApproveSerialisesConflictCheck pins S3: two
// concurrent approvals of distinct proposals carrying the same
// (api, name) must produce exactly one success and one
// ErrPolicyConflict — the conflict-check + Replace pair has to be
// atomic so the second approver sees the first one's apply.
func TestProposalsApproveSerialisesConflictCheck(t *testing.T) {
	policySvc := realService(t)
	svc := New(NewMemoryStore(), policySvc)
	a, err := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "x"})
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	b, err := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "y"})
	if err != nil {
		t.Fatalf("create b: %v", err)
	}

	var success, conflict atomic.Int32
	var wg sync.WaitGroup
	for _, id := range []ProposalID{a.ID, b.ID} {
		wg.Add(1)
		go func(id ProposalID) {
			defer wg.Done()
			_, err := svc.Approve(context.Background(), id, "r", false)
			switch {
			case err == nil:
				success.Add(1)
			case errors.Is(err, ErrPolicyConflict):
				conflict.Add(1)
			default:
				t.Errorf("unexpected approve err: %v", err)
			}
		}(id)
	}
	wg.Wait()
	if success.Load() != 1 || conflict.Load() != 1 {
		t.Errorf("success=%d conflict=%d, want 1/1", success.Load(), conflict.Load())
	}
}

// TestProposalsApproveIdempotentAfterPutFailure pins R19 S3 /
// R20 B7: if store.Put fails after validator.Replace already
// landed the policy, the runtime+policy store hold the live policy
// while the proposal record is still `proposed`. A second Approve
// must complete cleanly — Replace is idempotent, the second Put
// closes the inconsistency window. Without this test the doc that
// describes the recovery path is decorative; a reorder of the
// calls in Approve would silently break it.
func TestProposalsApproveIdempotentAfterPutFailure(t *testing.T) {
	policySvc := realService(t)
	store := &flakyStore{inner: NewMemoryStore()}
	svc := New(store, policySvc)

	created, err := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "x"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Arm the next Put after Create's to fail. Approve will run
	// validator.Replace successfully (live policy lands), then hit
	// the Put failure on its proposal-record write.
	store.failNextPut()
	if _, err := svc.Approve(context.Background(), created.ID, "r1", false); err == nil {
		t.Fatal("expected approve to surface the put failure")
	}
	// Live policy is in the runtime+policy store despite the
	// proposal record still showing proposed.
	if _, err := policySvc.Get("svc", "p1"); err != nil {
		t.Errorf("live policy should be present after failed Approve: %v", err)
	}
	got, err := svc.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusProposed {
		t.Errorf("after failed Put, status = %q, want still proposed", got.Status)
	}

	// Re-running Approve recovers, but the reviewer has to pass
	// overwrite=true: the conflict check now sees the policy that
	// the previous (failed) Approve already applied. Without
	// overwrite the second Approve returns ErrPolicyConflict and
	// the proposal stays stuck.
	if _, err := svc.Approve(context.Background(), created.ID, "r2", false); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("expected ErrPolicyConflict on overwrite=false re-approve, got %v", err)
	}
	if _, err := svc.Approve(context.Background(), created.ID, "r2", true); err != nil {
		t.Fatalf("overwrite re-approve: %v", err)
	}
	got, _ = svc.Get(context.Background(), created.ID)
	if got.Status != StatusApproved {
		t.Errorf("after re-approve, status = %q, want approved", got.Status)
	}
}

// flakyStore wraps another Store and fails the next Put once. Used
// to drive the partial-failure recovery test for Approve.
type flakyStore struct {
	inner Store
	mu    sync.Mutex
	armed bool
}

func (s *flakyStore) failNextPut() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armed = true
}

func (s *flakyStore) Put(ctx context.Context, p Proposal) error {
	s.mu.Lock()
	if s.armed {
		s.armed = false
		s.mu.Unlock()
		return errors.New("flakyStore: armed Put failure")
	}
	s.mu.Unlock()
	return s.inner.Put(ctx, p)
}
func (s *flakyStore) Get(ctx context.Context, id ProposalID) (Proposal, error) {
	return s.inner.Get(ctx, id)
}
func (s *flakyStore) Delete(ctx context.Context, id ProposalID) error {
	return s.inner.Delete(ctx, id)
}
func (s *flakyStore) List(ctx context.Context, opts ListOpts) ([]Proposal, error) {
	return s.inner.List(ctx, opts)
}

func TestProposalsListFilters(t *testing.T) {
	svc := newService(t)
	for _, body := range []CreateInput{
		{Policy: goodPolicy(), Author: "a"},
		{Policy: func() models.Policy { p := goodPolicy(); p.Name = "p2"; return p }(), Author: "a"},
	} {
		if _, err := svc.Create(context.Background(), body); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	all, err := svc.List(context.Background(), ListOpts{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("all = %d, want 2", len(all))
	}

	// Reject one, then filter by status=proposed.
	if _, err := svc.Reject(context.Background(), all[0].ID, "r", "no"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	open, err := svc.List(context.Background(), ListOpts{Status: StatusProposed})
	if err != nil {
		t.Fatalf("list proposed: %v", err)
	}
	if len(open) != 1 {
		t.Errorf("open = %d, want 1", len(open))
	}
}

func TestProposalsDelete(t *testing.T) {
	svc := newService(t)
	created, _ := svc.Create(context.Background(), CreateInput{Policy: goodPolicy(), Author: "a"})
	if err := svc.Delete(context.Background(), created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.Get(context.Background(), created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get-after-delete err = %v, want ErrNotFound", err)
	}
}
