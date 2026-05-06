// Package proposals implements the human-in-the-loop draft workflow
// for policies. An agent (or operator) creates a Proposal carrying a
// candidate models.Policy; a human reviewer can edit, reject, or
// approve it. Approval promotes the policy through the same Service
// the policy CRUD endpoint uses, so a one-line YAML edit and a
// reviewed proposal land in the runtime via the same code path.
//
// Editing is the differentiator vs. a "submit-and-pray" workflow: a
// reviewer can tighten or relax the candidate condition and the
// proposal record bumps `updated_at`, runs the validation pipeline,
// and refuses to accept a syntactically-broken edit. The proposed
// policy never affects request evaluation until approval.
package proposals

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Status enumerates the proposal state machine.
//
//	create → proposed → (edit → still proposed)
//	                  → approved (terminal: policy applied)
//	                  → rejected (terminal: kept for audit)
type Status string

const (
	StatusProposed Status = "proposed"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// OriginKind labels what produced the proposal. Useful for the UI to
// distinguish operator-authored from agent-suggested entries, and for
// metrics ("how many auto-generated proposals get approved without
// edits?"). Strategy 03 enumerates these three kinds; new origins are
// additive — add the constant here and extend OriginKind.Validate.
type OriginKind string

const (
	OriginManual      OriginKind = "manual"
	OriginAgent       OriginKind = "agent"
	OriginFromRequest OriginKind = "from_request"
)

// Validate rejects an unknown OriginKind. Mirrors the
// PolicyResult.Validate pattern: typed string aliases without an
// explicit allow-set silently accept anything that fits the
// underlying string and round-trip it through every API. Service
// surfaces the rejection as ErrInvalid.
func (k OriginKind) Validate() error {
	switch k {
	case "", OriginManual, OriginAgent, OriginFromRequest:
		return nil
	default:
		return fmt.Errorf("unknown origin kind %q", string(k))
	}
}

// Origin records what produced the proposal. Agent and RequestID are
// optional and depend on the kind. The shape mirrors the JSON record
// in strategy/follow-ups/03-proposal-api.md.
type Origin struct {
	Kind      OriginKind      `json:"kind"`
	Agent     string          `json:"agent,omitempty"`
	RequestID traffic.EventID `json:"request_id,omitempty"`
}

// Kind discriminates what the proposal asks the reviewer to do.
//
//   - KindApply (default): create-or-replace the policy in the live
//     runtime, exactly as the proposal specifies. The historical
//     proposal shape — every legacy record decodes with Kind="" and
//     is treated as Apply.
//   - KindDelete: remove the policy at (api, name) from the live
//     runtime. Only the api/name fields of Policy are read; the rest
//     (action, condition, result) are ignored at create time and
//     never reach the runtime.
//
// Adding a kind is additive — new value here, new branch in the
// Create/Approve dispatch, store schema needs no change since the
// field is just a JSON string.
type Kind string

const (
	// KindApply means create-or-replace the policy on approve. Empty
	// JSON value (legacy records) decodes as Apply for back-compat.
	KindApply Kind = "apply"
	// KindDelete means remove the policy at (api, name) on approve.
	KindDelete Kind = "delete"
)

// Validate rejects an unknown Kind. Empty stays valid — the storage
// layer hands back legacy records with Kind="" and Resolve() coerces
// them to KindApply downstream.
func (k Kind) Validate() error {
	switch k {
	case "", KindApply, KindDelete:
		return nil
	default:
		return fmt.Errorf("unknown proposal kind %q", string(k))
	}
}

// Resolve returns the effective Kind, mapping the empty string onto
// the default (KindApply) so dispatch logic only has to handle
// concrete values.
func (k Kind) Resolve() Kind {
	if k == "" {
		return KindApply
	}
	return k
}

// Proposal is the persisted record. ID is set by the Service on
// Create; everything else flows from CreateInput / UpdateInput.
type Proposal struct {
	ID              ProposalID    `json:"id"`
	Kind            Kind          `json:"kind,omitempty"`
	Policy          models.Policy `json:"policy"`
	Status          Status        `json:"status"`
	Origin          Origin        `json:"origin"`
	Author          string        `json:"author"`
	Rationale       string        `json:"rationale,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	DecidedAt       *time.Time    `json:"decided_at,omitempty"`
	DecidedBy       string        `json:"decided_by,omitempty"`
	RejectionReason string        `json:"rejection_reason,omitempty"`
}

// CreateInput is what callers (HTTP handler, tests, future agent SDK)
// hand to Service.Create. Author is the identity that submitted the
// proposal; Origin describes what produced it.
type CreateInput struct {
	Kind      Kind          `json:"kind,omitempty"`
	Policy    models.Policy `json:"policy"`
	Origin    Origin        `json:"origin"`
	Author    string        `json:"author"`
	Rationale string        `json:"rationale,omitempty"`
}

// UpdateInput is the PATCH body. Both fields are optional pointers so
// the caller can update one without touching the other (a rationale
// rephrase doesn't have to repeat the policy block, and a policy
// tightening doesn't have to repeat the rationale). nil means "leave
// it alone".
type UpdateInput struct {
	Policy    *models.Policy `json:"policy,omitempty"`
	Rationale *string        `json:"rationale,omitempty"`
}

// PolicyValidator is the slice of *policies.Service the proposals
// Service depends on. Defined as an interface so tests don't need to
// stand up a real runtime. Production wiring passes the live
// *policies.Service.
type PolicyValidator interface {
	Validate(p *models.Policy) error
	Replace(ctx context.Context, api, name string, p *models.Policy) error
	Delete(ctx context.Context, api, name string) error
	Get(api, name string) (models.Policy, error)
}

// Store persists proposals. Implementations may be in-memory (for
// tests, ephemeral deployments) or on-disk; the interface is small
// and operates on whole proposals so a future SQLite or YAML backend
// has minimal surface to satisfy.
type Store interface {
	List(ctx context.Context, opts ListOpts) ([]Proposal, error)
	Get(ctx context.Context, id ProposalID) (Proposal, error)
	Put(ctx context.Context, p Proposal) error
	Delete(ctx context.Context, id ProposalID) error
}

// ListOpts narrows what List returns. Empty fields mean "no filter".
type ListOpts struct {
	Status Status
	API    string
}

// Sentinel errors. HTTP handlers map these onto status codes.
var (
	ErrNotFound       = errors.New("proposal not found")
	ErrInvalid        = errors.New("invalid proposal")
	ErrBadTransition  = errors.New("proposal not in proposed state")
	ErrPolicyConflict = errors.New("policy with the same (api, name) already exists in active store")
)

// Service coordinates the validate-then-persist flow. It depends on a
// PolicyValidator (for compile checks at create/update time and for
// promoting a policy on approve) and a Store (for persistence). The
// hot proxy path never touches this Service — proposals are inert
// metadata until approve fires.
//
// `mu` serialises every mutating operation so the conflict-check +
// validator.Replace + store.Put chain is atomic with respect to
// other reviewers acting on the same (api, name) or the same id.
// Without it two concurrent Approves of overlapping policies could
// both pass the conflict-check and one silently clobber the other.
// Reads (Get / List) are unguarded: the underlying store handles its
// own locking and a stale read is acceptable for a human-review
// surface.
type Service struct {
	store     Store
	validator PolicyValidator
	nowFn     func() time.Time
	idFn      func() ProposalID

	mu sync.Mutex
}

// New constructs a Service. Both store and v must be non-nil.
func New(store Store, v PolicyValidator) *Service {
	return &Service{
		store:     store,
		validator: v,
		nowFn:     time.Now,
		idFn:      NewProposalID,
	}
}

// SetClock replaces the wall-clock dependency. Tests pin time with
// this so created/updated/decided fields are deterministic.
func (s *Service) SetClock(now func() time.Time) { s.nowFn = now }

// SetIDGen replaces the ID generator. Tests use this to pin IDs.
func (s *Service) SetIDGen(idFn func() ProposalID) { s.idFn = idFn }

// Create validates the candidate policy, issues an ID, and persists
// the proposal in `proposed` state. The author and origin fields are
// preserved verbatim. ErrInvalid wraps any validation failure.
//
// Validation depends on Kind:
//   - apply (default): the full models.Policy must compile against
//     the live runtime.
//   - delete: only api + name are read; the rest of Policy is
//     ignored, and Approve will remove the live policy at that key.
//     CEL fields aren't validated because there's no policy body to
//     compile.
func (s *Service) Create(ctx context.Context, in CreateInput) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kind := in.Kind.Resolve()
	if err := in.Kind.Validate(); err != nil {
		return Proposal{}, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	if err := in.Origin.Kind.Validate(); err != nil {
		return Proposal{}, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	if err := validateForKind(kind, &in.Policy, s.validator); err != nil {
		return Proposal{}, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	now := s.nowFn().UTC()
	p := Proposal{
		ID:        s.idFn(),
		Kind:      kind,
		Policy:    in.Policy,
		Status:    StatusProposed,
		Origin:    in.Origin,
		Author:    in.Author,
		Rationale: in.Rationale,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.Put(ctx, p); err != nil {
		return Proposal{}, fmt.Errorf("store: %w", err)
	}
	return p, nil
}

// validateForKind branches on the proposal kind. Apply runs the full
// policy validator; delete only checks api + name are present.
// Centralised so Create and Update share one definition of "valid
// for this kind".
func validateForKind(kind Kind, p *models.Policy, v PolicyValidator) error {
	switch kind {
	case KindDelete:
		if p.API == "" || p.Name == "" {
			return errors.New("api and name are required for kind=delete")
		}
		return nil
	default:
		// KindApply (also covers the legacy empty-string case via
		// Kind.Resolve at the call site).
		return v.Validate(p)
	}
}

// Get fetches a proposal by ID. ErrNotFound if no such ID.
func (s *Service) Get(ctx context.Context, id ProposalID) (Proposal, error) {
	return s.store.Get(ctx, id)
}

// List returns proposals matching opts. Order is store-defined; v1
// tolerates that.
func (s *Service) List(ctx context.Context, opts ListOpts) ([]Proposal, error) {
	return s.store.List(ctx, opts)
}

// Update applies a PATCH. It is the reviewer's edit hook: only
// proposals in `proposed` state may be edited (ErrBadTransition
// otherwise), and the resulting policy must validate (ErrInvalid if
// not). On success `updated_at` bumps to now.
//
// A nil field on UpdateInput leaves the existing value alone. The
// caller can rephrase the rationale without touching the policy
// block, or tighten the policy without re-stating the rationale.
func (s *Service) Update(ctx context.Context, id ProposalID, in UpdateInput) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.store.Get(ctx, id)
	if err != nil {
		return Proposal{}, err
	}
	if cur.Status != StatusProposed {
		return Proposal{}, fmt.Errorf("%w: id=%s status=%s", ErrBadTransition, id, cur.Status)
	}
	if in.Policy != nil {
		if err := validateForKind(cur.Kind.Resolve(), in.Policy, s.validator); err != nil {
			return Proposal{}, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
		}
		cur.Policy = *in.Policy
	}
	if in.Rationale != nil {
		cur.Rationale = *in.Rationale
	}
	cur.UpdatedAt = s.nowFn().UTC()
	if err := s.store.Put(ctx, cur); err != nil {
		return Proposal{}, fmt.Errorf("store: %w", err)
	}
	return cur, nil
}

// Approve promotes the proposal's policy through the policy Service
// (which writes the durable store and applies to the runtime), then
// marks the proposal `approved`. Re-runs validation in case the
// underlying API surface drifted between create and approval.
//
// If a live policy already exists at the same (api, name) and
// overwrite is false, returns ErrPolicyConflict — the reviewer can
// retry with overwrite to accept the displacement, or edit the
// proposal's name first.
//
// Failure ordering: Replace runs before the proposal-record Put,
// so a Put failure leaves the policy live in the runtime + policy
// store while the proposal still shows `proposed`. Recovery: the
// reviewer re-approves with overwrite=true (the conflict check
// otherwise sees the just-applied policy and returns
// ErrPolicyConflict). After the second Approve the proposal flips
// to approved and the inconsistency window closes. The alternative
// (proposal-record-first with a rollback on Replace failure) would
// require a two-phase commit across two stores that may not share
// a transaction; the operator-driven retry trade-off is the right
// shape for the human-review surface this lives on. Operators
// inspecting state during the window see "policy applied, proposal
// still proposed" — recoverable, never inconsistent in the
// dangerous direction (the policy never lands without an approval
// intent).
func (s *Service) Approve(ctx context.Context, id ProposalID, by string, overwrite bool) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.store.Get(ctx, id)
	if err != nil {
		return Proposal{}, err
	}
	if cur.Status != StatusProposed {
		return Proposal{}, fmt.Errorf("%w: id=%s status=%s", ErrBadTransition, id, cur.Status)
	}
	switch cur.Kind.Resolve() {
	case KindDelete:
		// Delete is intentionally idempotent on a missing target — a
		// reviewer approving "remove this policy" wants the
		// post-condition (policy not present), not a strict "the
		// policy was here when you proposed it" guarantee. The other
		// error types still surface.
		if err := s.validator.Delete(ctx, cur.Policy.API, cur.Policy.Name); err != nil &&
			!errors.Is(err, policies.ErrNotFound) {
			return Proposal{}, fmt.Errorf("apply policy delete: %w", err)
		}
	default:
		if !overwrite {
			// Conflict-check must fail safe: only a definite "not
			// found" is permission to proceed. A transient I/O error
			// (or any future error type the validator returns) gets
			// surfaced rather than silently letting the Replace go
			// through and clobber whatever live policy exists.
			_, getErr := s.validator.Get(cur.Policy.API, cur.Policy.Name)
			switch {
			case getErr == nil:
				return Proposal{}, fmt.Errorf("%w: %s/%s",
					ErrPolicyConflict, cur.Policy.API, cur.Policy.Name)
			case errors.Is(getErr, policies.ErrNotFound):
				// No live policy at this (api, name) — safe to proceed.
			default:
				return Proposal{}, fmt.Errorf("conflict check %s/%s: %w",
					cur.Policy.API, cur.Policy.Name, getErr)
			}
		}
		if err := s.validator.Replace(ctx, cur.Policy.API, cur.Policy.Name, &cur.Policy); err != nil {
			return Proposal{}, fmt.Errorf("apply policy: %w", err)
		}
	}
	now := s.nowFn().UTC()
	cur.Status = StatusApproved
	cur.UpdatedAt = now
	cur.DecidedAt = &now
	cur.DecidedBy = by
	if err := s.store.Put(ctx, cur); err != nil {
		return Proposal{}, fmt.Errorf("store: %w", err)
	}
	return cur, nil
}

// Reject closes the proposal as `rejected` with the supplied reason.
// The proposal stays in the store for audit; Delete is the way to
// purge it.
func (s *Service) Reject(ctx context.Context, id ProposalID, by, reason string) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.store.Get(ctx, id)
	if err != nil {
		return Proposal{}, err
	}
	if cur.Status != StatusProposed {
		return Proposal{}, fmt.Errorf("%w: id=%s status=%s", ErrBadTransition, id, cur.Status)
	}
	now := s.nowFn().UTC()
	cur.Status = StatusRejected
	cur.UpdatedAt = now
	cur.DecidedAt = &now
	cur.DecidedBy = by
	cur.RejectionReason = reason
	if err := s.store.Put(ctx, cur); err != nil {
		return Proposal{}, fmt.Errorf("store: %w", err)
	}
	return cur, nil
}

// Delete purges the proposal regardless of state. v1 keeps no
// recycle bin: a delete is a delete.
func (s *Service) Delete(ctx context.Context, id ProposalID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Delete(ctx, id)
}
