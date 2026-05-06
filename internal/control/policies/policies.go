// Package policies fronts the live `*runtime.Runtime` policy set with
// validate-then-persist-then-apply semantics. Every write goes through
// one Service so the control-plane HTTP handlers, the proposal-approval
// path, and (eventually) IaC bulk-import all run the same checks and
// touch the runtime in the same order.
//
// Reads bypass the Service entirely — they go straight to the runtime,
// which holds the source of truth at request time. Writes:
//
//  1. Validate (schema + compile against the live type env).
//  2. Persist via the Store.
//  3. Apply via runtime.ReplacePolicy / RemovePolicy.
//
// If the Store write fails, the runtime is untouched. The third step
// can in principle fail (defensive guard) but only on programmer error
// — the compile already succeeded in step 1.
package policies

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Store persists the policy set to durable storage. Implementations
// hide whether that's a YAML directory, a SQLite table, or just a
// map (test backend). The interface is deliberately tight: List for
// boot, Put + Delete for control-plane writes. Live reads go through
// the runtime, not the store.
//
// Delete returns ErrNotFound when (api, name) is unknown, mirroring
// the proposals.Store contract. Service.Delete still runs `find` up
// front, so the typical 404 path doesn't reach the store; the
// sentinel exists for callers that bypass the Service (a future
// reconciliation loop, a bulk import) and want a clean
// already-deleted signal.
type Store interface {
	List(ctx context.Context) ([]models.Policy, error)
	Put(ctx context.Context, policy models.Policy) error
	Delete(ctx context.Context, api, name string) error
}

// Sentinel errors. Handlers map these onto HTTP statuses; tests assert
// against them with errors.Is.
var (
	ErrInvalid  = errors.New("invalid policy")
	ErrNotFound = errors.New("policy not found")
	ErrConflict = errors.New("policy already exists")
	ErrAPIPath  = errors.New("api/name in path does not match body")
	ErrReadOnly = errors.New("policy store is read-only")
)

// Service is the policy CRUD coordinator. Construct one per process and
// share it between the HTTP handlers and the proposal-approval path so
// every write goes through the same pipeline.
//
// `mu` serialises every mutating operation so the find + persist +
// apply sequence is atomic with respect to other writers. Without it
// two concurrent Creates for the same (api, name) could both pass
// the duplicate check and clobber each other's apply. Reads (List /
// Get) bypass the mutex; they go through the runtime's own RWMutex
// and tolerate stale snapshots.
type Service struct {
	rt    *runtime.Runtime
	store Store

	// readOnly, when true, makes Create/Replace/Delete return
	// ErrReadOnly without touching the store or runtime. Set via
	// SetReadOnly at boot. Reads (List/Get/Validate) are unaffected.
	readOnly bool

	mu sync.Mutex
}

// New constructs a Service. Both rt and store must be non-nil.
func New(rt *runtime.Runtime, store Store) *Service {
	return &Service{rt: rt, store: store}
}

// SetReadOnly toggles the read-only flag. Intended to be called once
// at boot from the cmd layer, before the Service is exposed to
// handlers; concurrent flips during request serving are not supported
// because the rest of the Service has no write barrier on this field.
func (s *Service) SetReadOnly(ro bool) { s.readOnly = ro }

// Writeable reports whether mutations are allowed. The admin
// capabilities endpoint surfaces this so the UI can hide edit
// affordances when the operator boots in read-only mode.
func (s *Service) Writeable() bool { return !s.readOnly }

// LoadFromStore replays every persisted policy through the runtime so
// the in-memory policy set matches disk. Called once at boot from
// `cmd/bouncer/main.go` (or `server.Load`); the existing path that
// walks the policies directory is replaced by a Store + this call.
//
// If any policy fails to compile (e.g. an API rename made an old policy
// invalid) LoadFromStore returns the first failure — the operator
// fixes the file and restarts. Silent skipping would let a bad policy
// hide in the store indefinitely.
func (s *Service) LoadFromStore(ctx context.Context) error {
	all, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	for i := range all {
		if _, err := s.rt.ReplacePolicy(&all[i]); err != nil {
			return fmt.Errorf("load policy %q on api %q: %w", all[i].Name, all[i].API, err)
		}
	}
	return nil
}

// Validate runs the compile pipeline against the live runtime without
// mutating anything. Used directly by `:dryRun` and indirectly by every
// other write path.
func (s *Service) Validate(p *models.Policy) error {
	if err := basicSchema(p); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	if err := s.rt.ValidatePolicy(p); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	return nil
}

// Create inserts a new policy. Returns ErrConflict if (api, name) is
// already taken, ErrInvalid wrapping the compile error otherwise.
// Returns ErrReadOnly if the Service was booted with --policies-readonly.
func (s *Service) Create(ctx context.Context, p *models.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readOnly {
		return ErrReadOnly
	}
	if err := s.Validate(p); err != nil {
		return err
	}
	if _, ok := s.find(p.API, p.Name); ok {
		return fmt.Errorf("%w: %s/%s", ErrConflict, p.API, p.Name)
	}
	return s.persistAndApply(ctx, p)
}

// Replace upserts the policy at (api, name). The api/name in the URL
// path must match the body; if not, ErrAPIPath. Validation and persist
// run before the runtime mutation so a failed compile leaves both disk
// and memory unchanged.
func (s *Service) Replace(ctx context.Context, api, name string, p *models.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readOnly {
		return ErrReadOnly
	}
	if p.API != api || p.Name != name {
		return fmt.Errorf("%w: path=%s/%s body=%s/%s", ErrAPIPath, api, name, p.API, p.Name)
	}
	if err := s.Validate(p); err != nil {
		return err
	}
	return s.persistAndApply(ctx, p)
}

// Delete removes the policy at (api, name). ErrNotFound if it does
// not exist. The store delete runs first; if the runtime remove
// then fails the policy is gone from disk but still firing in
// memory — i.e. an operator-initiated revoke that didn't actually
// stop applying.
//
// In practice this never fires: rt.RemovePolicy only fails when
// the API is unregistered, and `find` above already passed (which
// requires the API to be registered). The defensive guard exists
// because runtime mutators return errors today; if a future
// refactor adds a real failure mode here, the right fix is either
// to invert the order (runtime remove first; on failure the store
// stays authoritative and the next boot re-removes) or to wrap
// both in an explicit two-phase commit. Don't trust the next-boot
// reconciliation argument that Create/Replace use — for Delete,
// boot deletes in the same direction the operator already
// requested, so the in-memory phantom-policy window is unbounded
// until the next boot.
func (s *Service) Delete(ctx context.Context, api, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readOnly {
		return ErrReadOnly
	}
	if _, ok := s.find(api, name); !ok {
		return fmt.Errorf("%w: %s/%s", ErrNotFound, api, name)
	}
	if err := s.store.Delete(ctx, api, name); err != nil {
		return fmt.Errorf("store delete: %w", err)
	}
	if _, err := s.rt.RemovePolicy(api, name); err != nil {
		return fmt.Errorf("runtime remove: %w", err)
	}
	return nil
}

// List returns every policy currently in the runtime. The order is
// deny-first, permit-second within each API.
func (s *Service) List() []models.Policy { return s.rt.ListPolicies() }

// Get returns the policy at (api, name) or ErrNotFound.
func (s *Service) Get(api, name string) (models.Policy, error) {
	if p, ok := s.find(api, name); ok {
		return p, nil
	}
	return models.Policy{}, fmt.Errorf("%w: %s/%s", ErrNotFound, api, name)
}

func (s *Service) find(api, name string) (models.Policy, bool) {
	for _, p := range s.rt.ListPolicies() {
		if p.API == api && p.Name == name {
			return p, true
		}
	}
	return models.Policy{}, false
}

// persistAndApply runs the durable write before mutating the runtime,
// so a Store error never lands a half-applied policy in memory.
//
// Trade-off: a runtime ReplacePolicy that fails after the Store
// write succeeded leaves disk ahead of memory. On the next boot
// LoadFromStore replays the bad row through the same compile path,
// surfaces the same error, and refuses to start. This is the
// correct *runtime* behaviour (memory mirrors disk after every
// successful CRUD) but a footgun at *boot* time — an operator
// dealing with a poison policy must hand-edit the store. We accept
// the trade because the compile error in question is defence in
// depth: Validate already ran, so ReplacePolicy only fails on a
// bug. A future LoadFromStore-WARN-and-skip variant could trade
// startup brittleness for silent drift if that calculus ever
// flips.
func (s *Service) persistAndApply(ctx context.Context, p *models.Policy) error {
	if err := s.store.Put(ctx, *p); err != nil {
		return fmt.Errorf("store put: %w", err)
	}
	if _, err := s.rt.ReplacePolicy(p); err != nil {
		return fmt.Errorf("runtime apply: %w", err)
	}
	return nil
}

// basicSchema covers the cheap structural checks the runtime compile
// path doesn't surface clearly. Empty api/name produce nasty downstream
// errors (the runtime's lookup fails with "api %q not registered" for
// an empty key); catching them here keeps the validation message
// focused on what the caller did wrong.
func basicSchema(p *models.Policy) error {
	if p.API == "" {
		return errors.New("api is required")
	}
	if p.Name == "" {
		return errors.New("name is required")
	}
	if p.Condition == "" {
		return errors.New("condition is required")
	}
	if err := p.Result.Validate(); err != nil {
		return err
	}
	return nil
}
