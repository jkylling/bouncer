// Package agents tracks pending and approved agent registrations.
// Agents self-register over /_api/agents/register (no auth — anyone
// who can reach the server can request a slot); the operator
// approves or rejects from the dashboard. Approval transitions the
// record to "approved"; the actual JWT issuance still goes through
// tokens.Issue.
//
// Storage is one JSON file per agent under `<data-dir>/agents/`,
// matching connections/'s file-per-record shape. A future change
// might consolidate into a single index, but file-per-record makes
// `ls`/`grep` on disk legible and avoids contention on a single hot
// file.
package agents

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Sentinel errors. Handlers map these onto HTTP statuses.
var (
	ErrInvalid     = errors.New("invalid agent")
	ErrNotFound    = errors.New("agent not found")
	ErrPersistence = errors.New("agent persistence error")
	ErrNotPending  = errors.New("agent is not pending")
)

// Status is one of pending / approved / rejected.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// Agent is one registration record. ID is opaque and assigned by the
// store on Register; Fingerprint is the agent-supplied identifier
// (typically a sha256 over its install). Harness is one of
// claude-code / cursor / desktop / hermes / other.
//
// Name and Services are the operator-set fields the new Agents UI
// surfaces: Name is a free-form label ("daily-digest", "drafting-
// bot"); Services is the slug list the operator says this agent
// should reach. Both default to zero values on old records, and
// both are informational in v1 — actual enforcement still flows
// through CEL policies, not the slug list.
type Agent struct {
	ID          string    `json:"id"`
	Name        string    `json:"name,omitempty"`
	Harness     string    `json:"harness"`
	Fingerprint string    `json:"fingerprint"`
	Services    []string  `json:"services,omitempty"`
	Status      Status    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	DecidedAt   time.Time `json:"decided_at,omitempty"`
}

// Store is the file-backed registry. mu serialises every mutation so
// approve/reject can read-modify-write atomically.
type Store struct {
	mu  sync.Mutex
	dir string
}

// NewStore returns a Store rooted at dir.
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// RegisterOpts is the optional set of fields the operator-facing
// "Connect a new agent" form can fill in alongside the agent's own
// harness + fingerprint announcement.
type RegisterOpts struct {
	Name     string
	Services []string
}

// Register creates a pending agent. Returns the new record. Harness
// is validated against a small allow-list — a typo there is the most
// likely user error, and rejecting unknown harness names early
// avoids a useless "unknown" entry on the dashboard.
func (s *Store) Register(harness, fingerprint string) (Agent, error) {
	return s.RegisterWith(harness, fingerprint, RegisterOpts{})
}

// RegisterWith is Register plus the operator-supplied Name +
// Services. Empty fields are stored as-is so the existing
// agent-initiated path (which doesn't set them) keeps working
// without a separate code branch.
//
// In the local-bouncer model the registering agent is a process the
// operator just ran on their own machine; there is no anonymous
// poster to gate against, and the actual access gate sits one layer
// up (MCP get_{slug}_token tools check connection state, not agent
// status). Registration therefore lands directly as approved. A
// future hosted deployment can re-introduce the pending state by
// gating this call on the listener's reachability.
func (s *Store) RegisterWith(harness, fingerprint string, opts RegisterOpts) (Agent, error) {
	if !isKnownHarness(harness) {
		return Agent{}, fmt.Errorf("%w: harness %q not in [claude-code,cursor,desktop,hermes,other]", ErrInvalid, harness)
	}
	if fingerprint == "" {
		return Agent{}, fmt.Errorf("%w: fingerprint required", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return Agent{}, fmt.Errorf("%w: id: %v", ErrPersistence, err)
	}
	now := time.Now().UTC()
	rec := Agent{
		ID:          id,
		Name:        opts.Name,
		Harness:     harness,
		Fingerprint: fingerprint,
		Services:    append([]string(nil), opts.Services...),
		Status:      StatusApproved,
		CreatedAt:   now,
		DecidedAt:   now,
	}
	if err := s.write(rec); err != nil {
		return Agent{}, err
	}
	return rec, nil
}

// List returns every agent, sorted newest-first.
func (s *Store) List() ([]Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: readdir: %v", ErrPersistence, err)
	}
	out := make([]Agent, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		rec, err := readFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	// Newest-first; CreatedAt is monotonic enough for this UI.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.After(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// Get returns one agent by ID, or ErrNotFound.
func (s *Store) Get(id string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(id)
}

// Approve transitions a pending agent to approved. The HTTP layer
// then mints the agent's JWT separately via tokens.Issue and returns
// it to the caller; this package only flips the status.
func (s *Store) Approve(id string) (Agent, error) {
	return s.decide(id, StatusApproved)
}

// Reject transitions a pending agent to rejected. Stored rather than
// deleted so an audit log of declined registrations is preserved.
func (s *Store) Reject(id string) (Agent, error) {
	return s.decide(id, StatusRejected)
}

func (s *Store) decide(id string, to Status) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.getLocked(id)
	if err != nil {
		return Agent{}, err
	}
	if rec.Status != StatusPending {
		return Agent{}, fmt.Errorf("%w: status is %s", ErrNotPending, rec.Status)
	}
	rec.Status = to
	rec.DecidedAt = time.Now().UTC()
	if err := s.writeLocked(rec); err != nil {
		return Agent{}, err
	}
	return rec, nil
}

func (s *Store) getLocked(id string) (Agent, error) {
	if !validID(id) {
		return Agent{}, fmt.Errorf("%w: id", ErrInvalid)
	}
	rec, err := readFile(filepath.Join(s.dir, id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("%w: read: %v", ErrPersistence, err)
	}
	return rec, nil
}

func (s *Store) write(rec Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked(rec)
}

func (s *Store) writeLocked(rec Agent) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("%w: mkdir: %v", ErrPersistence, err)
	}
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode: %v", ErrPersistence, err)
	}
	tmp := filepath.Join(s.dir, rec.ID+".json.tmp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("%w: write: %v", ErrPersistence, err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, rec.ID+".json")); err != nil {
		return fmt.Errorf("%w: rename: %v", ErrPersistence, err)
	}
	return nil
}

func readFile(path string) (Agent, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Agent{}, err
	}
	var rec Agent
	if err := json.Unmarshal(body, &rec); err != nil {
		return Agent{}, err
	}
	return rec, nil
}

// newID returns a 16-byte hex string suitable for a URL path
// parameter. The collision probability over a single bouncer's
// lifetime is negligible at 128 bits.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// validID guards the URL path parameter against traversal — opaque
// hex is the only legitimate input.
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isKnownHarness(h string) bool {
	switch h {
	case "claude-code", "cursor", "desktop", "hermes", "other":
		return true
	}
	return false
}
