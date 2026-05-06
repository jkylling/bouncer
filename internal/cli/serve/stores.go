package serve

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/proposals"
	"github.com/jkylling/bouncer/internal/control/store"
	"github.com/jkylling/bouncer/internal/control/traffic"
)

// TrafficStoreKind selects the traffic-viewer storage backend. The
// type only admits values the flag accepts, so an unknown kind is
// rejected at parse time and the build switch can stay exhaustive.
type TrafficStoreKind string

const (
	TrafficStoreNone   TrafficStoreKind = "none"
	TrafficStoreMemory TrafficStoreKind = "memory"
	TrafficStoreSqlite TrafficStoreKind = "sqlite"
)

func (k *TrafficStoreKind) UnmarshalText(b []byte) error {
	s := TrafficStoreKind(strings.ToLower(strings.TrimSpace(string(b))))
	switch s {
	case TrafficStoreNone, TrafficStoreMemory, TrafficStoreSqlite:
		*k = s
		return nil
	}
	return fmt.Errorf("invalid traffic store %q (none|memory|sqlite)", b)
}

// PoliciesStoreKind selects the policies storage backend. `file`
// keeps the operator-managed YAML-directory layout; the other kinds
// route through the shared sqlite/memory backends.
type PoliciesStoreKind string

const (
	PoliciesStoreFile   PoliciesStoreKind = "file"
	PoliciesStoreMemory PoliciesStoreKind = "memory"
	PoliciesStoreSqlite PoliciesStoreKind = "sqlite"
)

func (k *PoliciesStoreKind) UnmarshalText(b []byte) error {
	s := PoliciesStoreKind(strings.ToLower(strings.TrimSpace(string(b))))
	switch s {
	case PoliciesStoreFile, PoliciesStoreMemory, PoliciesStoreSqlite:
		*k = s
		return nil
	}
	return fmt.Errorf("invalid policies store %q (file|memory|sqlite)", b)
}

// ProposalsStoreKind selects the proposals storage backend.
type ProposalsStoreKind string

const (
	ProposalsStoreMemory ProposalsStoreKind = "memory"
	ProposalsStoreSqlite ProposalsStoreKind = "sqlite"
)

func (k *ProposalsStoreKind) UnmarshalText(b []byte) error {
	s := ProposalsStoreKind(strings.ToLower(strings.TrimSpace(string(b))))
	switch s {
	case ProposalsStoreMemory, ProposalsStoreSqlite:
		*k = s
		return nil
	}
	return fmt.Errorf("invalid proposals store %q (memory|sqlite)", b)
}

// backendCache interns store backends by configured path so two
// domains pointed at the same sqlite file share one *sql.DB rather
// than opening it twice. Backends are closed in reverse open order
// at shutdown via closeAll.
type backendCache struct {
	sqlite map[string]store.SQLBackend
	memory store.MemoryBackend
	open   []store.Backend
}

// sqliteAt returns the SQLBackend for path, opening one on first
// reference and reusing the same handle on subsequent calls. The
// caller does not Close — closeAll runs at shutdown.
func (c *backendCache) sqliteAt(path string) (store.SQLBackend, error) {
	if b, ok := c.sqlite[path]; ok {
		return b, nil
	}
	b, err := store.OpenSQLite(path)
	if err != nil {
		return nil, err
	}
	if c.sqlite == nil {
		c.sqlite = map[string]store.SQLBackend{}
	}
	c.sqlite[path] = b
	c.open = append(c.open, b)
	return b, nil
}

// memoryBackend returns the process-wide MemoryBackend, allocating
// one on first use. All in-memory domains share it because the
// MemoryBackend itself carries no state — domain stores allocate
// their own maps.
func (c *backendCache) memoryBackend() store.MemoryBackend {
	if c.memory == nil {
		c.memory = store.Memory()
		c.open = append(c.open, c.memory)
	}
	return c.memory
}

// closeAll closes every backend opened through the cache, in reverse
// order. Logs at WARN on failure — close errors after a successful
// run are visibility-only.
func (c *backendCache) closeAll() {
	for i := len(c.open) - 1; i >= 0; i-- {
		if err := c.open[i].Close(); err != nil {
			slog.Warn("backend close", "err", err)
		}
	}
}

// resolveDBPath returns the sqlite path a domain should use: the
// per-domain flag if set, otherwise the shared --store-db. Empty
// when neither is set; callers turn that into a clear error.
func resolveDBPath(perDomain, fallback string) string {
	if perDomain != "" {
		return perDomain
	}
	return fallback
}

// buildTraffic constructs the configured Store and the AsyncRecorder
// that feeds it. Returns (nil, nil, nil) when the operator selected
// `--traffic-store=none` so the caller can skip wiring entirely.
func buildTraffic(cfg *config, cache *backendCache) (traffic.Store, *traffic.AsyncRecorder, error) {
	opts := traffic.Options{
		MaxBytes:  cfg.TrafficBudget,
		MaxAge:    cfg.TrafficMaxAge,
		MaxPinned: cfg.TrafficMaxPinned,
	}
	var backend store.Backend
	switch cfg.TrafficStore {
	case TrafficStoreNone:
		return nil, nil, nil
	case TrafficStoreMemory:
		backend = cache.memoryBackend()
	case TrafficStoreSqlite:
		// validate() already enforced --traffic-db (or --store-db).
		b, err := cache.sqliteAt(resolveDBPath(cfg.TrafficDB, cfg.StoreDB))
		if err != nil {
			return nil, nil, fmt.Errorf("open traffic db: %w", err)
		}
		backend = b
	default:
		return nil, nil, fmt.Errorf("unhandled traffic store %q", cfg.TrafficStore)
	}
	st, err := traffic.Open(backend, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("traffic.Open: %w", err)
	}
	rec := traffic.NewAsyncRecorder(st, traffic.RecorderOptions{})
	return st, rec, nil
}

// buildPolicyStore opens the configured policies.Store. The "file"
// backend keeps the existing --policies-dir UX intact — a YAML
// directory rooted at exactly that path, no subdir layering.
func buildPolicyStore(cfg *config, cache *backendCache) (policies.Store, error) {
	switch cfg.PoliciesStore {
	case PoliciesStoreFile:
		// FileStore wraps --policies-dir directly. We intentionally
		// don't go through store.OpenFS+Subdir here so the existing
		// /policies layout is preserved verbatim. A unified-FS-root
		// deployment can use --policies-store=file --policies-dir=
		// /var/lib/bouncer/policies the same way.
		return policies.NewFileStore(cfg.PoliciesDir)
	case PoliciesStoreMemory:
		return policies.Open(cache.memoryBackend())
	case PoliciesStoreSqlite:
		// validate() already enforced --policies-db (or --store-db).
		b, err := cache.sqliteAt(resolveDBPath(cfg.PoliciesDB, cfg.StoreDB))
		if err != nil {
			return nil, fmt.Errorf("open policies db: %w", err)
		}
		return policies.Open(b)
	default:
		return nil, fmt.Errorf("unhandled policies store %q", cfg.PoliciesStore)
	}
}

// buildProposalStore opens the configured proposals.Store. Default
// is in-memory, matching the existing "drafts evaporate on restart"
// behaviour so an operator who upgrades and ignores the new flag
// sees no change.
func buildProposalStore(cfg *config, cache *backendCache) (proposals.Store, error) {
	switch cfg.ProposalsStore {
	case ProposalsStoreMemory:
		return proposals.Open(cache.memoryBackend())
	case ProposalsStoreSqlite:
		// validate() already enforced --proposals-db (or --store-db).
		b, err := cache.sqliteAt(resolveDBPath(cfg.ProposalsDB, cfg.StoreDB))
		if err != nil {
			return nil, fmt.Errorf("open proposals db: %w", err)
		}
		return proposals.Open(b)
	default:
		return nil, fmt.Errorf("unhandled proposals store %q", cfg.ProposalsStore)
	}
}
