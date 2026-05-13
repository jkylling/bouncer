// Package traffic captures, stores, and serves a recent-requests log
// for the bouncer control plane. It is the data layer behind the
// future traffic viewer UI: a `Recorder` is fed one `Event` per
// inbound request from `internal/server.Server.handle`, hands it to a
// pluggable `Store`, and the store backs the read APIs under
// `/_api/traffic/...`.
//
// Pluggability is the spine. The `Store` interface is small enough
// that a third-party backend (Postgres, ClickHouse, an S3 archive) is
// plausible. Two built-in implementations ship in this module:
//
//   - `memory` — bounded ring buffer + id map, no persistence.
//     Default when `--traffic-store=memory`. Used for local
//     development, integration tests, and the contract test suite
//     shared between backends.
//   - `sqlite` — single-file modernc.org/sqlite (pure Go, no cgo)
//     with one events table.
//
// The store is byte-budgeted (default 16 MiB) and age-budgeted
// (default 24h). On each `Insert` the store removes the oldest rows
// until both budgets are met.
//
// `Event.Binds` carries the resolved bind values from policy
// evaluation. They are stored opaquely (`json.RawMessage`) so the
// store does not need to know about the runtime's `messages.Value`
// shape. The recorder is responsible for marshalling.
package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Decision is the policy outcome attached to a captured Event. The
// string values match the otel `policy.decision` span attribute so a
// viewer row and a span can be joined on `decision` without
// translation. The named type prevents typos at the compiler level.
type Decision string

// Decision values.
const (
	DecisionPermit  Decision = "permit"
	DecisionDeny    Decision = "deny"
	DecisionNoMatch Decision = "no_match"
	DecisionError   Decision = "error"
)

// Event is one captured request as the recorder sees it. Field order
// is documentation only — JSON tags are stable so the serialised
// shape can be loaded by tools or future migrations.
//
// `RequestBody` and `UpstreamBody` may be truncated; `Truncated` is
// set when at least one side was. The recorder applies `Sanitize`
// before handing the event to a store, so headers like
// `Authorization` never reach disk.
type Event struct {
	ID                EventID            `json:"id"`
	Timestamp         time.Time          `json:"timestamp"`
	Subject           string             `json:"subject,omitempty"`
	Method            string             `json:"method"`
	URL               string             `json:"url"`
	RequestHeaders    []KV               `json:"request_headers,omitempty"`
	RequestBody       []byte             `json:"request_body,omitempty"`
	API               string             `json:"api,omitempty"`
	Action            string             `json:"action,omitempty"`
	Binds             []ResolvedBind     `json:"binds,omitempty"`
	MetaFetches       []MetaFetch        `json:"meta_fetches,omitempty"`
	Decision          Decision           `json:"decision"`
	Policy            string             `json:"policy,omitempty"`
	PolicyEvaluations []PolicyEvaluation `json:"policy_evaluations,omitempty"`
	UpstreamStatus    int                `json:"upstream_status,omitempty"`
	UpstreamHeaders   []KV               `json:"upstream_headers,omitempty"`
	UpstreamBody      []byte             `json:"upstream_body,omitempty"`
	LatencyMS         int64              `json:"latency_ms"`
	Error             string             `json:"error,omitempty"`
	Truncated         bool               `json:"truncated,omitempty"`
}

// PolicyEvaluation records one (policy, action) condition evaluation
// that ran during a request. Recorded in evaluation order; the
// runtime breaks out of the loop on the first Fired=true, so the
// deciding policy (when present) is always the last entry.
//
// Result is the policy's declared outcome — `permit` or `deny` — so
// even non-firing entries communicate "this policy would have done X
// if its condition had matched". Error captures a CEL eval failure
// on the policy's condition (the data plane separately surfaces this
// as a 403 to the caller).
type PolicyEvaluation struct {
	Policy string `json:"policy"`
	Action string `json:"action,omitempty"`
	Result string `json:"result,omitempty"`
	Fired  bool   `json:"fired,omitempty"`
	Error  string `json:"error,omitempty"`
}

// KV is one header line. A slice of these preserves order and allows
// duplicates, neither of which a `map[string][]string` would do
// without ceremony.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ResolvedBind is one runtime-resolved bind value. `Value` is the
// JSON encoding of the bind's `*messages.Value` — opaque to the
// store, useful to the policy-from-request flow which re-parses it
// to build a CEL equality predicate. The recorder owns the encoding;
// the store only persists.
type ResolvedBind struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// MetaFetch is one upstream side call that ran during policy
// evaluation — the lazy completer behind a meta value firing once an
// access path reached an output field. The recorder collects them in
// the order they fired, so a chain like `parent.parent.parent` shows
// up as three entries. Bodies are sanitised the same way as the
// inbound request/upstream pair (header strip, byte cap, NoBodyAPIs
// redaction). Status carries the upstream HTTP code on success and
// the failing code on UpstreamError; zero means the call never made
// it onto the wire (e.g. malformed meta request).
type MetaFetch struct {
	Meta         string `json:"meta"`
	API          string `json:"api,omitempty"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	RequestBody  []byte `json:"request_body,omitempty"`
	Status       int    `json:"status,omitempty"`
	ResponseBody []byte `json:"response_body,omitempty"`
	LatencyMS    int64  `json:"latency_ms"`
	Error        string `json:"error,omitempty"`
}

// Summary is the row shape returned by `Store.List`. It deliberately
// omits the bodies and binds — list views render hundreds of rows at
// a time, and a 16 MiB budget fits ~1k full Events but tens of
// thousands of summaries. Use `Get(id)` to fetch the full payload.
type Summary struct {
	ID             EventID   `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Subject        string    `json:"subject,omitempty"`
	Method         string    `json:"method"`
	URL            string    `json:"url"`
	API            string    `json:"api,omitempty"`
	Action         string    `json:"action,omitempty"`
	Decision       Decision  `json:"decision"`
	Policy         string    `json:"policy,omitempty"`
	UpstreamStatus int       `json:"upstream_status,omitempty"`
	LatencyMS      int64     `json:"latency_ms"`
}

// ListOpts carries the filters and pagination state for `Store.List`.
// All filter fields AND together. Zero-value fields are not applied.
//
// `Subject` is a pointer so the difference between "not filtering" and
// "filter on the empty subject" stays representable — the access-
// control story uses the latter for unauthenticated traffic.
//
// `Cursor` is opaque to the caller; pass back what `List` returned to
// page forward.
type ListOpts struct {
	// API filters to events whose api equals this value. Mutually
	// exclusive with APIs (which takes precedence when non-empty).
	API string

	// APIs filters to events whose api is in this set. Non-empty
	// overrides API. Used by the per-service traffic view, which
	// scopes to the bundle's full API set in one query.
	APIs []string

	Action     string
	Method     string
	Decision   Decision
	PathPrefix string
	Since      time.Time
	Until      time.Time
	Subject    *string
	Limit      int
	Cursor     Cursor
}

// Cursor is an opaque string token. Stores encode their own
// implementation detail (typically `(ts, id)`) into it; callers
// only round-trip it across pages.
type Cursor string

// Errors stores may return. HTTP-status mapping lives in
// internal/server/admin.
var (
	ErrNotFound = errors.New("traffic: event not found")
)

// Store is the persistence interface backing the traffic viewer.
// Implementations must be safe for concurrent use across goroutines —
// the recorder calls `Insert` from a single writer goroutine, but
// reads (`List`, `Get`) happen on inbound HTTP requests in parallel.
//
// `Insert` is responsible for honouring the byte and age budgets the
// implementation was constructed with.
type Store interface {
	Insert(ctx context.Context, ev Event) error
	List(ctx context.Context, opts ListOpts) ([]Summary, Cursor, error)
	Get(ctx context.Context, id EventID) (Event, error)

	// Subjects returns one row per distinct JWT subject observed in
	// stored traffic, with first-seen, last-seen, and request count.
	// Empty-subject (unauthenticated) events are excluded — callers
	// asking "which agents have authenticated" don't want them. The
	// returned slice is sorted last-seen-descending.
	Subjects(ctx context.Context) ([]SubjectSummary, error)

	Close() error
}

// SubjectSummary is one row of the Subjects query — a per-JWT-subject
// roll-up of stored traffic. Drives the Agents-page "agents that have
// authenticated" list; nothing depends on it being stable across a
// proxy restart since the source data is the traffic store, which is
// itself ephemeral by design.
type SubjectSummary struct {
	Subject      string    `json:"subject"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int64     `json:"request_count"`
}

// Tunables live here so the package doc can't drift from the actual
// values. Stores read these at construction time; values left at zero
// in Options pull the defaults from this file.
const (
	// DefaultMaxBytes is the byte budget when Options leaves
	// MaxBytes zero.
	DefaultMaxBytes = 16 * 1024 * 1024

	// DefaultMaxAge is the age budget when Options leaves MaxAge
	// zero.
	DefaultMaxAge = 24 * time.Hour

	// DefaultListLimit is the page size List falls back to when
	// ListOpts.Limit is zero.
	DefaultListLimit = 100

	// MaxListLimit is the absolute ceiling on a page size. A hostile
	// client cannot scan the whole table in one request.
	MaxListLimit = 1000
)

// ClampLimit applies the default + max policy. Exposed so store
// implementations stay consistent without re-deriving the rule.
func ClampLimit(n int) int {
	if n <= 0 {
		return DefaultListLimit
	}
	if n > MaxListLimit {
		return MaxListLimit
	}
	return n
}
