// Package storetest is the shared behavioural contract that every
// traffic.Store implementation must satisfy. Backends import it from
// their own _test.go files and call Run with a factory.
//
// Living here (rather than in internal/control/traffic/) keeps the
// production package free of `testing`-flavoured exports while still
// letting both built-in stores share one source of truth for the
// semantics callers depend on.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/control/traffic"
)

// Config bundles per-test-run knobs the contract suite needs.
//
// `MaxBytes` and `MaxAge` exercise the eviction paths. Implementations
// may impose hard floors (e.g. a sqlite store that won't accept a
// MaxBytes of 0); when they do, the suite supplies values large enough
// not to clip normal-sized payloads.
type Config struct {
	// New constructs a fresh, empty store. Each subtest receives its
	// own store so cross-test ordering does not matter.
	New func(t *testing.T) traffic.Store

	// MaxBytes is the budget the New-returned store was configured
	// with. Used to construct payloads that exercise eviction.
	MaxBytes int

	// MaxAge is the age budget. Tests that need to drive eviction by
	// age can bypass real wall-clock time by inserting events with
	// pre-set Timestamps.
	MaxAge time.Duration
}

// Run dispatches every contract subtest. Backends call it once from
// their TestStoreContract function; subtests are isolated via t.Run
// so a failure in one does not blank out the rest of the matrix.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	t.Run("InsertAndGetRoundTrip", func(t *testing.T) { testRoundTrip(t, cfg) })
	t.Run("GetMissingReturnsNotFound", func(t *testing.T) { testGetMissing(t, cfg) })
	t.Run("ListNewestFirst", func(t *testing.T) { testListNewestFirst(t, cfg) })
	t.Run("ListFiltersAND", func(t *testing.T) { testListFilters(t, cfg) })
	t.Run("ListSubjectFilter", func(t *testing.T) { testListSubject(t, cfg) })
	t.Run("ListPagination", func(t *testing.T) { testListPagination(t, cfg) })
	t.Run("EvictionRespectsByteBudget", func(t *testing.T) { testEvictionByteBudget(t, cfg) })
}

func newEvent(api, action string, decision traffic.Decision, subject string, ts time.Time) traffic.Event {
	return traffic.Event{
		ID:        traffic.NewEventID(),
		Timestamp: ts,
		Subject:   subject,
		Method:    "GET",
		URL:       "/" + api + "/v1/things",
		API:       api,
		Action:    action,
		Decision:  decision,
		LatencyMS: 5,
	}
}

func mustInsert(t *testing.T, s traffic.Store, ev traffic.Event) {
	t.Helper()
	if err := s.Insert(context.Background(), ev); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}

func mustList(t *testing.T, s traffic.Store, opts traffic.ListOpts) ([]traffic.Summary, traffic.Cursor) {
	t.Helper()
	rows, next, err := s.List(context.Background(), opts)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return rows, next
}

func testRoundTrip(t *testing.T, cfg Config) {
	s := cfg.New(t)
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	ev := newEvent("gmail", "messages.list", traffic.DecisionPermit, "alice", now)
	ev.RequestBody = []byte(`{"q":"label:inbox"}`)
	ev.UpstreamStatus = 200
	ev.LatencyMS = 42

	mustInsert(t, s, ev)
	got, err := s.Get(context.Background(), ev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != ev.ID || got.API != "gmail" || got.Action != "messages.list" {
		t.Errorf("got %+v, want id/api/action match", got)
	}
	if got.UpstreamStatus != 200 || got.LatencyMS != 42 {
		t.Errorf("got status=%d latency=%d, want 200/42", got.UpstreamStatus, got.LatencyMS)
	}
	if string(got.RequestBody) != `{"q":"label:inbox"}` {
		t.Errorf("request body = %q, want round-trip", got.RequestBody)
	}
	if !got.Timestamp.Equal(now) {
		t.Errorf("timestamp = %v, want %v", got.Timestamp, now)
	}
}

func testGetMissing(t *testing.T, cfg Config) {
	s := cfg.New(t)
	defer s.Close()
	_, err := s.Get(context.Background(), "deadbeef")
	if err != traffic.ErrNotFound {
		t.Errorf("Get unknown = %v, want ErrNotFound", err)
	}
}

func testListNewestFirst(t *testing.T, cfg Config) {
	s := cfg.New(t)
	defer s.Close()
	base := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	for i := 0; i < 5; i++ {
		ev := newEvent("gmail", "messages.list", traffic.DecisionPermit, "alice", base.Add(time.Duration(i)*time.Second))
		mustInsert(t, s, ev)
	}
	rows, _ := mustList(t, s, traffic.ListOpts{})
	if len(rows) != 5 {
		t.Fatalf("rows = %d, want 5", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if !rows[i].Timestamp.Before(rows[i-1].Timestamp) {
			t.Errorf("rows[%d].ts %v not before rows[%d].ts %v",
				i, rows[i].Timestamp, i-1, rows[i-1].Timestamp)
		}
	}
}

func testListFilters(t *testing.T, cfg Config) {
	s := cfg.New(t)
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	mustInsert(t, s, newEvent("gmail", "messages.list", traffic.DecisionPermit, "alice", now))
	mustInsert(t, s, newEvent("gmail", "messages.send", traffic.DecisionDeny, "alice", now.Add(-time.Second)))
	mustInsert(t, s, newEvent("drive", "files.list", traffic.DecisionPermit, "bob", now.Add(-2*time.Second)))

	rows, _ := mustList(t, s, traffic.ListOpts{API: "gmail"})
	if len(rows) != 2 {
		t.Errorf("api=gmail → %d rows, want 2", len(rows))
	}
	rows, _ = mustList(t, s, traffic.ListOpts{API: "gmail", Decision: traffic.DecisionDeny})
	if len(rows) != 1 || rows[0].Action != "messages.send" {
		t.Errorf("api=gmail decision=deny → %+v, want one messages.send row", rows)
	}
	rows, _ = mustList(t, s, traffic.ListOpts{Method: "POST"})
	if len(rows) != 0 {
		t.Errorf("method=POST → %d rows, want 0", len(rows))
	}
	rows, _ = mustList(t, s, traffic.ListOpts{PathPrefix: "/drive"})
	if len(rows) != 1 || rows[0].API != "drive" {
		t.Errorf("path_prefix=/drive → %+v, want one drive row", rows)
	}
}

func testListSubject(t *testing.T, cfg Config) {
	s := cfg.New(t)
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	mustInsert(t, s, newEvent("gmail", "a", traffic.DecisionPermit, "alice", now))
	mustInsert(t, s, newEvent("gmail", "a", traffic.DecisionPermit, "bob", now.Add(-time.Second)))
	mustInsert(t, s, newEvent("gmail", "a", traffic.DecisionPermit, "", now.Add(-2*time.Second)))

	alice := "alice"
	rows, _ := mustList(t, s, traffic.ListOpts{Subject: &alice})
	if len(rows) != 1 || rows[0].Subject != "alice" {
		t.Errorf("subject=alice → %+v, want one alice row", rows)
	}

	empty := ""
	rows, _ = mustList(t, s, traffic.ListOpts{Subject: &empty})
	if len(rows) != 1 || rows[0].Subject != "" {
		t.Errorf("subject='' → %+v, want one empty-subject row", rows)
	}

	rows, _ = mustList(t, s, traffic.ListOpts{}) // nil subject = all
	if len(rows) != 3 {
		t.Errorf("subject=nil → %d rows, want 3", len(rows))
	}
}

func testListPagination(t *testing.T, cfg Config) {
	s := cfg.New(t)
	defer s.Close()
	base := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	for i := 0; i < 10; i++ {
		mustInsert(t, s, newEvent("gmail", "a", traffic.DecisionPermit, "alice", base.Add(time.Duration(i)*time.Second)))
	}
	page1, cur1 := mustList(t, s, traffic.ListOpts{Limit: 4})
	if len(page1) != 4 {
		t.Fatalf("page1 len = %d, want 4", len(page1))
	}
	if cur1 == "" {
		t.Fatal("page1 cursor empty, want forward cursor")
	}
	page2, cur2 := mustList(t, s, traffic.ListOpts{Limit: 4, Cursor: cur1})
	if len(page2) != 4 {
		t.Fatalf("page2 len = %d, want 4", len(page2))
	}
	page3, cur3 := mustList(t, s, traffic.ListOpts{Limit: 4, Cursor: cur2})
	if len(page3) != 2 {
		t.Fatalf("page3 len = %d, want 2 (10 total in 4+4+2)", len(page3))
	}
	if cur3 != "" {
		t.Errorf("page3 cursor = %q, want empty (final page)", cur3)
	}
	// No overlap between pages.
	seen := map[traffic.EventID]bool{}
	for _, p := range [][]traffic.Summary{page1, page2, page3} {
		for _, r := range p {
			if seen[r.ID] {
				t.Errorf("id %s appeared in multiple pages", r.ID)
			}
			seen[r.ID] = true
		}
	}
	if len(seen) != 10 {
		t.Errorf("paginated %d distinct ids, want 10", len(seen))
	}
}

// testEvictionByteBudget fills the store past its byte budget and
// asserts the oldest rows are gone.
func testEvictionByteBudget(t *testing.T, cfg Config) {
	s := cfg.New(t)
	defer s.Close()
	// 4 KiB body × 64 events ≈ 256 KiB worth of payload bodies. Even
	// stores with a > 1 MiB minimum will evict at this scale if the
	// budget is set tight enough.
	bigBody := make([]byte, 4*1024)
	for i := range bigBody {
		bigBody[i] = 'x'
	}
	base := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	const N = 64
	ids := make([]traffic.EventID, N)
	for i := 0; i < N; i++ {
		ev := newEvent("gmail", "a", traffic.DecisionPermit, "alice", base.Add(time.Duration(i)*time.Second))
		ev.RequestBody = bigBody
		ids[i] = ev.ID
		mustInsert(t, s, ev)
	}
	// Tighter than every event together but loose enough to keep at
	// least the most recent few. Stores are free to keep more —
	// they must keep at least the newest one.
	rows, _ := mustList(t, s, traffic.ListOpts{Limit: traffic.MaxListLimit})
	if len(rows) == N {
		t.Errorf("after over-budget inserts: still %d rows, expected eviction", len(rows))
	}
	if len(rows) == 0 {
		t.Fatal("after over-budget inserts: 0 rows, expected newest survives")
	}
	// Newest survives.
	newest := ids[N-1]
	if rows[0].ID != newest {
		t.Errorf("newest row id = %s, want %s", rows[0].ID, newest)
	}
	// Oldest gone.
	if _, err := s.Get(context.Background(), ids[0]); err != traffic.ErrNotFound {
		t.Errorf("oldest Get = %v, want ErrNotFound after eviction", err)
	}
}
