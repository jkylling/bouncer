package traffic

import (
	"container/list"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

// memoryStore is the in-process backend. Constructed via Open with a
// store.MemoryBackend. Safe for concurrent use.
//
// Implementation: every event lands in a map keyed by id and an
// insertion-order doubly-linked list. Eviction walks the list from
// the oldest end, skipping pinned rows, until the byte and age
// budgets are met. List queries iterate the map and sort by ts —
// fine for the small (~1k row) buffer this backend is sized for.
type memoryStore struct {
	opts Options

	mu     sync.Mutex
	byID   map[EventID]*list.Element // id → *list.Element holding *entry
	ll     *list.List                // oldest at Front, newest at Back
	bytes  int                       // sum of non-pinned size_bytes
	pinned int                       // count of pinned entries
}

type entry struct {
	ev   Event
	size int
}

// newMemoryStore returns a fresh in-memory store with defaults
// applied. Always succeeds — the only allocation here is map/list
// state.
func newMemoryStore(opts Options) *memoryStore {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	if opts.MaxPinned <= 0 {
		opts.MaxPinned = DefaultMaxPinned
	}
	return &memoryStore{
		opts: opts,
		byID: map[EventID]*list.Element{},
		ll:   list.New(),
	}
}

// Insert adds ev to the store and runs eviction. The event's ID
// drives uniqueness — re-inserting the same id replaces the prior
// entry. Pinned-ness is preserved across replacement.
func (s *memoryStore) Insert(ctx context.Context, ev Event) error {
	size := approxSize(&ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.byID[ev.ID]; ok {
		oldEntry := old.Value.(*entry)
		ev.Pinned = oldEntry.ev.Pinned // preserve pin
		if !oldEntry.ev.Pinned {
			s.bytes -= oldEntry.size
		}
		s.ll.Remove(old)
		delete(s.byID, ev.ID)
	}
	e := &entry{ev: ev, size: size}
	el := s.ll.PushBack(e)
	s.byID[ev.ID] = el
	if !ev.Pinned {
		s.bytes += size
	}
	s.evictLocked(time.Now())
	return nil
}

// Get returns the full event for id, falling through to ErrNotFound
// when nothing matches. Returns a copy so callers cannot mutate
// store-internal state through the result.
func (s *memoryStore) Get(ctx context.Context, id EventID) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.byID[id]
	if !ok {
		return Event{}, ErrNotFound
	}
	return cloneEvent(el.Value.(*entry).ev), nil
}

// Pin marks id as pinned. ErrNotFound if the id is unknown,
// ErrPinnedFull if MaxPinned is already reached. Idempotent on a
// row that is already pinned.
func (s *memoryStore) Pin(ctx context.Context, id EventID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	e := el.Value.(*entry)
	if e.ev.Pinned {
		return nil
	}
	if s.pinned >= s.opts.MaxPinned {
		return ErrPinnedFull
	}
	e.ev.Pinned = true
	s.pinned++
	s.bytes -= e.size // pinned rows don't count toward byte budget
	return nil
}

// Unpin clears the pinned flag on id. ErrNotFound if the id is
// unknown. Idempotent on a row that is not pinned.
func (s *memoryStore) Unpin(ctx context.Context, id EventID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	e := el.Value.(*entry)
	if !e.ev.Pinned {
		return nil
	}
	e.ev.Pinned = false
	s.pinned--
	s.bytes += e.size
	s.evictLocked(time.Now())
	return nil
}

// List returns summaries for events matching opts, newest first,
// page-size capped by ClampLimit, with a forward cursor when more
// rows exist.
func (s *memoryStore) List(ctx context.Context, opts ListOpts) ([]Summary, Cursor, error) {
	curTS, curID, err := DecodeCursor(opts.Cursor)
	if err != nil {
		return nil, "", err
	}
	limit := ClampLimit(opts.Limit)

	s.mu.Lock()
	matched := make([]Event, 0, 64)
	for el := s.ll.Front(); el != nil; el = el.Next() {
		ev := el.Value.(*entry).ev
		if !match(ev, opts) {
			continue
		}
		matched = append(matched, ev)
	}
	s.mu.Unlock()

	// Newest first.
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Timestamp.Equal(matched[j].Timestamp) {
			return matched[i].ID > matched[j].ID
		}
		return matched[i].Timestamp.After(matched[j].Timestamp)
	})

	// Drop everything strictly newer than the cursor (we already
	// returned those on prior pages). The cursor encodes the last
	// row's (ts, id) — we resume strictly after it.
	if curID != "" {
		i := 0
		for i < len(matched) {
			ev := matched[i]
			if ev.Timestamp.Before(curTS) || (ev.Timestamp.Equal(curTS) && ev.ID < curID) {
				break
			}
			i++
		}
		matched = matched[i:]
	}

	page := matched
	var next Cursor
	if len(page) > limit {
		page = page[:limit]
		last := page[len(page)-1]
		next = EncodeCursor(last.Timestamp, last.ID)
	}
	out := make([]Summary, len(page))
	for i, ev := range page {
		out[i] = summary(ev)
	}
	return out, next, nil
}

// Close is a no-op for the in-memory store.
func (s *memoryStore) Close() error { return nil }

// evictLocked enforces the byte and age budgets. Caller must hold
// s.mu. Pinned entries are skipped, never removed.
func (s *memoryStore) evictLocked(now time.Time) {
	ageCutoff := now.Add(-s.opts.MaxAge)
	for el := s.ll.Front(); el != nil; {
		next := el.Next()
		e := el.Value.(*entry)
		drop := false
		if !e.ev.Pinned {
			if s.bytes > s.opts.MaxBytes {
				drop = true
			} else if !e.ev.Timestamp.IsZero() && e.ev.Timestamp.Before(ageCutoff) {
				drop = true
			}
		}
		if drop {
			s.bytes -= e.size
			delete(s.byID, e.ev.ID)
			s.ll.Remove(el)
		}
		el = next
	}
}

// cloneEvent deep-copies the slices inside ev so callers can mutate
// what they receive without corrupting store state.
func cloneEvent(ev Event) Event {
	out := ev
	if ev.RequestHeaders != nil {
		out.RequestHeaders = append([]KV(nil), ev.RequestHeaders...)
	}
	if ev.UpstreamHeaders != nil {
		out.UpstreamHeaders = append([]KV(nil), ev.UpstreamHeaders...)
	}
	if ev.RequestBody != nil {
		out.RequestBody = append([]byte(nil), ev.RequestBody...)
	}
	if ev.UpstreamBody != nil {
		out.UpstreamBody = append([]byte(nil), ev.UpstreamBody...)
	}
	if ev.Binds != nil {
		out.Binds = make([]ResolvedBind, len(ev.Binds))
		for i, b := range ev.Binds {
			out.Binds[i] = ResolvedBind{
				Name:  b.Name,
				Value: append(json.RawMessage(nil), b.Value...),
			}
		}
	}
	if ev.MetaFetches != nil {
		out.MetaFetches = make([]MetaFetch, len(ev.MetaFetches))
		for i, mf := range ev.MetaFetches {
			out.MetaFetches[i] = mf // scalar fields by value
			if mf.RequestBody != nil {
				out.MetaFetches[i].RequestBody = append([]byte(nil), mf.RequestBody...)
			}
			if mf.ResponseBody != nil {
				out.MetaFetches[i].ResponseBody = append([]byte(nil), mf.ResponseBody...)
			}
		}
	}
	return out
}

// match applies the ListOpts filters to ev. Zero filter fields are
// ignored. Subject is a pointer so a non-nil filter on the empty
// string still matches empty-subject events.
func match(ev Event, opts ListOpts) bool {
	if opts.PinnedOnly && !ev.Pinned {
		return false
	}
	if opts.API != "" && ev.API != opts.API {
		return false
	}
	if opts.Action != "" && ev.Action != opts.Action {
		return false
	}
	if opts.Method != "" && ev.Method != opts.Method {
		return false
	}
	if opts.Decision != "" && ev.Decision != opts.Decision {
		return false
	}
	if opts.PathPrefix != "" && !strings.HasPrefix(ev.URL, opts.PathPrefix) {
		return false
	}
	if !opts.Since.IsZero() && ev.Timestamp.Before(opts.Since) {
		return false
	}
	if !opts.Until.IsZero() && ev.Timestamp.After(opts.Until) {
		return false
	}
	if opts.Subject != nil && ev.Subject != *opts.Subject {
		return false
	}
	return true
}

// summary projects an Event onto its list-row shape. Bodies and
// headers are deliberately omitted so a 1k-row page does not pull
// every body into memory.
func summary(ev Event) Summary {
	return Summary{
		ID:             ev.ID,
		Timestamp:      ev.Timestamp,
		Subject:        ev.Subject,
		Method:         ev.Method,
		URL:            ev.URL,
		API:            ev.API,
		Action:         ev.Action,
		Decision:       ev.Decision,
		Policy:         ev.Policy,
		UpstreamStatus: ev.UpstreamStatus,
		LatencyMS:      ev.LatencyMS,
		Pinned:         ev.Pinned,
	}
}

// approxSize estimates the on-the-wire size of ev for budget
// accounting. Off by a constant factor compared to JSON length but
// stable enough that comparisons against MaxBytes work.
func approxSize(ev *Event) int {
	n := len(ev.ID) + len(ev.Subject) + len(ev.Method) + len(ev.URL) +
		len(ev.API) + len(ev.Action) + len(ev.Decision) + len(ev.Policy) +
		len(ev.Error)
	for _, kv := range ev.RequestHeaders {
		n += len(kv.Key) + len(kv.Value) + 2
	}
	for _, kv := range ev.UpstreamHeaders {
		n += len(kv.Key) + len(kv.Value) + 2
	}
	n += len(ev.RequestBody) + len(ev.UpstreamBody)
	for _, b := range ev.Binds {
		n += len(b.Name) + len(b.Value) + 2
	}
	// Fixed overhead per row covering timestamps + ints + struct
	// alignment. Conservative — it's better to evict slightly early
	// than to blow past the budget under tiny events.
	return n + 128
}
