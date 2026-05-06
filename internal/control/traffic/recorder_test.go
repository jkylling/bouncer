package traffic_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/control/store"
	"github.com/jkylling/bouncer/internal/control/traffic"
)

// newMemStore returns an in-memory traffic store via the shared
// backend abstraction. The test file's previous helper called the
// removed memory.New constructor directly; this thin wrapper keeps
// the test bodies short while routing through the public API.
func newMemStore(t *testing.T) traffic.Store {
	t.Helper()
	s, err := traffic.Open(store.Memory(), traffic.Options{})
	if err != nil {
		t.Fatalf("traffic.Open: %v", err)
	}
	return s
}

func TestAsyncRecorderHappyPath(t *testing.T) {
	store := newMemStore(t)
	defer store.Close()
	rec := traffic.NewAsyncRecorder(store, traffic.RecorderOptions{})

	now := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < 5; i++ {
		rec.Record(context.Background(), traffic.Event{
			ID:        traffic.NewEventID(),
			Timestamp: now,
			API:       "gmail",
			Decision:  traffic.DecisionPermit,
		})
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rows, _, err := store.List(context.Background(), traffic.ListOpts{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 5 {
		t.Errorf("rows = %d, want 5", len(rows))
	}
}

// TestAsyncRecorderSanitizes confirms Sanitize runs before the store
// sees the event — the recorder's sanitize-in-the-pipeline contract
// is what lets stores assume their input is already redacted.
func TestAsyncRecorderSanitizes(t *testing.T) {
	store := newMemStore(t)
	defer store.Close()
	rec := traffic.NewAsyncRecorder(store, traffic.RecorderOptions{})

	id := traffic.NewEventID()
	rec.Record(context.Background(), traffic.Event{
		ID:        id,
		Timestamp: time.Now().UTC().Truncate(time.Millisecond),
		API:       "gmail",
		Decision:  traffic.DecisionPermit,
		RequestHeaders: []traffic.KV{
			{Key: "Authorization", Value: "Bearer secret"},
			{Key: "X-Trace", Value: "1"},
		},
		RequestBody: []byte("user content here"),
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, kv := range got.RequestHeaders {
		if kv.Key == "Authorization" {
			t.Errorf("Authorization header survived sanitize: %q", kv.Value)
		}
	}
	if got.RequestBody != nil {
		t.Errorf("gmail body survived no-body sanitize: %q", got.RequestBody)
	}
}

// TestAsyncRecorderDropsWhenFull saturates a tiny buffer with a
// blocked store, asserts Record never blocks, and verifies the drop
// counter increments.
func TestAsyncRecorderDropsWhenFull(t *testing.T) {
	store := &blockingStore{block: make(chan struct{})}
	rec := traffic.NewAsyncRecorder(store, traffic.RecorderOptions{
		BufferSize:   2,
		DropLogEvery: 1,
	})

	// First push (taken by writer immediately, blocks in store.Insert).
	rec.Record(context.Background(), traffic.Event{ID: "a"})
	// Two more fill the buffer.
	rec.Record(context.Background(), traffic.Event{ID: "b"})
	rec.Record(context.Background(), traffic.Event{ID: "c"})
	// Wait for writer to be parked and buffer to fill.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && store.calls() < 1 {
		time.Sleep(time.Millisecond)
	}
	// Further pushes should be dropped.
	for i := 0; i < 5; i++ {
		rec.Record(context.Background(), traffic.Event{ID: "drop"})
	}
	close(store.block)
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rec.Dropped() == 0 {
		t.Errorf("Dropped() = 0, want > 0 after saturating buffer")
	}
}

// TestAsyncRecorderDrainsBufferedOnClose: Records that committed
// to the buffer before Close fired must reach the store. Pins the
// shutdown contract — no last-millisecond drops on a routine close.
func TestAsyncRecorderDrainsBufferedOnClose(t *testing.T) {
	st := &blockingStore{block: make(chan struct{})}
	rec := traffic.NewAsyncRecorder(st, traffic.RecorderOptions{BufferSize: 8})

	// First send is taken by writer (blocks inside Insert). The next
	// few queue in the channel buffer.
	for i := 0; i < 5; i++ {
		rec.Record(context.Background(), traffic.Event{ID: traffic.NewEventID()})
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && st.calls() < 1 {
		time.Sleep(time.Millisecond)
	}
	// Trigger Close concurrently while the writer is blocked. Then
	// release the writer and wait for Close to return.
	done := make(chan error, 1)
	go func() { done <- rec.Close() }()
	close(st.block)
	if err := <-done; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := st.calls(); got != 5 {
		t.Errorf("store inserts = %d, want 5 — Close dropped buffered events", got)
	}
}

// TestAsyncRecorderRecordAfterClose is a no-op Record post-Close —
// no panic, no enqueue, no goroutine leak.
func TestAsyncRecorderRecordAfterClose(t *testing.T) {
	store := newMemStore(t)
	defer store.Close()
	rec := traffic.NewAsyncRecorder(store, traffic.RecorderOptions{})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rec.Record(context.Background(), traffic.Event{ID: "after-close"})
	if err := rec.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	rows, _, _ := store.List(context.Background(), traffic.ListOpts{})
	if len(rows) != 0 {
		t.Errorf("post-close Record landed: %d rows", len(rows))
	}
}

// blockingStore is a traffic.Store whose Insert blocks until the
// test signals on `block`. Used to deterministically saturate the
// recorder's buffer.
type blockingStore struct {
	block   chan struct{}
	mu      sync.Mutex
	callcnt int
}

func (b *blockingStore) Insert(ctx context.Context, ev traffic.Event) error {
	b.mu.Lock()
	b.callcnt++
	b.mu.Unlock()
	<-b.block
	return nil
}
func (b *blockingStore) Get(ctx context.Context, id traffic.EventID) (traffic.Event, error) {
	return traffic.Event{}, errors.New("not implemented")
}
func (b *blockingStore) List(ctx context.Context, opts traffic.ListOpts) ([]traffic.Summary, traffic.Cursor, error) {
	return nil, "", errors.New("not implemented")
}
func (b *blockingStore) Pin(ctx context.Context, id traffic.EventID) error {
	return errors.New("not implemented")
}
func (b *blockingStore) Unpin(ctx context.Context, id traffic.EventID) error {
	return errors.New("not implemented")
}
func (b *blockingStore) Close() error { return nil }

func (b *blockingStore) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.callcnt
}
