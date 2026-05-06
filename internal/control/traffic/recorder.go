package traffic

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// AsyncRecorder buffers events on a channel and writes them to its
// Store from a single background goroutine. The proxy hot path calls
// Record (cheap channel send), the slow path runs in the writer.
//
// Drop policy: when the buffer is full, Record drops the event and
// increments a counter. A WARN log fires once per `dropLogEvery`
// drops so a saturated recorder is visible without flooding logs.
//
// Lifecycle: construct with New, call Record any number of times,
// then Close to drain pending events and stop the writer. After
// Close, Record returns immediately without enqueueing — Close is
// the one operation that has to be synchronised with shutdown.
//
// Shutdown ordering: Close holds the write lock around `close(r.in)`,
// blocking out any concurrent Record under the read lock. After
// Close releases the lock, late Records observe `closed` and bail
// without touching the (now closed) channel. The writer goroutine's
// range loop reads every buffered event before the channel close
// signals it to exit, so no committed Record loses its event.
type AsyncRecorder struct {
	store        Store
	sanitizeOpts SanitizeOptions
	in           chan Event
	exitCh       chan struct{}

	mu     sync.RWMutex
	closed bool

	dropped      atomic.Uint64 // total drops since construction
	loggedDrops  atomic.Uint64 // drops at last log emit
	dropLogEvery uint64

	logger *slog.Logger
}

// RecorderOptions tune the channel size, drop-log cadence, and
// sanitiser policy. Zero values pick defaults that match the rest of
// this package.
type RecorderOptions struct {
	// BufferSize is the channel capacity. A small fixed buffer
	// matches the design's intent: the recorder must never become a
	// memory hog on a saturated proxy.
	BufferSize int

	// DropLogEvery throttles the WARN log emitted on full-buffer
	// drops. The log fires when total drops cross a multiple of
	// this value. Zero falls back to DefaultDropLogEvery.
	DropLogEvery uint64

	// Sanitize is applied to every event before it reaches the
	// store. Zero value selects DefaultSanitizeOptions implicitly
	// (header strip, 8 KiB body cap, gmail/drive no-body).
	Sanitize SanitizeOptions

	// Logger is the slog.Logger used for drop warnings. Nil falls
	// back to slog.Default().
	Logger *slog.Logger
}

// DefaultBufferSize matches the design doc's 1024-cap channel.
const DefaultBufferSize = 1024

// DefaultDropLogEvery is the number of drops between WARN log
// emissions. Sized so a misbehaving deployment logs once or twice a
// minute under heavy drop pressure rather than per-event.
const DefaultDropLogEvery = 100

// NewAsyncRecorder wraps store in an async recorder. The writer
// goroutine starts immediately; callers must Close the recorder to
// avoid leaking it.
func NewAsyncRecorder(store Store, opts RecorderOptions) *AsyncRecorder {
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultBufferSize
	}
	if opts.DropLogEvery == 0 {
		opts.DropLogEvery = DefaultDropLogEvery
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	r := &AsyncRecorder{
		store:        store,
		sanitizeOpts: opts.Sanitize,
		in:           make(chan Event, opts.BufferSize),
		exitCh:       make(chan struct{}),
		dropLogEvery: opts.DropLogEvery,
		logger:       logger,
	}
	go r.run()
	return r
}

// Record enqueues ev for asynchronous writing. Non-blocking: drops
// the event when the channel is full and updates the drop counter.
// After Close, returns immediately without enqueueing.
//
// The read lock makes the closed-check + channel-send atomic with
// respect to Close: either the send wins and the writer drains it,
// or `closed` is observed and the call returns without touching the
// closed channel.
func (r *AsyncRecorder) Record(ctx context.Context, ev Event) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return
	}
	select {
	case r.in <- ev:
	default:
		r.onDrop(ctx)
	}
}

// onDrop bumps the drop counter and emits a rate-limited log line.
// The log records the cumulative drop count so a single line is
// enough to know we are saturated.
func (r *AsyncRecorder) onDrop(ctx context.Context) {
	total := r.dropped.Add(1)
	last := r.loggedDrops.Load()
	if total-last < r.dropLogEvery {
		return
	}
	// CAS so concurrent Record calls share one log per cadence
	// boundary instead of N. If the swap loses, the other goroutine
	// already logged.
	if r.loggedDrops.CompareAndSwap(last, total) {
		r.logger.WarnContext(ctx, "traffic: recorder dropping events",
			"total_dropped", total,
			"buffer_size", cap(r.in),
		)
	}
}

// Close drains any buffered events into the store and stops the
// writer goroutine. Idempotent: subsequent calls are no-ops. Returns
// after the writer has exited so callers can safely close the
// underlying store.
//
// The write lock blocks every concurrent Record (which holds the
// read lock) until the channel is closed. After Close releases, late
// Records observe `closed` and bail without sending. The writer's
// range loop reads everything still buffered before the channel
// close signals it to exit, so a routine shutdown does not drop
// last-millisecond events.
func (r *AsyncRecorder) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	close(r.in)
	r.mu.Unlock()
	<-r.exitCh
	return nil
}

// Dropped returns the total number of dropped events since
// construction. Exposed for tests and operator metrics.
func (r *AsyncRecorder) Dropped() uint64 {
	return r.dropped.Load()
}

// run is the writer goroutine body. Ranges over the channel until
// Close shuts it down — a closed channel drains every buffered event
// before the loop exits, so committed Records always reach the
// store.
func (r *AsyncRecorder) run() {
	defer close(r.exitCh)
	for ev := range r.in {
		r.write(ev)
	}
}

// write sanitises and persists a single event. Errors are logged at
// WARN — the recorder is best-effort, never fatal.
func (r *AsyncRecorder) write(ev Event) {
	Sanitize(&ev, r.sanitizeOpts)
	ctx := context.Background()
	if err := r.store.Insert(ctx, ev); err != nil {
		r.logger.WarnContext(ctx, "traffic: store insert", "id", ev.ID, "err", err)
	}
}
