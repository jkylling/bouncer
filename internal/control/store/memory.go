package store

// memoryBackend is the in-process MemoryBackend. It carries no state
// — domain stores allocate their own maps when handed one — but
// having a value to pass through keeps the Open signatures uniform.
type memoryBackend struct{}

// Memory returns a MemoryBackend. Cheap to call repeatedly; the
// returned value is comparable but each call yields a distinct
// instance (so two domains in test code can hold "their own"
// memory backend if they want one each).
func Memory() MemoryBackend { return &memoryBackend{} }

// memoryMarker satisfies the unexported marker on MemoryBackend.
func (*memoryBackend) memoryMarker() {}

// Close is a no-op.
func (*memoryBackend) Close() error { return nil }
