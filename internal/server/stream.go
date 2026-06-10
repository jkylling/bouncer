package server

import (
	"errors"
	"net/http"
	"time"
)

// streamWriter relays upstream response bytes to the client as they
// arrive. The data plane proxies AI-agent workloads where SSE and
// chunked LLM token streams are the norm, so two things must hold
// that a plain io.Copy(w, body) does not provide:
//
//   - Each chunk is flushed immediately. net/http buffers ~4 KiB and
//     otherwise flushes only when the handler returns, which turns an
//     incremental upstream stream into one burst at the end.
//   - The connection's write deadline is pushed out on every chunk.
//     The listener's WriteTimeout is an absolute budget measured from
//     the start of the request; without the per-chunk extension it
//     hard-cuts any stream that outlives it. Extending on progress
//     keeps active streams alive while a stalled client still times
//     out after one idle window.
type streamWriter struct {
	w    http.ResponseWriter
	rc   *http.ResponseController
	idle time.Duration
}

func newStreamWriter(w http.ResponseWriter, idle time.Duration) *streamWriter {
	return &streamWriter{w: w, rc: http.NewResponseController(w), idle: idle}
}

func (sw *streamWriter) Write(p []byte) (int, error) {
	n, err := sw.w.Write(p)
	if n > 0 {
		// Push the deadline before flushing so the flush itself runs
		// under the fresh budget. ErrNotSupported (test recorders,
		// exotic wrappers) downgrades to the server's absolute
		// WriteTimeout rather than failing the stream.
		if sw.idle > 0 {
			if derr := sw.rc.SetWriteDeadline(time.Now().Add(sw.idle)); derr != nil && !errors.Is(derr, http.ErrNotSupported) && err == nil {
				err = derr
			}
		}
		if ferr := sw.rc.Flush(); ferr != nil && !errors.Is(ferr, http.ErrNotSupported) && err == nil {
			err = ferr
		}
	}
	return n, err
}
