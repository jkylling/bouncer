// Package mitm turns the proxy into a TLS-terminating forward proxy
// so an unmodified HTTPS client can be pointed at bouncer via
// HTTPS_PROXY. The handler hijacks `CONNECT host:port`, replies
// `200 Connection established`, and wraps the conn in tls.Server with
// a GetCertificate callback that issues a per-SNI leaf signed by an
// operator-provided CA. Tunnelled requests are dispatched to the
// inner handler. Non-CONNECT requests pass through unchanged so the
// proxy is still reachable directly for diagnostics.
package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/jkylling/bouncer/internal/observability"
)

// AttrTargetHost is the span attribute that records the SNI host the
// CONNECT was for.
const AttrTargetHost = "target.host"

var tracerName = observability.PackagePath()

// Handler wraps an inner http.Handler with CONNECT-method handling
// and TLS-MITM. Construct with New.
type Handler struct {
	ca                *CA
	inner             http.Handler
	idleTimeout       time.Duration
	readHeaderTimeout time.Duration
}

// Options carry per-listener knobs for New. Zero values pick defaults.
type Options struct {
	IdleTimeout       time.Duration
	ReadHeaderTimeout time.Duration
}

func New(ca *CA, inner http.Handler, opts Options) *Handler {
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 120 * time.Second
	}
	if opts.ReadHeaderTimeout == 0 {
		opts.ReadHeaderTimeout = 5 * time.Second
	}
	return &Handler{
		ca:                ca,
		inner:             inner,
		idleTimeout:       opts.IdleTimeout,
		readHeaderTimeout: opts.ReadHeaderTimeout,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		h.inner.ServeHTTP(w, r)
		return
	}
	h.serveConnect(w, r)
}

func (h *Handler) serveConnect(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 1 {
		// CONNECT-and-tunnel relies on http.Hijacker, which is HTTP/1.x
		// only. Real HTTPS_PROXY clients use HTTP/1.1 for the proxy hop
		// even when inner traffic is h2, so landing here means a
		// misconfigured client.
		http.Error(w, "MITM proxy requires HTTP/1.1 for CONNECT", http.StatusHTTPVersionNotSupported)
		return
	}

	// RFC 9110 §9.3.6: the CONNECT request target *is* the authority,
	// in r.URL.Host. r.Host is the (client-craftable) Host header;
	// reading it would let an attacker request a CA-signed leaf for an
	// arbitrary hostname by skewing the two.
	host, _, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}

	// Open a span around tunnel setup so target.host shows up in the
	// trace promptly. End it as soon as the handshake completes —
	// keeping it open for the tunnel lifetime would delay export until
	// keep-alive elapses, useless for live debugging. The inner
	// request span uses the captured SpanContext as its parent.
	setupCtx, span := otel.Tracer(tracerName).Start(r.Context(), "mitm.tunnel")
	span.SetAttributes(attribute.String(AttrTargetHost, host))
	tunnelCtx := trace.ContextWithSpanContext(r.Context(), span.SpanContext())

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		span.SetStatus(codes.Error, "hijack unsupported")
		span.End()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hijacker.Hijack()
	if err != nil {
		span.SetStatus(codes.Error, "hijack failed")
		span.RecordError(err)
		span.End()
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Hand-write the ack: the stdlib's WriteHeader path adds Date /
	// Content-Length headers that RFC 7230 §3.3.3 forbids on a 2xx
	// CONNECT response, and some hardened clients reject them.
	if _, err := brw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		span.RecordError(err)
		span.End()
		slog.WarnContext(r.Context(), "mitm connect ack write", "host", host, "err", err)
		return
	}
	if err := brw.Flush(); err != nil {
		span.RecordError(err)
		span.End()
		slog.WarnContext(r.Context(), "mitm connect ack flush", "host", host, "err", err)
		return
	}

	// SNI-less fallback uses the CONNECT host, not hello.Conn.LocalAddr
	// (which would collapse every SNI-less tunnel onto one leaf bearing
	// the proxy's IP — strict-trust clients would refuse the chain).
	var leafNotAfter time.Time
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			leaf, err := h.ca.leafFor(name)
			if err == nil && leaf.Leaf != nil {
				leafNotAfter = leaf.Leaf.NotAfter
			}
			return leaf, err
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	tlsConn := tls.Server(conn, tlsConfig)
	defer tlsConn.Close()

	hsCtx, cancel := context.WithTimeout(setupCtx, h.readHeaderTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		span.SetStatus(codes.Error, "tls handshake")
		span.RecordError(err)
		span.End()
		slog.WarnContext(tunnelCtx, "mitm tls handshake", "host", host, "err", err)
		return
	}
	span.End()

	// Close the tunnel before the leaf cert expires so a reconnecting
	// client gets a fresh cert on the new TLS handshake.
	tunnelDone := make(chan struct{})
	defer close(tunnelDone)
	if !leafNotAfter.IsZero() {
		remaining := time.Until(leafNotAfter.Add(-h.ca.effectiveMargin()))
		if remaining > 0 {
			timer := time.NewTimer(remaining)
			go func() {
				select {
				case <-timer.C:
					slog.DebugContext(tunnelCtx, "mitm tunnel closing: leaf cert approaching expiry", "host", host)
					conn.Close()
				case <-tunnelDone:
					timer.Stop()
				}
			}()
		}
	}

	// One-conn http.Server runs the inner router. BaseContext threads
	// the tunnel SpanContext into every request so otelhttp inside the
	// inner router picks it as a parent.
	inner := &http.Server{
		Handler:           h.inner,
		ReadHeaderTimeout: h.readHeaderTimeout,
		IdleTimeout:       h.idleTimeout,
		BaseContext:       func(_ net.Listener) context.Context { return tunnelCtx },
	}
	if err := inner.Serve(newSingleConnListener(tlsConn, host)); err != nil && !errors.Is(err, errSingleConnDone) {
		slog.DebugContext(tunnelCtx, "mitm inner serve", "host", host, "err", err)
	}
}

// singleConnListener turns one tls.Conn into a net.Listener so we can
// drive it with http.Server. First Accept returns the conn (wrapped so
// Close unblocks subsequent Accepts); subsequent Accepts block until
// close and return errSingleConnDone so Serve exits cleanly.
type singleConnListener struct {
	conn   net.Conn
	host   string
	served sync.Once
	done   chan struct{}
	mu     sync.Mutex
	closed bool
}

var errSingleConnDone = errors.New("mitm: single-conn listener exhausted")

func newSingleConnListener(conn net.Conn, host string) *singleConnListener {
	return &singleConnListener{
		conn: conn,
		host: host,
		done: make(chan struct{}),
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var first bool
	l.served.Do(func() { first = true })
	if first {
		return &notifyOnCloseConn{Conn: l.conn, l: l}, nil
	}
	<-l.done
	return nil, errSingleConnDone
}

// Close unblocks any pending Accept. The underlying conn is closed by
// the outer serveConnect's defer.
func (l *singleConnListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.done)
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	if a, ok := l.conn.(interface{ LocalAddr() net.Addr }); ok {
		return a.LocalAddr()
	}
	return dummyAddr(l.host)
}

// notifyOnCloseConn signals the parent listener when http.Server closes
// the conn so Accept terminates without an arbitrary timeout.
type notifyOnCloseConn struct {
	net.Conn
	l    *singleConnListener
	once sync.Once
}

func (c *notifyOnCloseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.Close() })
	return err
}

type dummyAddr string

func (a dummyAddr) Network() string { return "tls" }
func (a dummyAddr) String() string  { return string(a) }
