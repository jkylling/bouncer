package mitm

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestConnectThenInner pins the full CONNECT → 200 ack → TLS handshake
// → routed request → response path against a real http.Client through
// HTTPS_PROXY.
func TestConnectThenInner(t *testing.T) {
	ca, caCertPEM := mustCA(t)

	inner := http.NewServeMux()
	inner.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "host="+r.Host+";path="+r.URL.Path)
	})

	proxy := httptest.NewServer(New(ca, inner, Options{}))
	defer proxy.Close()

	client := proxyClient(t, proxy.URL, caCertPEM)
	resp, err := client.Get("https://gmail.googleapis.com/echo")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "host=gmail.googleapis.com;path=/echo"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestNonConnectFallsThrough: a plain GET is delegated to the inner
// handler unchanged so operators can hit the proxy directly with curl
// while the listener is in mitm mode.
func TestNonConnectFallsThrough(t *testing.T) {
	ca, _ := mustCA(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct:"+r.URL.Path)
	})
	proxy := httptest.NewServer(New(ca, inner, Options{}))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/diag")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "direct:/diag" {
		t.Errorf("body = %q, want direct:/diag", got)
	}
}

// TestConnectBadHost: a CONNECT without host:port returns 400 before
// hijack so the conn isn't leaked.
func TestConnectBadHost(t *testing.T) {
	ca, _ := mustCA(t)
	proxy := httptest.NewServer(New(ca, http.NotFoundHandler(), Options{}))
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodConnect, proxy.URL, nil)
	req.Host = "no-port-here"
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// proxyClient builds an http.Client routed through the given proxy
// with the test CA installed as a trusted root.
func proxyClient(t *testing.T, proxyURL string, caPEM []byte) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM: false")
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		},
	}
}

// TestConnectLeafSAN: after a CONNECT, the leaf cert handed to the
// client carries an SNI-matching SAN.
func TestConnectLeafSAN(t *testing.T) {
	ca, caCertPEM := mustCA(t)
	proxy := httptest.NewServer(New(ca, http.NotFoundHandler(), Options{}))
	defer proxy.Close()

	client := proxyClient(t, proxy.URL, caCertPEM)
	tr := client.Transport.(*http.Transport).Clone()
	var seenSAN []string
	tr.TLSClientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		c, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		seenSAN = append([]string(nil), c.DNSNames...)
		return nil
	}
	client.Transport = tr

	resp, err := client.Get("https://oauth2.googleapis.com/anything")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if len(seenSAN) != 1 || seenSAN[0] != "oauth2.googleapis.com" {
		t.Errorf("seen SAN = %v, want [oauth2.googleapis.com]", seenSAN)
	}
}

// TestConnectRecordsTargetHost: the span the mitm package opens around
// a CONNECT carries target.host so a trace UI can pivot on the SNI
// without reading the inner request URL.
func TestConnectRecordsTargetHost(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ca, caCertPEM := mustCA(t)
	proxy := httptest.NewServer(New(ca, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}), Options{}))
	defer proxy.Close()

	client := proxyClient(t, proxy.URL, caCertPEM)
	resp, err := client.Get("https://gmail.googleapis.com/anything")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	// Close idle conns so the kept-alive tunnel terminates before flush.
	client.CloseIdleConnections()

	if err := tp.ForceFlush(t.Context()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	spans := exporter.GetSpans()
	var seen string
	for _, s := range spans {
		for _, a := range s.Attributes {
			if string(a.Key) == AttrTargetHost {
				seen = a.Value.AsString()
			}
		}
	}
	if seen != "gmail.googleapis.com" {
		t.Errorf("target.host = %q, want gmail.googleapis.com (spans: %d)", seen, len(spans))
	}
}

// TestNonConnectOverHTTP2FallsThrough: the non-CONNECT branch is
// transparent under HTTP/2. Catches a regression that touches the
// non-CONNECT path on a typed assertion only HTTP/1 satisfies.
func TestNonConnectOverHTTP2FallsThrough(t *testing.T) {
	ca, _ := mustCA(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "h2:"+r.Proto+":"+r.URL.Path)
	})

	ts := httptest.NewUnstartedServer(New(ca, inner, Options{}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // self-signed test cert
			ForceAttemptHTTP2: true,
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get(ts.URL + "/diag")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("negotiated proto = %s, want HTTP/2", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "h2:HTTP/2.0:/diag"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestConnectOverHTTP2Returns505: a CONNECT over HTTP/2 must return
// `505 HTTP Version Not Supported` rather than the opaque 500 the
// hijack-failed path would produce. Go's transport always uses HTTP/1.1
// for the proxy hop, so the test fakes the protocol fields directly.
func TestConnectOverHTTP2Returns505(t *testing.T) {
	ca, _ := mustCA(t)
	h := New(ca, http.NotFoundHandler(), Options{})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodConnect, "/", nil)
	req.Host = "example.com:443"
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusHTTPVersionNotSupported {
		t.Errorf("status = %d, want 505", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "HTTP/1.1") {
		t.Errorf("body = %q, want one mentioning HTTP/1.1", rec.Body.String())
	}
}

// TestHTTP2UpgradeFallsBackToH1: a GET carrying h2c upgrade headers
// must be served as plain HTTP/1.1, not 101 Switching Protocols (RFC
// 7540 §3.2). Guards against a future h2c patch landing 101 responses
// without thinking through the proxy implications.
func TestHTTP2UpgradeFallsBackToH1(t *testing.T) {
	ca, _ := mustCA(t)
	var seenProto string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenProto = r.Proto
		_, _ = io.WriteString(w, "h1-response")
	})
	proxy := httptest.NewServer(New(ca, inner, Options{}))
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodGet, proxy.URL+"/diag", nil)
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
	req.Header.Set("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (server should ignore the upgrade)", resp.StatusCode)
	}
	if resp.ProtoMajor != 1 {
		t.Errorf("response proto = %s, want HTTP/1.x", resp.Proto)
	}
	if seenProto != "HTTP/1.1" {
		t.Errorf("inner handler saw proto = %q, want HTTP/1.1", seenProto)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "h1-response" {
		t.Errorf("body = %q, want h1-response", body)
	}
}

// TestConnectInnerErrorPropagates: a 500 from the inner handler reads
// back over the tunnel as a 500 with body intact.
func TestConnectInnerErrorPropagates(t *testing.T) {
	ca, caCertPEM := mustCA(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	proxy := httptest.NewServer(New(ca, inner, Options{}))
	defer proxy.Close()

	client := proxyClient(t, proxy.URL, caCertPEM)
	resp, err := client.Get("https://api.example.com/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "boom") {
		t.Errorf("body = %q, want one containing boom", body)
	}
}

// TestTunnelClosesBeforeCertExpiry: a long-lived CONNECT tunnel must
// be torn down before the leaf cert expires. Without this, a
// keep-alive tunnel outlasts the 24h leaf and reconnecting clients
// see an expired cert from the stale TLS session.
//
// The expiry timer is injected (Handler.newTimer) so the test drives
// the teardown event-style: establish a tunnel, prove it serves, fire
// the timer, and observe the server closing the connection via a
// blocked Read — no real TTL is slept out. The deadline arithmetic
// (LeafTTL - ExpiryMargin) is pinned separately by asserting the
// duration handed to the timer.
func TestTunnelClosesBeforeCertExpiry(t *testing.T) {
	ca, caCertPEM := mustCA(t)
	ca.LeafTTL = time.Hour
	ca.ExpiryMargin = 10 * time.Minute

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	})
	h := New(ca, inner, Options{})
	expire := make(chan time.Time)
	var timerDelay atomic.Int64
	h.newTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
		timerDelay.Store(int64(d))
		return expire, func() bool { return true }
	}
	proxy := httptest.NewServer(h)
	defer proxy.Close()

	// Raw CONNECT + TLS so the test owns the tunnel connection and
	// can watch it close.
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	ack, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || ack.StatusCode != 200 {
		t.Fatalf("CONNECT ack: status=%v err=%v", ack, err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}

	// The tunnel serves before the expiry fires.
	if _, err := io.WriteString(tlsConn, "GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	tbr := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(tbr, nil)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("tunnel request: status=%v err=%v", resp, err)
	}

	// The teardown deadline handed to the timer is TTL minus margin
	// (give or take the issuance instant).
	if d := time.Duration(timerDelay.Load()); d <= 40*time.Minute || d > 50*time.Minute {
		t.Errorf("timer delay = %v, want ~LeafTTL-ExpiryMargin (50m)", d)
	}

	// Fire the expiry. The server must close the tunnel; the blocked
	// Read observes it. The read deadline is a failure guard, not a
	// poll interval.
	expire <- time.Time{}
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tbr.ReadByte(); err == nil {
		t.Fatal("tunnel still serving after expiry fired; want server-side close")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("read timed out: tunnel was not closed when the expiry timer fired")
	}
}
