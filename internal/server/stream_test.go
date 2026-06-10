package server

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// streamingUpstream returns an httptest upstream that writes chunks
// at the given interval, flushing each one — the shape of an SSE /
// LLM token stream.
func streamingUpstream(t *testing.T, chunks []string, interval time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream recorder is not a Flusher")
			return
		}
		for i, c := range chunks {
			if i > 0 {
				time.Sleep(interval)
			}
			_, _ = io.WriteString(w, c)
			f.Flush()
		}
	}))
}

// streamingProxyGet issues an authorized GET for the permitted gmail
// path through proxy and returns the response. Callers own Body.Close.
func streamingProxyGet(t *testing.T, proxyURL, jwt string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", proxyURL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// TestForwardFlushesStreamedChunks pins the relay contract for
// streaming upstreams: a chunk the upstream flushed must reach the
// client while the upstream response is still open, not when the
// handler returns. The upstream blocks after its first chunk until
// the client has observed it — without per-chunk flushing in forward
// this deadlocks (caught by the watchdog timeout).
func TestForwardFlushesStreamedChunks(t *testing.T) {
	clientGotFirst := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-clientGotFirst:
		case <-time.After(5 * time.Second):
			t.Error("client never observed the first chunk")
			return
		}
		_, _ = io.WriteString(w, "second\n")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp := streamingProxyGet(t, proxy.URL, issueJWT(t, keys, "tok"))
	defer resp.Body.Close()

	lines := make(chan string, 2)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	select {
	case first := <-lines:
		if first != "first" {
			t.Fatalf("first chunk = %q, want %q", first, "first")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first chunk was not flushed through the proxy before the upstream finished")
	}
	close(clientGotFirst)
	if second := <-lines; second != "second" {
		t.Fatalf("second chunk = %q, want %q", second, "second")
	}
}

// TestForwardStreamOutlivesWriteTimeout pins the per-chunk write
// deadline extension: a stream whose total duration exceeds the
// listener's WriteTimeout survives as long as chunks keep flowing
// faster than StreamIdleTimeout. Without the extension the absolute
// deadline kills the connection mid-stream and the client sees a
// truncated body.
func TestForwardStreamOutlivesWriteTimeout(t *testing.T) {
	chunks := []string{"a", "b", "c", "d", "e"}
	// 5 chunks × 150ms ≈ 600ms total, against a 300ms WriteTimeout.
	upstream := streamingUpstream(t, chunks, 150*time.Millisecond)
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{
		Runtime:           rt,
		Keys:              keys,
		HTTPClient:        upstream.Client(),
		APIFactory:        gmailFactory,
		StreamIdleTimeout: 300 * time.Millisecond,
	})
	proxy := httptest.NewUnstartedServer(srv.Router())
	proxy.Config.WriteTimeout = 300 * time.Millisecond
	proxy.Start()
	defer proxy.Close()

	resp := streamingProxyGet(t, proxy.URL, issueJWT(t, keys, "tok"))
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streamed body: %v (stream cut by WriteTimeout?)", err)
	}
	if got, want := string(body), strings.Join(chunks, ""); got != want {
		t.Fatalf("body = %q, want %q (truncated by WriteTimeout)", got, want)
	}
}

// TestForwardStreamOutlivesMetaClientTimeout pins the client split:
// the forward path must not run on the meta-call client, whose
// Client.Timeout covers reading the whole response body and would
// cut any stream longer than the per-call budget.
func TestForwardStreamOutlivesMetaClientTimeout(t *testing.T) {
	chunks := []string{"a", "b", "c", "d"}
	upstream := streamingUpstream(t, chunks, 100*time.Millisecond)
	defer upstream.Close()

	// upstream.Client() returns one shared instance — build two
	// distinct clients over its transport so the Timeout below only
	// lands on the meta client.
	metaClient := &http.Client{Transport: upstream.Client().Transport, Timeout: 150 * time.Millisecond} // would cut the ~300ms stream
	forwardClient := &http.Client{Transport: upstream.Client().Transport}

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{
		Runtime:       rt,
		Keys:          keys,
		HTTPClient:    metaClient,
		ForwardClient: forwardClient,
		APIFactory:    gmailFactory,
	})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	resp := streamingProxyGet(t, proxy.URL, issueJWT(t, keys, "tok"))
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streamed body: %v (forward ran on the meta client?)", err)
	}
	if got, want := string(body), strings.Join(chunks, ""); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}
