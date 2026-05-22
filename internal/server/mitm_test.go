package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/server/mitm"
)

// TestMITMUnmodifiedClient exercises the unmodified-client claim:
// an http.Client pointed at the proxy via HTTPS_PROXY, with the
// MITM CA installed as a trusted root, can refresh and call the
// data plane without ever knowing the proxy's URL. The request
// URLs are the real Google ones; the proxy intercepts both.
//
// Flow:
//
//  1. POST https://oauth2.googleapis.com/token  → mitm intercepts,
//     /token handler exchanges with the stub upstream, returns a
//     fresh access JWT.
//  2. GET  https://gmail.googleapis.com/gmail/... with that JWT →
//     mitm intercepts, chi matches the /gmail prefix, proxy
//     forwards to the stub upstream with the embedded access
//     token swapped into Authorization.
func TestMITMUnmodifiedClient(t *testing.T) {
	var seenAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_, _ = io.WriteString(w, `{"access_token":"upstream-fresh","expires_in":3600}`)
		default:
			seenAuth = r.Header.Get("Authorization")
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})

	caCertPEM, caKeyPEM, err := mitm.GenerateCAForTest()
	if err != nil {
		t.Fatalf("GenerateCAForTest: %v", err)
	}
	ca, err := mitm.CAFromPEM(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("CAFromPEM: %v", err)
	}
	proxy := httptest.NewServer(mitm.New(ca, srv.Router(), mitm.Options{}))
	defer proxy.Close()

	client := newProxyClient(t, proxy.URL, caCertPEM)

	// Refresh JWT carries the *real* upstream URL — the proxy
	// uses it for outbound /token calls regardless of which URL
	// the client posted to.
	refresh, err := auth.IssueRefreshToken(keys, "agent-mitm", auth.RefreshCreds{
		RefreshToken: "rt-original",
		TokenURL:     upstream.URL + "/token",
	}, 0, false)
	if err != nil {
		t.Fatalf("issue refresh: %v", err)
	}

	// Step 1: POST to the *Google* token URL through HTTPS_PROXY.
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	form.Set("client_id", "client-id")
	form.Set("client_secret", "client-secret")
	resp, err := client.Post(
		"https://oauth2.googleapis.com/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("token post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status = %d, body = %s", resp.StatusCode, body)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Step 2: data-plane GET against the *Google* gmail host.
	req, _ := http.NewRequest("GET", "https://gmail.googleapis.com/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	used, err := client.Do(req)
	if err != nil {
		t.Fatalf("data plane: %v", err)
	}
	defer used.Body.Close()
	if used.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(used.Body)
		t.Fatalf("data plane status = %d, body = %s", used.StatusCode, body)
	}
	if !strings.Contains(seenAuth, "upstream-fresh") {
		t.Errorf("upstream auth = %q, want bearer upstream-fresh", seenAuth)
	}
}

// newProxyClient returns an http.Client routed through proxyURL
// (an HTTP proxy) with the test CA installed as a trusted root.
// Centralised so individual e2e tests stay focused on the flow.
func newProxyClient(t *testing.T, proxyURL string, caPEM []byte) *http.Client {
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
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
}
