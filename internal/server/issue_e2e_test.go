package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/tokens"
	"github.com/jkylling/bouncer/internal/server/admin"
)

// TestIssueTokenIsUsableByProxy is the cross-package end-to-end pin:
// a token issued via /_api/issue/tokens (admin package) authenticates
// a subsequent proxy call (server package) without any out-of-band
// issuance step. Catches a regression where the encrypted `enc`
// claim's wire format diverges between issue and verify on the same
// listener, and indirectly that admin.MountOn wires both halves to
// the same keys.
func TestIssueTokenIsUsableByProxy(t *testing.T) {
	var seenAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	rt := loadGmailRuntime(t, upstream.URL)
	keys := mustKeys(t)
	srv := NewServer(Dependencies{Runtime: rt, Keys: keys, HTTPClient: upstream.Client(), APIFactory: gmailFactory})
	proxy := httptest.NewServer(srv.Router())
	defer proxy.Close()

	// Bootstrap: issue an admin JWT against the same keys so the
	// /_api/issue/tokens call below — now admin-tier — is allowed.
	adminJWT, err := auth.IssueAccessToken(keys, "test-admin",
		auth.AccessCreds{AccessToken: "x"}, time.Hour, true)
	if err != nil {
		t.Fatalf("issue admin: %v", err)
	}

	body, _ := json.Marshal(tokens.Spec{
		Subject:     "agent-e2e",
		AccessToken: "issued-bearer",
		TTLSeconds:  60,
	})
	issueReq, _ := http.NewRequest(http.MethodPost, proxy.URL+admin.IssuePath, bytes.NewReader(body))
	issueReq.Header.Set("Content-Type", "application/json")
	issueReq.Header.Set("Authorization", "Bearer "+adminJWT)
	resp, err := http.DefaultClient.Do(issueReq)
	if err != nil {
		t.Fatalf("issue post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("issue: status = %d, body = %s", resp.StatusCode, raw)
	}
	var issued admin.IssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		t.Fatalf("decode: %v", err)
	}

	req, _ := http.NewRequest("GET", proxy.URL+"/gmail/v1/users/42/messages/abc", nil)
	req.Header.Set("Authorization", "Bearer "+issued.Token)
	used, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy call: %v", err)
	}
	defer used.Body.Close()
	if used.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(used.Body)
		t.Fatalf("proxy status = %d, body = %s", used.StatusCode, raw)
	}
	if !strings.Contains(seenAuth, "issued-bearer") {
		t.Errorf("upstream auth = %q, want bearer issued-bearer", seenAuth)
	}
}
