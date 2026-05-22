package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteDenialEmitsNextSteps pins the denial body contract:
// every access error carries the four discovery URLs as relative
// paths on the same proxy origin.
func TestWriteDenialEmitsNextSteps(t *testing.T) {
	w := httptest.NewRecorder()
	WriteDenial(w, http.StatusForbidden, "policy denied this request")

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got DenialResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Error != "Forbidden" || got.Message == "" {
		t.Errorf("got %+v, want Error=Forbidden + non-empty Message", got)
	}
	if got.NextSteps.SupportedAPIs != APIsPath {
		t.Errorf("supported_apis = %q, want %q", got.NextSteps.SupportedAPIs, APIsPath)
	}
	if got.NextSteps.Policies != PoliciesPath {
		t.Errorf("policies = %q", got.NextSteps.Policies)
	}
	if got.NextSteps.Docs != DocsPath {
		t.Errorf("docs = %q", got.NextSteps.Docs)
	}
	if got.NextSteps.DocsPolicies != DocsPoliciesPath {
		t.Errorf("docs_policies = %q, want %q", got.NextSteps.DocsPolicies, DocsPoliciesPath)
	}
	if got.API != "" || len(got.MatchedActions) != 0 {
		t.Errorf("plain WriteDenial leaked api/matched_actions: %+v", got)
	}
}
