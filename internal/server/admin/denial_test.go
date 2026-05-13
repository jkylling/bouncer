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

// TestWriteDenialDetailIncludesAPIAndActions pins the policy-deny
// body contract: when the data plane denies a request, the body
// surfaces the matched API and the action names whose match logic
// fired so the agent can draft a permitting policy without a
// separate GET /_api/apis round-trip.
func TestWriteDenialDetailIncludesAPIAndActions(t *testing.T) {
	w := httptest.NewRecorder()
	WriteDenialDetail(w, http.StatusForbidden, "policy denied this request",
		"google.gmail", []string{"get_message", "modify_message"})

	var got DenialResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.API != "google.gmail" {
		t.Errorf("api = %q, want gmail", got.API)
	}
	want := []string{"get_message", "modify_message"}
	if len(got.MatchedActions) != len(want) {
		t.Fatalf("matched_actions = %v, want %v", got.MatchedActions, want)
	}
	for i, a := range want {
		if got.MatchedActions[i] != a {
			t.Errorf("matched_actions[%d] = %q, want %q", i, got.MatchedActions[i], a)
		}
	}
}
