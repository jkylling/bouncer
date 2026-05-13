package mcp

import (
	"testing"
)

// proposePayload is the JSON shape the policy_input schema accepts.
// Used by the three propose_policy tests below.
func proposePayload(name string) map[string]any {
	return map[string]any{
		"api":       "stub",
		"name":      name,
		"action":    "true",
		"condition": "true",
		"result":    "permit",
	}
}

func TestProposePolicyNonAdminReturnsDraft(t *testing.T) {
	ts, keys, _, _ := testServer(t)

	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name":      "propose_policy",
		"arguments": proposePayload("from-non-admin"),
	})
	body := toolText(t, resp)

	if body["ok"] != true {
		t.Errorf("ok = %v, want true: %v", body["ok"], body)
	}
	if body["applied"] != false {
		t.Errorf("applied = %v, want false: %v", body["applied"], body)
	}
	if _, ok := body["policy"]; !ok {
		t.Errorf("policy missing from response: %v", body)
	}
	if msg, _ := body["message"].(string); msg == "" {
		t.Errorf("message empty: %v", body)
	}
}

func TestProposePolicyAdminAppliesPolicy(t *testing.T) {
	ts, keys, _, policySvc := testServer(t)

	resp := rpc(t, ts.URL, issueAccess(t, keys, true), "tools/call", map[string]any{
		"name":      "propose_policy",
		"arguments": proposePayload("from-admin"),
	})
	body := toolText(t, resp)

	if body["ok"] != true || body["applied"] != true {
		t.Errorf("ok/applied = %v/%v, want true/true: %v", body["ok"], body["applied"], body)
	}
	if _, err := policySvc.Get("stub", "from-admin"); err != nil {
		t.Errorf("policy not persisted in live runtime: %v", err)
	}
}

func TestProposePolicyInvalidReturnsError(t *testing.T) {
	ts, keys, _, _ := testServer(t)

	bad := proposePayload("invalid")
	bad["condition"] = "this is not valid CEL ((("

	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "tools/call", map[string]any{
		"name":      "propose_policy",
		"arguments": bad,
	})
	body := toolText(t, resp)

	if body["ok"] != false {
		t.Errorf("ok = %v, want false: %v", body["ok"], body)
	}
	if errMsg, _ := body["error"].(string); errMsg == "" {
		t.Errorf("error message missing: %v", body)
	}
	if body["applied"] == true {
		t.Errorf("applied should be false on invalid input: %v", body)
	}
}

func TestProposePolicyConflictNotApplied(t *testing.T) {
	ts, keys, _, _ := testServer(t)

	// First admin call lands the policy.
	rpc(t, ts.URL, issueAccess(t, keys, true), "tools/call", map[string]any{
		"name":      "propose_policy",
		"arguments": proposePayload("dup"),
	})
	// Second call (any role) hits the conflict path.
	resp := rpc(t, ts.URL, issueAccess(t, keys, true), "tools/call", map[string]any{
		"name":      "propose_policy",
		"arguments": proposePayload("dup"),
	})
	body := toolText(t, resp)

	if body["ok"] != true {
		t.Errorf("ok = %v, want true (validation passed): %v", body["ok"], body)
	}
	if body["applied"] != false {
		t.Errorf("applied = %v, want false on conflict: %v", body["applied"], body)
	}
	if msg, _ := body["message"].(string); msg == "" {
		t.Errorf("conflict message missing: %v", body)
	}
}
