package mcp

import (
	"encoding/json"
	"testing"
)

func TestPromptsListIsEmpty(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "prompts/list", nil)
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	var got listPromptsResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	if len(got.Prompts) != 0 {
		t.Errorf("expected empty prompt list, got %+v", got.Prompts)
	}
}

func TestPromptsGetUnknownNameReturnsInvalidParams(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "prompts/get", map[string]any{"name": "no-such-prompt"})
	if resp.Error == nil {
		t.Fatal("want error for unknown prompt, got nil")
	}
	if resp.Error.Code != codeInvalidParams {
		t.Errorf("code = %d, want %d", resp.Error.Code, codeInvalidParams)
	}
}
