package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInitializeReturnsServerInfo(t *testing.T) {
	ts, keys, _, _ := testServer(t)
	resp := rpc(t, ts.URL, issueAccess(t, keys, false), "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
	})
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	var got initializeResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	if got.ServerInfo.Name != ServerName {
		t.Errorf("serverInfo.name = %q, want %q", got.ServerInfo.Name, ServerName)
	}
	if got.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocolVersion = %q, want %q", got.ProtocolVersion, ProtocolVersion)
	}
	if got.Instructions == "" {
		t.Fatalf("empty instructions")
	}
	for _, needle := range []string{"Bouncer", "/_admin/tokens", "Common errors"} {
		if !strings.Contains(got.Instructions, needle) {
			t.Errorf("instructions missing %q:\n%s", needle, got.Instructions)
		}
	}
}
