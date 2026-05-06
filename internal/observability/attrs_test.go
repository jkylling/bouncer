package observability

import "testing"

// TestAttributeKeys pins the wire strings emitted as span attribute
// keys. Renaming any of these silently breaks dashboards and queries
// downstream, so the assertion guards against an accidental edit.
func TestAttributeKeys(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{string(APIName("x").Key), "api.name"},
		{string(PolicyDecision("x").Key), "policy.decision"},
		{string(Subject("x").Key), "proxy.subject"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("key = %q, want %q", tc.got, tc.want)
		}
	}
}
