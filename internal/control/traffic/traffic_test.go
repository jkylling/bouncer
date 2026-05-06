package traffic

import "testing"

// TestClampLimit pins the default + max policy ClampLimit applies on
// every store's List path. Hostile clients can't scan the whole table
// in one request, and a zero-valued ListOpts gets a usable default.
func TestClampLimit(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"zero falls back to default", 0, DefaultListLimit},
		{"negative falls back to default", -1, DefaultListLimit},
		{"in range identity", 50, 50},
		{"at max identity", MaxListLimit, MaxListLimit},
		{"above max clamps", MaxListLimit + 1, MaxListLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClampLimit(tc.in); got != tc.want {
				t.Errorf("ClampLimit(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
