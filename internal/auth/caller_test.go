package auth

import (
	"context"
	"testing"
)

func TestCallerRoleHelpers(t *testing.T) {
	cases := []struct {
		name      string
		caller    Caller
		wantAdmin bool
		wantAuth  bool
	}{
		{"anonymous", Caller{}, false, false},
		{"user", Caller{Subject: "u", Role: RoleUser}, false, true},
		{"admin", Caller{Subject: "a", Role: RoleAdmin}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.caller.IsAdmin(); got != tc.wantAdmin {
				t.Errorf("IsAdmin = %v, want %v", got, tc.wantAdmin)
			}
			if got := tc.caller.IsAuthenticated(); got != tc.wantAuth {
				t.Errorf("IsAuthenticated = %v, want %v", got, tc.wantAuth)
			}
		})
	}
}

func TestCallerContextRoundtrip(t *testing.T) {
	in := Caller{Subject: "alice", Role: RoleAdmin}
	ctx := WithCaller(context.Background(), in)
	got := CallerFromContext(ctx)
	if got != in {
		t.Errorf("got %+v, want %+v", got, in)
	}
}

func TestCallerContextDefaultsToAnonymous(t *testing.T) {
	got := CallerFromContext(context.Background())
	if got.IsAuthenticated() {
		t.Errorf("default = %+v, want anonymous", got)
	}
}
