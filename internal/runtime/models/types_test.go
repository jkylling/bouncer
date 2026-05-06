package models

import (
	"strings"
	"testing"
)

func TestPolicyResultValidate(t *testing.T) {
	cases := []struct {
		name    string
		input   PolicyResult
		wantErr string // "" means no error expected
	}{
		{name: "permit", input: Permit},
		{name: "deny", input: Deny},
		{name: "empty", input: "", wantErr: "required"},
		{name: "typo", input: "dney", wantErr: `"dney"`},
		{name: "wrong_case", input: "Permit", wantErr: `"Permit"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}
