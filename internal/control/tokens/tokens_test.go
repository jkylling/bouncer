package tokens

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/auth"
)

func mustKeys(t *testing.T) *auth.ServerKeys {
	t.Helper()
	keys, err := auth.FromSecret(auth.DevStubSecret())
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}
	return keys
}

func TestIssueRoundTrips(t *testing.T) {
	keys := mustKeys(t)
	res, err := Issue(context.Background(), keys, &Spec{
		Subject:     "agent-1",
		AccessToken: "ya29-fake",
		TTLSeconds:  60,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.Token == "" {
		t.Fatal("token empty")
	}
	if d := time.Until(res.ExpiresAt); d < 30*time.Second || d > 2*time.Minute {
		t.Errorf("ExpiresAt = %v (~%v from now)", res.ExpiresAt, d)
	}
	tok, err := auth.VerifyAccessToken(keys, res.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok.Subject != "agent-1" {
		t.Errorf("Subject = %q", tok.Subject)
	}
	if tok.Creds.AccessToken != "ya29-fake" {
		t.Errorf("AccessToken = %q", tok.Creds.AccessToken)
	}
}

// TestIssueCarriesHeaders pins the new credential surface: a Spec
// with Headers (and no AccessToken) round-trips the bundle through
// the JWT so the forward path can stamp the headers on outbound
// requests. Cookies ride here too — as a `Cookie` row.
func TestIssueCarriesHeaders(t *testing.T) {
	keys := mustKeys(t)
	res, err := Issue(context.Background(), keys, &Spec{
		Subject: "agent-3",
		Headers: []auth.Header{
			{Name: "X-API-Key", Value: "k1"},
			{Name: "Cookie", Value: "d=xoxd-fake"},
		},
		TTLSeconds: 60,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tok, err := auth.VerifyAccessToken(keys, res.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok.Creds.AccessToken != "" {
		t.Errorf("AccessToken = %q, want empty", tok.Creds.AccessToken)
	}
	if len(tok.Creds.Headers) != 2 {
		t.Fatalf("Headers = %+v", tok.Creds.Headers)
	}
	if tok.Creds.Headers[0].Name != "X-API-Key" {
		t.Errorf("Headers[0] = %+v", tok.Creds.Headers[0])
	}
	if tok.Creds.Headers[1].Name != "Cookie" || tok.Creds.Headers[1].Value != "d=xoxd-fake" {
		t.Errorf("Headers[1] = %+v", tok.Creds.Headers[1])
	}
}

func TestIssueRefreshRoundTrips(t *testing.T) {
	keys := mustKeys(t)
	res, err := IssueRefresh(context.Background(), keys, &RefreshSpec{
		Subject:      "agent-2",
		RefreshToken: "1//rt-fake",
		TokenURL:     "https://oauth2.googleapis.com/token",
		TTLSeconds:   3600,
	})
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	if res.Token == "" {
		t.Fatal("token empty")
	}
	if d := time.Until(res.ExpiresAt); d < 30*time.Minute || d > 90*time.Minute {
		t.Errorf("ExpiresAt = %v (~%v from now)", res.ExpiresAt, d)
	}
	tok, err := auth.VerifyRefreshToken(keys, res.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok.Subject != "agent-2" {
		t.Errorf("Subject = %q", tok.Subject)
	}
	if tok.Creds.RefreshToken != "1//rt-fake" {
		t.Errorf("RefreshToken = %q", tok.Creds.RefreshToken)
	}
	if tok.Creds.TokenURL != "https://oauth2.googleapis.com/token" {
		t.Errorf("TokenURL = %q", tok.Creds.TokenURL)
	}
}

func TestIssueRefreshNoExpiry(t *testing.T) {
	keys := mustKeys(t)
	res, err := IssueRefresh(context.Background(), keys, &RefreshSpec{
		Subject:      "agent-3",
		RefreshToken: "rt",
		TokenURL:     "https://x",
		// TTLSeconds 0 → non-expiring; Result.ExpiresAt is the zero time.
	})
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	if !res.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero", res.ExpiresAt)
	}
}

func TestRefreshSpecValidate(t *testing.T) {
	cases := []struct {
		name string
		spec RefreshSpec
		want string
	}{
		{
			name: "missing_subject",
			spec: RefreshSpec{RefreshToken: "rt", TokenURL: "https://x"},
			want: "subject required",
		},
		{
			name: "missing_refresh_token",
			spec: RefreshSpec{Subject: "s", TokenURL: "https://x"},
			want: "refresh_token required",
		},
		{
			name: "missing_token_url",
			spec: RefreshSpec{Subject: "s", RefreshToken: "rt"},
			want: "token_url required",
		},
		{
			name: "negative_ttl",
			spec: RefreshSpec{Subject: "s", RefreshToken: "rt", TokenURL: "https://x", TTLSeconds: -1},
			want: "ttl_seconds must be non-negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if err == nil {
				t.Fatalf("Validate: expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestSpecValidate(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{
			name: "missing_subject",
			spec: Spec{TTLSeconds: 60, AccessToken: "x"},
			want: "subject required",
		},
		{
			name: "zero_ttl",
			spec: Spec{Subject: "s", AccessToken: "x"},
			want: "ttl_seconds must be positive",
		},
		{
			name: "no_credential_material",
			spec: Spec{Subject: "s", TTLSeconds: 60},
			want: "at least one of access_token or headers is required",
		},
		{
			name: "header_missing_value",
			spec: Spec{Subject: "s", TTLSeconds: 60, Headers: []auth.Header{{Name: "X"}}},
			want: "headers[0]: name and value are required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if err == nil {
				t.Fatalf("Validate: expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}
