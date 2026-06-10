// Package tokens contains the in-process token-issue primitives
// shared by the admin HTTP endpoints (POST /_api/tokens/issue and
// /_api/tokens/issue/refresh) and cmd/issue-token.
//
// Two flavours:
//
//   - `Spec` + `Issue` wrap an upstream access token in a short-lived
//     access JWT. JSON tags match the file `issue-token --access-token`
//     reads, so a payload posted to /_api/tokens/issue can also be the
//     CLI's input.
//   - `RefreshSpec` + `IssueRefresh` wrap an upstream refresh token in
//     a refresh JWT. The CLI's credentials-file mode also writes the
//     resulting JWT into a Google-shaped credentials.json — that
//     bundling lives in cmd/issue-token, not here. The /token data-
//     plane endpoint issues fresh access JWTs from the refresh JWT
//     during normal operation; this package's IssueRefresh is just the
//     bootstrap-side primitive.
package tokens

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/observability"
)

// tracerName identifies the otel instrumentation library for spans
// emitted by this package. Derived from the package import path so a
// rename or move surfaces in collector UIs without a hand-edit.
var tracerName = observability.PackagePath()

// Spec is the issue-token input shape. JSON tags double as the wire
// and on-disk format so a payload posted to /_api/tokens/issue can
// also be the file `issue-token --access-spec` reads.
//
// Refresh-token-bearing JWTs are *not* issued here — see the package
// doc. Spec carries only the access-token shape.
//
// Admin marks the issued JWT as authorised for admin/control-plane
// endpoints. The issue endpoint requires the *caller* to already be
// admin (the auth middleware gates it), so a non-admin cannot
// escalate to admin via this surface.
//
// At least one of AccessToken / Headers must be supplied — a Spec
// with neither would issue a token the proxy refuses on first use
// (no upstream credential to forward). Cookies belong in Headers as
// `Cookie: name=value; name2=value2` rows.
type Spec struct {
	Subject     string        `json:"subject"`
	AccessToken string        `json:"access_token,omitempty"`
	Headers     []auth.Header `json:"headers,omitempty"`
	TTLSeconds  int64         `json:"ttl_seconds"`
	Admin       bool          `json:"admin,omitempty"`
}

// Validate checks the cross-field shape invariants
// `auth.IssueAccessToken` does not. The verifier accepts any
// AccessCreds; a token issued with no credential material is valid
// for surfaces that don't forward upstream (e.g. the MCP control
// plane at /_api/mcp). The proxy's data-plane path still refuses to
// forward such a JWT with a clear "no upstream credential" error,
// turning "issue succeeds, forward fails" into a single understandable
// failure rather than a silent denial.
func (s *Spec) Validate() error {
	if s.Subject == "" {
		return errors.New("subject required")
	}
	for i, h := range s.Headers {
		if h.Name == "" || h.Value == "" {
			return fmt.Errorf("headers[%d]: name and value are required", i)
		}
	}
	if s.TTLSeconds <= 0 {
		return errors.New("ttl_seconds must be positive")
	}
	return nil
}

// Result is what Issue returns: the signed JWT and the wall-clock time
// at which it expires. Callers shape their response/output around
// this — the HTTP handler JSON-encodes it, the CLI prints the token
// and surfaces the expiry separately.
type Result struct {
	Token     string
	ExpiresAt time.Time
}

// ErrInvalidSpec wraps every Spec.Validate() failure Issue returns.
// It lets callers distinguish caller-fault errors (return 400 / exit
// with usage) from internal issue-time failures (return 500 / log
// and abort) without sniffing the error string.
var ErrInvalidSpec = errors.New("invalid spec")

// Issue validates the spec and issues a signed+encrypted access JWT
// against keys. ExpiresAt is computed from "now" so two calls in a
// row with the same spec do not collide.
//
// Validate failures are wrapped with `ErrInvalidSpec` (caller fault);
// IssueAccessToken failures are returned unwrapped (internal fault).
//
// ctx is used for span propagation (the operation itself does no IO),
// so an issue triggered from an HTTP handler shows up as a child span
// of the inbound request.
func Issue(ctx context.Context, keys *auth.ServerKeys, spec *Spec) (*Result, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "tokens.issue")
	defer span.End()

	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSpec, err.Error())
	}
	span.SetAttributes(
		attribute.String("proxy.subject", spec.Subject),
		attribute.Int64("token.ttl_seconds", spec.TTLSeconds),
	)
	ttl := time.Duration(spec.TTLSeconds) * time.Second
	now := time.Now()
	tok, err := auth.IssueAccessToken(keys, spec.Subject, auth.AccessCreds{
		AccessToken: spec.AccessToken,
		Headers:     spec.Headers,
	}, ttl, spec.Admin)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("issue token: %w", err)
	}
	return &Result{Token: tok, ExpiresAt: now.Add(ttl)}, nil
}

// RefreshSpec is the refresh-issue input. JSON tags double as the
// wire shape so an admin POST to /_api/tokens/issue/refresh can be mirrored
// on disk if a future CLI surface wants to read a freeform spec.
//
// TokenURL is the upstream OAuth2 token endpoint (e.g.
// https://oauth2.googleapis.com/token); it rides inside the refresh
// JWT so a Google refresh JWT and a Microsoft refresh JWT are
// interchangeable as far as the proxy is concerned.
//
// TTLSeconds == 0 issues a non-expiring refresh JWT — the default for
// long-lived bootstrap credentials. Operators that want a time-bound
// refresh pass a positive value (matching `issue-token --refresh-ttl`).
type RefreshSpec struct {
	Subject      string        `json:"subject"`
	RefreshToken string        `json:"refresh_token"`
	TokenURL     string        `json:"token_url"`
	Headers      []auth.Header `json:"headers,omitempty"`
	TTLSeconds   int64         `json:"ttl_seconds,omitempty"`
	Admin        bool          `json:"admin,omitempty"`
}

// Validate checks the cross-field invariants. TTL is allowed to be 0
// (= no expiry) — this matches auth.IssueRefreshToken's contract.
// Headers ride through the rotation onto every issued access JWT,
// so the same per-row name/value rules as Spec apply here.
func (s *RefreshSpec) Validate() error {
	if s.Subject == "" {
		return errors.New("subject required")
	}
	if s.RefreshToken == "" {
		return errors.New("refresh_token required")
	}
	if s.TokenURL == "" {
		return errors.New("token_url required")
	}
	for i, h := range s.Headers {
		if h.Name == "" || h.Value == "" {
			return fmt.Errorf("headers[%d]: name and value are required", i)
		}
	}
	if s.TTLSeconds < 0 {
		return errors.New("ttl_seconds must be non-negative")
	}
	return nil
}

// IssueRefresh validates the spec and issues a signed+encrypted
// refresh JWT. ExpiresAt mirrors the JWT's exp claim — the zero time
// for a non-expiring token (TTLSeconds == 0).
//
// Same error split as Issue: Validate failures wrap `ErrInvalidSpec`
// (caller fault), IssueRefreshToken failures are returned unwrapped.
func IssueRefresh(ctx context.Context, keys *auth.ServerKeys, spec *RefreshSpec) (*Result, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "tokens.issue_refresh")
	defer span.End()

	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSpec, err.Error())
	}
	span.SetAttributes(
		attribute.String("proxy.subject", spec.Subject),
		attribute.Int64("token.ttl_seconds", spec.TTLSeconds),
	)
	ttl := time.Duration(spec.TTLSeconds) * time.Second
	now := time.Now()
	tok, err := auth.IssueRefreshToken(keys, spec.Subject, auth.RefreshCreds{
		RefreshToken: spec.RefreshToken,
		TokenURL:     spec.TokenURL,
		Headers:      spec.Headers,
	}, ttl, spec.Admin)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("issue refresh: %w", err)
	}
	res := &Result{Token: tok}
	if ttl > 0 {
		res.ExpiresAt = now.Add(ttl)
	}
	return res, nil
}
