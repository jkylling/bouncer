package auth

import "context"

// Role is the privilege tier the auth middleware promotes a verified
// JWT into. Distinct from pb.Principal (which models the policy-eval
// caller); Role gates access to the admin/control-plane HTTP
// surface, not request-evaluation logic.
type Role int

const (
	// RoleAnonymous is the no-JWT (or unverified-JWT) tier. Open
	// endpoints serve it; everything else rejects it.
	RoleAnonymous Role = iota

	// RoleUser is a verified, non-admin JWT. May read its own
	// resources; cannot read across subjects or mutate
	// operator-controlled state.
	RoleUser

	// RoleAdmin is a verified JWT carrying `admin: true`. Full
	// read/write across subjects.
	RoleAdmin
)

// Caller is the verified identity attached to an inbound
// admin/control-plane request. Subject mirrors the JWT `sub`; Role
// is the promoted privilege tier. An anonymous Caller has Subject="".
type Caller struct {
	Subject string
	Role    Role
}

// IsAdmin reports whether the caller holds the admin tier.
func (c Caller) IsAdmin() bool { return c.Role == RoleAdmin }

// IsAuthenticated reports whether the caller has a verified JWT
// (admin or user). Useful for endpoints that gate on "any logged-in
// caller" without distinguishing the tier.
func (c Caller) IsAuthenticated() bool { return c.Role != RoleAnonymous }

// callerCtxKey is unexported so external packages can only read or
// write the Caller via WithCaller / CallerFromContext. Distinct
// type per Go context-key convention.
type callerCtxKey struct{}

// WithCaller returns ctx with c stashed under the package's private
// context key. The auth middleware calls this once per request
// after verifying the JWT (or as the anonymous default).
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerCtxKey{}, c)
}

// CallerFromContext returns the Caller stashed by WithCaller, or the
// anonymous Caller when none is present. Use IsAuthenticated to gate
// on a verified JWT — the "no middleware ran" and "middleware ran,
// caller was anonymous" cases share the same zero value.
func CallerFromContext(ctx context.Context) Caller {
	if c, ok := ctx.Value(callerCtxKey{}).(Caller); ok {
		return c
	}
	return Caller{}
}
