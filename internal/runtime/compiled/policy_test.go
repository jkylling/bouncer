package compiled

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// permitPolicy returns a minimal Policy source with the given
// principal predicate. Action and condition default to the empty
// "matches everything" form so each test focuses on the principal
// gate alone.
func permitPolicy(principal string) *models.Policy {
	return &models.Policy{
		API:       "google.mail",
		Name:      "p",
		Principal: principal,
		Action:    "",
		Condition: "true",
		Result:    models.Permit,
	}
}

func policyForTest(t *testing.T, src *models.Policy) *Policy {
	t.Helper()
	reg := messages.NewRegistry()
	require.NoError(t, reg.Register(&messages.Type{
		FullName:     "google.mail.message",
		InputFields:  []string{"id"},
		OutputFields: []string{"sender"},
	}))
	p, err := NewPolicy(src, "google.mail", reg)
	require.NoError(t, err)
	return p
}

func TestPolicyAppliesToPrincipalEmptySource(t *testing.T) {
	p := policyForTest(t, permitPolicy(""))

	got, err := p.AppliesToPrincipal(&pb.Request{}, &pb.Principal{Subject: "anyone"}, testNow)
	require.NoError(t, err)
	assert.True(t, got, "empty principal: must match every caller")
}

func TestPolicyAppliesToPrincipalSubjectMatch(t *testing.T) {
	p := policyForTest(t, permitPolicy(`principal.subject == "agent-1"`))

	got, err := p.AppliesToPrincipal(&pb.Request{}, &pb.Principal{Subject: "agent-1"}, testNow)
	require.NoError(t, err)
	assert.True(t, got)
}

func TestPolicyAppliesToPrincipalSubjectMismatch(t *testing.T) {
	p := policyForTest(t, permitPolicy(`principal.subject == "agent-1"`))

	got, err := p.AppliesToPrincipal(&pb.Request{}, &pb.Principal{Subject: "agent-2"}, testNow)
	require.NoError(t, err)
	assert.False(t, got)
}
