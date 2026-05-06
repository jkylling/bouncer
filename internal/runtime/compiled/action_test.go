package compiled

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/messages"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// metaFor constructs a fixture Meta wired against the registry from
// fixtureRegistry — enough for Action tests that just need a key in
// the metas map.
func metaFor(t *testing.T, reg *messages.Registry, fullName string) *Meta {
	t.Helper()
	typ, ok := reg.Get(fullName)
	if !ok {
		t.Fatalf("registry missing %q", fullName)
	}
	return &Meta{APIName: "google.mail", Type: typ}
}

// TestNewActionRejectsBindAndBindsTogether pins finding 1 (mutual
// exclusivity).
func TestNewActionRejectsBindAndBindsTogether(t *testing.T) {
	reg, _ := fixtureRegistry(t)
	a := &models.Action{
		Name:   "mixed",
		Method: "GET",
		Path:   "/mail/{id}",
		Bind:   "google.mail.message{id: match.id}",
		Binds:  []models.CelExpression{"google.mail.message{id: match.id}"},
	}
	_, err := NewAction(a, "google.mail", reg, map[string]*Meta{
		"google.mail.message": metaFor(t, reg, "google.mail.message"),
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v", err)
	}
}

// TestNewActionRejectsNoTemplateNoFilter pins the "must specify
// method+path, filter, or both" rejection.
func TestNewActionRejectsNoTemplateNoFilter(t *testing.T) {
	reg, _ := fixtureRegistry(t)
	a := &models.Action{Name: "bare"}
	_, err := NewAction(a, "google.mail", reg, nil)
	if err == nil || !strings.Contains(err.Error(), "must specify") {
		t.Fatalf("err = %v", err)
	}
}

// TestNewActionRejectsUnknownMetaType pins the "bind returns unknown
// meta type" message — and the fix from finding 2 (action label, not
// bind label).
func TestNewActionRejectsUnknownMetaType(t *testing.T) {
	reg, _ := fixtureRegistry(t)
	a := &models.Action{
		Name:   "ghost",
		Method: "GET",
		Path:   "/mail/{id}",
		Bind:   "google.mail.message{id: match.id}",
	}
	_, err := NewAction(a, "google.mail", reg, map[string]*Meta{}) // empty metas
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `action "ghost"`) {
		t.Errorf("error not labelled with action name: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown meta type") {
		t.Errorf("error missing 'unknown meta type': %v", err)
	}
}

// TestNewActionRejectsDuplicateBind pins the
// "duplicate bind for meta" rejection that protects the policy env
// from clobbered variables.
func TestNewActionRejectsDuplicateBind(t *testing.T) {
	reg, _ := fixtureRegistry(t)
	a := &models.Action{
		Name:   "dup",
		Method: "GET",
		Path:   "/mail/{id}",
		Binds: []models.CelExpression{
			"google.mail.message{id: match.id}",
			"google.mail.message{id: match.id}",
		},
	}
	_, err := NewAction(a, "google.mail", reg, map[string]*Meta{
		"google.mail.message": metaFor(t, reg, "google.mail.message"),
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate bind") {
		t.Fatalf("err = %v", err)
	}
}

// TestActionMatchTemplateOnly pins the happy path: a request that
// matches the template returns (capture map, true, nil).
func TestActionMatchTemplateOnly(t *testing.T) {
	reg, _ := fixtureRegistry(t)
	a := &models.Action{Name: "ok", Method: "GET", Path: "/mail/{id}"}
	act, err := NewAction(a, "google.mail", reg, nil)
	require.NoError(t, err)
	req := &pb.Request{Method: "GET", Path: "/mail/42", PathSegments: []string{"mail", "42"}}
	captures, ok, err := act.Match(req)
	require.NoError(t, err)
	if !ok {
		t.Fatal("want match")
	}
	if captures["id"] != "42" {
		t.Errorf("captures = %v, want id=42", captures)
	}
}

// TestActionMatchTemplateMiss pins the negative result for a request
// that doesn't match the template.
func TestActionMatchTemplateMiss(t *testing.T) {
	reg, _ := fixtureRegistry(t)
	a := &models.Action{Name: "ok", Method: "GET", Path: "/mail/{id}"}
	act, err := NewAction(a, "google.mail", reg, nil)
	require.NoError(t, err)
	req := &pb.Request{Method: "POST", Path: "/mail/42", PathSegments: []string{"mail", "42"}}
	captures, ok, err := act.Match(req)
	require.NoError(t, err)
	if ok || captures != nil {
		t.Fatalf("want (nil, false), got (%v, %v)", captures, ok)
	}
}

// TestActionMatchFilterOnly pins the path with no template — match
// hinges entirely on the filter predicate.
func TestActionMatchFilterOnly(t *testing.T) {
	reg, _ := fixtureRegistry(t)
	a := &models.Action{Name: "ok", Filter: `request.method == "GET"`}
	act, err := NewAction(a, "google.mail", reg, nil)
	require.NoError(t, err)
	got := &pb.Request{Method: "GET", Path: "/x"}
	_, ok, err := act.Match(got)
	require.NoError(t, err)
	if !ok {
		t.Fatal("want match")
	}
	got = &pb.Request{Method: "POST", Path: "/x"}
	_, ok, err = act.Match(got)
	require.NoError(t, err)
	if ok {
		t.Fatal("want no match")
	}
}
