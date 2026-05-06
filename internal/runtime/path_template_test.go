package runtime

import (
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// TestActionPathTemplateAndMatchInBind exercises the syntactic-sugar
// path: `method:` + `path:` with `{name}` placeholders. The captured
// segments are passed to the bind expression as `match.<name>`, and a
// policy condition reads the bound meta to verify the value flowed
// through correctly.
func TestActionPathTemplateAndMatchInBind(t *testing.T) {
	api := &models.API{
		Name:         "google.mail",
		BaseURL:      "https://mail",
		PathPrefixes: []string{"/v1/users"},
		Meta: []models.Metadata{{
			Name:    "message",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "user_id"}, {Name: "message_id"}},
			Request: `get('/v1/users/' + string(input.user_id) + '/messages/' + string(input.message_id))`,
			Output: []models.OutputField{
				{Name: "subject", Expr: "response.body.subject"},
			},
		}},
		Actions: []models.Action{{
			Name:   "get_message",
			Method: "GET",
			Path:   "/v1/users/{user_id}/messages/{message_id}",
			Binds:  []models.CelExpression{`message{user_id: match.user_id, message_id: match.message_id}`},
		}},
	}

	bld := NewBuilder()
	if err := bld.AddAPI(api); err != nil {
		t.Fatalf("AddAPI: %v", err)
	}
	rt, err := bld.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := rt.AddPolicy(&models.Policy{
		API:       "google.mail",
		Name:      "permit_alice",
		Action:    `action.name == "get_message"`,
		Condition: `message.user_id == 'alice' && message.message_id == 'm1'`,
		Result:    models.Permit,
	}); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	upstream := staticAPI{bodies: map[string]map[string]any{
		"/v1/users/alice/messages/m1": {"subject": "hi"},
	}}

	// Path matches → captures flow into bind → policy permits.
	_, got, err := rt.Evaluate(t.Context(), constantResolver(upstream), &pb.Request{
		Method:       "GET",
		Path:         "/v1/users/alice/messages/m1",
		PathSegments: []string{"v1", "users", "alice", "messages", "m1"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit, got %s", got)
	}

	// Wrong method → template doesn't match → action doesn't fire → deny.
	_, got, err = rt.Evaluate(t.Context(), constantResolver(upstream), &pb.Request{
		Method:       "DELETE",
		Path:         "/v1/users/alice/messages/m1",
		PathSegments: []string{"v1", "users", "alice", "messages", "m1"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Deny {
		t.Fatalf("expected Deny, got %s", got)
	}
}

// TestActionPathTemplateWithExtraFilter combines a path template (which
// captures segments) with an additional CEL filter. Both must succeed
// for the action to fire, and the filter can read the captures.
func TestActionPathTemplateWithExtraFilter(t *testing.T) {
	api := &models.API{
		Name:         "google.mail",
		BaseURL:      "https://mail",
		PathPrefixes: []string{"/v1/users"},
		Meta: []models.Metadata{{
			Name:    "mailbox",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "user_id"}},
			Request: `get('/v1/users/' + string(input.user_id))`,
			Output:  []models.OutputField{{Name: "kind", Expr: "response.body.kind"}},
		}},
		Actions: []models.Action{{
			Name:   "get_self_mailbox",
			Method: "GET",
			Path:   "/v1/users/{user_id}",
			// Only fires when the captured user_id is "me".
			Filter: `match.user_id == 'me'`,
			Binds:  []models.CelExpression{`mailbox{user_id: match.user_id}`},
		}},
	}

	bld := NewBuilder()
	if err := bld.AddAPI(api); err != nil {
		t.Fatalf("AddAPI: %v", err)
	}
	rt, err := bld.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := rt.AddPolicy(&models.Policy{
		API:       "google.mail",
		Name:      "permit_self",
		Action:    `action.name == "get_self_mailbox"`,
		Condition: `mailbox.user_id == 'me'`,
		Result:    models.Permit,
	}); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	upstream := staticAPI{bodies: map[string]map[string]any{
		"/v1/users/me": {"kind": "self"},
	}}

	// Path matches AND filter passes.
	_, got, err := rt.Evaluate(t.Context(), constantResolver(upstream), &pb.Request{
		Method: "GET", Path: "/v1/users/me",
		PathSegments: []string{"v1", "users", "me"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit, got %s", got)
	}

	// Path matches but filter rejects → no action fires → deny.
	_, got, err = rt.Evaluate(t.Context(), constantResolver(upstream), &pb.Request{
		Method: "GET", Path: "/v1/users/alice",
		PathSegments: []string{"v1", "users", "alice"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Deny {
		t.Fatalf("expected Deny, got %s", got)
	}
}

// TestActionRejectsBareDeclaration confirms the compiler refuses an
// action that supplies neither a path template nor a filter.
func TestActionRejectsBareDeclaration(t *testing.T) {
	api := &models.API{
		Name:    "google.mail",
		BaseURL: "https://mail",
		Actions: []models.Action{{Name: "no_match"}},
	}
	bld := NewBuilder()
	if err := bld.AddAPI(api); err != nil {
		t.Fatalf("AddAPI: %v", err)
	}
	if _, err := bld.Build(); err == nil {
		t.Fatal("expected build error for action with no match clause")
	}
}

// TestActionRejectsDuplicateBindMeta confirms the compiler refuses an
// action whose bind list produces the same meta type twice. Two binds
// keyed under the same meta full name would clobber each other in the
// policy CEL env, with last-wins semantics dependent on slice
// iteration order.
func TestActionRejectsDuplicateBindMeta(t *testing.T) {
	api := &models.API{
		Name:         "google.mail",
		BaseURL:      "https://mail",
		PathPrefixes: []string{"/v1/users"},
		Meta: []models.Metadata{{
			Name:    "message",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "user_id"}, {Name: "message_id"}},
			Request: `get('/v1/users/' + string(input.user_id) + '/messages/' + string(input.message_id))`,
			Output:  []models.OutputField{{Name: "subject", Expr: "response.body.subject"}},
		}},
		Actions: []models.Action{{
			Name:   "dup",
			Method: "GET",
			Path:   "/v1/users/{user_id}/messages/{message_id}",
			Binds: []models.CelExpression{
				`message{user_id: match.user_id, message_id: match.message_id}`,
				`message{user_id: 'me', message_id: match.message_id}`,
			},
		}},
	}
	bld := NewBuilder()
	if err := bld.AddAPI(api); err != nil {
		t.Fatalf("AddAPI: %v", err)
	}
	if _, err := bld.Build(); err == nil {
		t.Fatal("expected build error for action with duplicate bind meta")
	}
}

// TestAddPolicyRejectsInvalidResult pins B3: a typo in `result:` (or an
// omitted field) must fail at AddPolicy rather than silently routing
// the policy to the permit slice in policyStore.add.
func TestAddPolicyRejectsInvalidResult(t *testing.T) {
	api := &models.API{
		Name:         "google.mail",
		BaseURL:      "https://mail",
		PathPrefixes: []string{"/v1"},
		Meta: []models.Metadata{{
			Name:    "message",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/v1/' + string(input.id))`,
			Output:  []models.OutputField{{Name: "subject", Expr: "response.body.subject"}},
		}},
		Actions: []models.Action{{
			Name:   "get",
			Method: "GET",
			Path:   "/v1/{id}",
			Binds:  []models.CelExpression{`message{id: match.id}`},
		}},
	}
	bld := NewBuilder()
	if err := bld.AddAPI(api); err != nil {
		t.Fatalf("AddAPI: %v", err)
	}
	rt, err := bld.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, bad := range []models.PolicyResult{"", "dney", "Permit", "allow"} {
		t.Run(string(bad), func(t *testing.T) {
			err := rt.AddPolicy(&models.Policy{
				API:       "google.mail",
				Name:      "p",
				Action:    `action.name == "get"`,
				Condition: "true",
				Result:    bad,
			})
			if err == nil {
				t.Fatalf("AddPolicy with result=%q must fail", bad)
			}
		})
	}
}
