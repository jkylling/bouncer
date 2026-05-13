package runtime

import (
	"context"
	"strings"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// gmailWithHeaders is a PhysicalAPI variant that returns a canned
// message — directly for /messages/* GETs, and wrapped in `message:`
// for /drafts/* GETs — whose `payload.headers` carries the supplied
// RFC-5322 (name, value) pairs. Used by tests that assert how the
// `message` and `draft` metas lift headers into direct fields.
type gmailWithHeaders struct {
	headers []map[string]any
}

var _ compiled.PhysicalAPI = gmailWithHeaders{}

func (g gmailWithHeaders) Call(_ context.Context, req *pb.MetaRequest) (*pb.Response, error) {
	hs := make([]any, 0, len(g.headers))
	for _, h := range g.headers {
		hs = append(hs, h)
	}
	message := map[string]any{
		"id":           "abc",
		"threadId":     "thread-1",
		"labelIds":     []any{},
		"snippet":      "snippet",
		"historyId":    "100",
		"internalDate": "0",
		"sizeEstimate": 0.0,
		"payload": map[string]any{
			"mimeType": "text/plain",
			"headers":  hs,
		},
	}
	var body map[string]any
	switch {
	case strings.HasSuffix(req.GetPath(), "/profile"):
		body = map[string]any{"emailAddress": "abc@gmail.com"}
	case strings.Contains(req.GetPath(), "/drafts/"):
		body = map[string]any{"id": "draft-1", "message": message}
	default:
		body = message
	}
	s, err := structpb.NewValue(body)
	if err != nil {
		return nil, err
	}
	return &pb.Response{Body: s}, nil
}

// fakeGmailAPI returns canned responses tailored for the bundled gmail
// `read` policy, which checks both `mailbox.messagesTotal == 100` (profile)
// and `'Label_1234' in message.labelIds` (message read).
type fakeGmailAPI struct{}

var _ compiled.PhysicalAPI = fakeGmailAPI{}

func (fakeGmailAPI) Call(_ context.Context, req *pb.MetaRequest) (*pb.Response, error) {
	var body map[string]any
	if req.GetPath() == "/gmail/v1/users/42/profile" {
		body = map[string]any{
			"emailAddress":  "abc@gmail.com",
			"messagesTotal": 100.0,
			"threadsTotal":  2.0,
			"historyId":     "1",
		}
	} else {
		body = map[string]any{
			"id":           "abc",
			"threadId":     "thread-1",
			"labelIds":     []any{"Label_1234"},
			"snippet":      "snippet",
			"historyId":    "100",
			"internalDate": "0",
			"sizeEstimate": 0.0,
			"payload": map[string]any{
				"mimeType": "text/plain",
				"headers":  []any{},
			},
		}
	}
	s, err := structpb.NewValue(body)
	if err != nil {
		return nil, err
	}
	return &pb.Response{Body: s}, nil
}

func loadGmailRuntime(t *testing.T) *APIRuntime {
	t.Helper()
	policies, err := models.FromYAMLDir[models.Policy](testdataPolicies(t))
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	var gmailPolicies []models.Policy
	for _, p := range policies {
		if p.API == "google.gmail" {
			gmailPolicies = append(gmailPolicies, p)
		}
	}
	return loadCrossApiRuntime(t, "google.gmail", gmailPolicies)
}

func TestEvaluateGmailGetPermits(t *testing.T) {
	rt := loadGmailRuntime(t)
	req := &pb.Request{
		Method:       "GET",
		Path:         "/gmail/v1/users/42/messages/abc",
		PathSegments: []string{"gmail", "v1", "users", "42", "messages", "abc"},
	}
	got, err := rt.Evaluate(t.Context(), constantResolver(fakeGmailAPI{}), req, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("expected Permit, got %s", got)
	}
}

// TestGmailHeaderFields pins that the four RFC-5322 recipient/sender
// headers are lifted out of `payload.headers` as the matching header's
// raw value (or "" when absent), and that they're directly readable
// from a CEL policy. Covers both `message.*` (read paths) and
// `draft.*` (compose paths) since they share the same lift shape.
func TestGmailHeaderFields(t *testing.T) {
	type variant struct {
		bind         string // "message" or "draft"
		action       string
		path         string
		pathSegments []string
	}
	variants := []variant{
		{
			bind:         "message",
			action:       "get_message",
			path:         "/gmail/v1/users/42/messages/abc",
			pathSegments: []string{"gmail", "v1", "users", "42", "messages", "abc"},
		},
		{
			bind:         "draft",
			action:       "get_draft",
			path:         "/gmail/v1/users/42/drafts/abc",
			pathSegments: []string{"gmail", "v1", "users", "42", "drafts", "abc"},
		},
	}
	cases := []struct {
		name      string
		headers   []map[string]any
		condition string // %s is replaced with "message" or "draft"
	}{
		{
			name: "to_membership",
			headers: []map[string]any{
				{"name": "To", "value": "alice@example.com"},
				{"name": "From", "value": "bob@example.com"},
			},
			condition: `"alice@example.com" in %s.to`,
		},
		{
			name: "from_indexed",
			headers: []map[string]any{
				{"name": "From", "value": "bob@example.com"},
			},
			condition: `%s.from[0] == "bob@example.com"`,
		},
		{
			name: "cc_and_bcc_empty_when_absent",
			headers: []map[string]any{
				{"name": "To", "value": "alice@example.com"},
			},
			condition: `%s.cc.size() == 0 && %s.bcc.size() == 0`,
		},
		{
			name:      "empty_headers_yield_empty_lists",
			headers:   nil,
			condition: `%s.to.size() == 0 && %s.from.size() == 0 && %s.cc.size() == 0 && %s.bcc.size() == 0`,
		},
		{
			name: "to_substring_via_exists",
			headers: []map[string]any{
				{"name": "To", "value": "Alice <alice@example.com>, bob@example.com"},
			},
			condition: `%s.to.exists(v, v.contains("@example.com"))`,
		},
	}
	for _, v := range variants {
		t.Run(v.bind, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					condition := strings.ReplaceAll(tc.condition, "%s", v.bind)
					rt := loadCrossApiRuntime(t, "google.gmail", []models.Policy{{
						API:       "google.gmail",
						Name:      "header_check",
						Action:    `action.name == "` + v.action + `"`,
						Condition: condition,
						Result:    models.Permit,
					}})
					got, err := rt.Evaluate(t.Context(),
						constantResolver(gmailWithHeaders{headers: tc.headers}),
						&pb.Request{
							Method:       "GET",
							Path:         v.path,
							PathSegments: v.pathSegments,
						}, stubPrincipal())
					if err != nil {
						t.Fatalf("evaluate: %v", err)
					}
					if got != models.Permit {
						t.Fatalf("decision = %s, want Permit", got)
					}
				})
			}
		})
	}
}
