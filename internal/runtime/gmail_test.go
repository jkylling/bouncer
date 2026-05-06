package runtime

import (
	"context"
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

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
		if p.API == "gmail" {
			gmailPolicies = append(gmailPolicies, p)
		}
	}
	return loadCrossApiRuntime(t, "gmail", gmailPolicies)
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
