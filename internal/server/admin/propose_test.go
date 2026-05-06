package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/proposals"
	"github.com/jkylling/bouncer/internal/control/propose"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// gmailMessageEvent is the canonical recorded event the propose
// tests render against — one bind, two output fields, a clean
// no-meta-fetch shape so the engine has something to constrain on.
func gmailMessageEvent(t *testing.T) traffic.Event {
	t.Helper()
	body := map[string]any{
		"type":    "gmail.message",
		"inputs":  map[string]any{"id": "msg-7"},
		"outputs": map[string]any{"from": "alice@example.com", "labelIds": []any{"INBOX", "WORK"}},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return traffic.Event{
		ID:        "evt_1",
		Timestamp: time.Now().UTC(),
		Subject:   "alice",
		Method:    "GET",
		URL:       "/gmail/v1/users/me/messages/msg-7",
		API:       "gmail",
		Action:    "get_message",
		Decision:  traffic.DecisionPermit,
		Binds:     []traffic.ResolvedBind{{Name: "gmail.message", Value: raw}},
	}
}

func gmailRuntime(t *testing.T) *runtime.Runtime {
	t.Helper()
	api := &models.API{
		Name:         "gmail",
		BaseURL:      "https://gmail.invalid",
		PathPrefixes: []string{"/gmail"},
		Meta: []models.Metadata{{
			Name:    "message",
			Kind:    "endpoint",
			Input:   []models.InputField{{Name: "id"}},
			Request: `get('/gmail/' + string(input.id))`,
			Output: []models.OutputField{
				{Name: "from", Expr: "response.body.from"},
				{Name: "labelIds", Expr: "response.body.labelIds"},
			},
		}},
		Actions: []models.Action{{
			Name:   "get_message",
			Method: "GET",
			Path:   "/gmail/v1/users/me/messages/{id}",
			Bind:   "message{id: match.id}",
		}},
	}
	b := runtime.NewBuilder()
	if err := b.AddAPI(api); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return rt
}

// fakeStore is a one-event traffic.Store stub. Only Get is exercised
// by the propose handler; the rest panic to flag accidental use.
type fakeStore struct {
	event traffic.Event
}

func (f fakeStore) Get(_ context.Context, id traffic.EventID) (traffic.Event, error) {
	if id != f.event.ID {
		return traffic.Event{}, traffic.ErrNotFound
	}
	return f.event, nil
}
func (f fakeStore) List(context.Context, traffic.ListOpts) ([]traffic.Summary, traffic.Cursor, error) {
	panic("unexpected List")
}
func (f fakeStore) Pin(context.Context, traffic.EventID) error   { panic("unexpected Pin") }
func (f fakeStore) Unpin(context.Context, traffic.EventID) error { panic("unexpected Unpin") }
func (f fakeStore) Insert(context.Context, traffic.Event) error {
	panic("unexpected Insert")
}
func (f fakeStore) Close() error { return nil }

func proposeServer(t *testing.T, withProposals bool) (*httptest.Server, *proposals.Service, string) {
	ts, prSvc, bearer, _ := proposeServerWithKeys(t, withProposals)
	return ts, prSvc, bearer
}

// proposeServerWithKeys is the keys-aware variant. Subject-scoping
// tests need to issue a non-admin bearer for an arbitrary subject and
// thus need access to the same ServerKeys the middleware was wired
// against.
func proposeServerWithKeys(t *testing.T, withProposals bool) (*httptest.Server, *proposals.Service, string, *auth.ServerKeys) {
	t.Helper()
	rt := gmailRuntime(t)
	store := fakeStore{event: gmailMessageEvent(t)}
	engine := propose.New(rt)
	var prSvc *proposals.Service
	if withProposals {
		prSvc = proposals.New(proposals.NewMemoryStore(), policies.New(rt, policies.NewMemoryStore()))
	}
	keys := mustKeys(t)
	r := testRouter(keys)
	MountPropose(r, store, engine, prSvc)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, prSvc, adminBearer(t, keys), keys
}

func postPropose(t *testing.T, base, bearer, id string, body propose.Input, submit bool) *http.Response {
	t.Helper()
	url := base + strings.Replace(ProposePolicyPath, "{id}", id, 1)
	if submit {
		url += "?submit=true"
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestProposePolicyPreviewRendersDefaults(t *testing.T) {
	ts, _, bearer := proposeServer(t, false)
	resp := postPropose(t, ts.URL, bearer, "evt_1", propose.Input{Result: models.Deny}, false)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var got proposeResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if !got.CompileOK {
		t.Errorf("compile error: %s", got.CompileError)
	}
	if got.Policy.Result != models.Deny || got.Policy.API != "gmail" {
		t.Errorf("policy = %+v", got.Policy)
	}
	// Default selection should produce a multi-clause condition.
	if !strings.Contains(got.Policy.Condition, `message.from`) {
		t.Errorf("expected from clause, got %q", got.Policy.Condition)
	}
	if got.Proposal != nil {
		t.Errorf("preview leaked a proposal: %+v", got.Proposal)
	}
}

func TestProposePolicyUnknownIDReturns404(t *testing.T) {
	ts, _, bearer := proposeServer(t, false)
	resp := postPropose(t, ts.URL, bearer, "missing", propose.Input{Result: models.Deny}, false)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestProposePolicySubmitWritesProposal(t *testing.T) {
	ts, prSvc, bearer := proposeServer(t, true)
	resp := postPropose(t, ts.URL, bearer, "evt_1", propose.Input{Result: models.Deny}, true)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	// 201 must carry both Content-Type (so clients decode the body)
	// and Location (RFC convention for "created"). Setting Content-
	// Type after WriteHeader is silently ignored, so a regression
	// here is invisible without an explicit check.
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got proposeResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if got.Proposal == nil {
		t.Fatal("submit returned no proposal")
	}
	if loc, want := resp.Header.Get("Location"), ProposalsPath+"/"+got.Proposal.ID.String(); loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
	if got.Proposal.Origin.Kind != proposals.OriginFromRequest || got.Proposal.Origin.RequestID != "evt_1" {
		t.Errorf("origin = %+v, want from_request/evt_1", got.Proposal.Origin)
	}
	// And the proposal is persisted.
	round, err := prSvc.Get(context.Background(), got.Proposal.ID)
	if err != nil {
		t.Fatalf("get proposal: %v", err)
	}
	if round.Policy.API != "gmail" {
		t.Errorf("persisted policy api = %q", round.Policy.API)
	}
}

// TestProposePolicyEmptyBodyUsesDefaults pins the no-body case: a
// POST without a JSON payload is the natural curl shape for "use
// the default selection" and must round-trip as a 200 preview with
// the engine's default heuristic applied. Earlier the handler
// rejected this with 400 ("invalid JSON: EOF") because Decode
// returns io.EOF on an empty reader.
func TestProposePolicyEmptyBodyUsesDefaults(t *testing.T) {
	ts, _, bearer := proposeServer(t, false)
	url := ts.URL + strings.Replace(ProposePolicyPath, "{id}", "evt_1", 1)
	req, _ := http.NewRequest(http.MethodPost, url, http.NoBody)
	req.Header.Set("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var got proposeResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.CompileOK {
		t.Errorf("compile error: %s", got.CompileError)
	}
	if got.Policy.API != "gmail" {
		t.Errorf("policy api = %q, want gmail", got.Policy.API)
	}
}

func TestProposePolicySubmitWithoutProposalServiceReturns501(t *testing.T) {
	ts, _, bearer := proposeServer(t, false)
	resp := postPropose(t, ts.URL, bearer, "evt_1", propose.Input{Result: models.Deny}, true)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestProposePolicyOtherSubjectReturns404 pins the subject-scoping
// guard: a non-admin caller proposing against another subject's
// recorded event gets 404, not 403, so an agent can't probe for
// other subjects' event ids.
func TestProposePolicyOtherSubjectReturns404(t *testing.T) {
	ts, _, _, keys := proposeServerWithKeys(t, false)
	bearer := userBearer(t, keys, "bob") // event subject is "alice"
	resp := postPropose(t, ts.URL, bearer, "evt_1", propose.Input{Result: models.Deny}, false)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestProposePolicyOwnSubjectAllowed pins the positive case: a
// non-admin caller proposing against their own recorded event is
// permitted and renders a preview.
func TestProposePolicyOwnSubjectAllowed(t *testing.T) {
	ts, _, _, keys := proposeServerWithKeys(t, false)
	bearer := userBearer(t, keys, "alice") // event subject is "alice"
	resp := postPropose(t, ts.URL, bearer, "evt_1", propose.Input{Result: models.Deny}, false)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, body = %s", resp.StatusCode, body)
	}
	resp.Body.Close()
}

// TestProposePolicyAnonymousReturns401 pins the route gate: without
// a bearer the propose endpoint 401s before reaching the handler.
func TestProposePolicyAnonymousReturns401(t *testing.T) {
	ts, _, _ := proposeServer(t, false)
	resp := postPropose(t, ts.URL, "", "evt_1", propose.Input{Result: models.Deny}, false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}
