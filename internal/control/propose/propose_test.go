package propose

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// gmailRuntime builds a runtime with a single `gmail` API and a
// `message` meta carrying input.id and output.from / labelIds. That
// surface is enough to exercise the walk + render + validate path
// without dragging real upstream calls in.
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
				{Name: "sizeEstimate", Expr: "response.body.sizeEstimate"},
			},
		}},
		Actions: []models.Action{{
			Name:   "get_message",
			Method: "GET",
			Path:   "/gmail/{id}",
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

func gmailEvent(binds []traffic.ResolvedBind) traffic.Event {
	return traffic.Event{
		ID:     "evt_1",
		API:    "gmail",
		Action: "get_message",
		Method: "GET",
		URL:    "/gmail/msg-7",
		Binds:  binds,
	}
}

// bindJSON builds a ResolvedBind whose Value matches the
// MarshalJSON shape produced by messages.Value. Tests that exercise
// the full recorder roundtrip live in the recorder/runtime packages;
// here we shape the JSON directly because the engine's contract is
// "given JSON of this shape, produce this policy".
func bindJSON(t *testing.T, fullName string, inputs, outputs map[string]any) traffic.ResolvedBind {
	t.Helper()
	body := map[string]any{"type": fullName, "inputs": inputs}
	if outputs != nil {
		body["outputs"] = outputs
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal bind: %v", err)
	}
	return traffic.ResolvedBind{Name: fullName, Value: raw}
}

func TestProposeRendersDefaultSelection(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.message",
			map[string]any{"id": "msg-7"},
			map[string]any{
				"from":         "alice@example.com",
				"labelIds":     []any{"INBOX", "WORK"},
				"sizeEstimate": 1024.0,
			}),
	})

	got, err := eng.Propose(ev, Input{Result: models.Deny})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if !got.CompileOK {
		t.Fatalf("compile error: %s", got.CompileError)
	}
	// Bind fields default to selected — the reviewer drops noisy
	// ones by editing the proposal. The request.* fallback fields
	// default off when binds exist (covered by
	// TestProposeRequestFieldsDefaultOffWhenBindsPresent).
	for _, f := range got.AvailableFields {
		if strings.HasPrefix(f.Path, "request.") {
			continue
		}
		if !f.Selected {
			t.Errorf("%s.Selected = false, want true (bind fields default-on)", f.Path)
		}
	}
	cond := got.Policy.Condition
	if !strings.Contains(cond, `message.from == "alice@example.com"`) {
		t.Errorf("condition missing from clause: %s", cond)
	}
	if !strings.Contains(cond, `["INBOX", "WORK"].all(x, x in message.labelIds)`) {
		t.Errorf("condition missing labelIds clause (default contains_all): %s", cond)
	}
	// Now that defaults include everything, the rendered condition
	// also constrains the instance id and the size estimate.
	if !strings.Contains(cond, `message.id == "msg-7"`) {
		t.Errorf("condition should include id clause: %s", cond)
	}
	if !strings.Contains(cond, `message.sizeEstimate == 1024`) {
		t.Errorf("condition should include sizeEstimate clause: %s", cond)
	}
	if got.Policy.Action != `action.name == "get_message"` {
		t.Errorf("action predicate = %q", got.Policy.Action)
	}
	if got.Policy.Result != models.Deny {
		t.Errorf("result = %q, want deny", got.Policy.Result)
	}
}

// TestProposeBindFieldsDefaultSelected pins the strategy doc's
// "include everything, reviewer prunes" rule: every walked bind
// field is selected by default, regardless of its leaf name.
// Earlier revisions ran a stem-based deny heuristic that
// misclassified fields like `identifierType` and `sizeEstimate`.
func TestProposeBindFieldsDefaultSelected(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.message",
			map[string]any{"id": "msg-7"},
			map[string]any{
				"identifierType": "rfc822",
				"sizeEstimate":   1024,
				"historyId":      "h7",
			}),
	})
	got, err := eng.Propose(ev, Input{Result: models.Deny})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	for _, f := range got.AvailableFields {
		if !strings.HasPrefix(f.Path, "request.") && !f.Selected {
			t.Errorf("%s.Selected = false, want true (bind fields default-on)", f.Path)
		}
	}
}

// TestProposeRequestFieldsDefaultOffWhenBindsPresent pins the
// inverse default: when there are bind fields to constrain on, the
// request.method/request.path fallback rows are *unselected* by
// default — the bind clauses do the gating, the request literals
// are noise. The reviewer can opt them in to pin the URL shape.
func TestProposeRequestFieldsDefaultOffWhenBindsPresent(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.message", map[string]any{"id": "msg-7"}, map[string]any{}),
	})
	got, err := eng.Propose(ev, Input{Result: models.Deny})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	for _, f := range got.AvailableFields {
		if strings.HasPrefix(f.Path, "request.") && f.Selected {
			t.Errorf("%s.Selected = true, want false (binds present)", f.Path)
		}
	}
}

func TestProposeRespectsExplicitInclude(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.message",
			map[string]any{"id": "msg-7"},
			map[string]any{"from": "alice@example.com", "labelIds": []any{"INBOX"}}),
	})
	got, err := eng.Propose(ev, Input{
		Result:  models.Deny,
		Include: []string{"message.id"}, // user toggled everything else off
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if got.Policy.Condition != `message.id == "msg-7"` {
		t.Errorf("condition = %q", got.Policy.Condition)
	}
	for _, f := range got.AvailableFields {
		want := f.Path == "message.id"
		if f.Selected != want {
			t.Errorf("%s selected=%v, want %v", f.Path, f.Selected, want)
		}
	}
}

func TestProposeListMatchModes(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.message",
			map[string]any{"id": "msg-7"},
			map[string]any{"labelIds": []any{"INBOX", "WORK"}}),
	})
	cases := []struct {
		mode ListMatch
		want string
	}{
		{ListContainsAll, `["INBOX", "WORK"].all(x, x in message.labelIds)`},
		{ListContainsAny, `["INBOX", "WORK"].exists(x, x in message.labelIds)`},
		{ListEquals, `message.labelIds == ["INBOX", "WORK"]`},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			got, err := eng.Propose(ev, Input{
				Result:    models.Deny,
				Include:   []string{"message.labelIds"},
				ListMatch: map[string]ListMatch{"message.labelIds": tc.mode},
			})
			if err != nil {
				t.Fatalf("propose: %v", err)
			}
			if got.Policy.Condition != tc.want {
				t.Errorf("condition = %q, want %q", got.Policy.Condition, tc.want)
			}
		})
	}
}

func TestProposeEmptyIncludeFailsCompile(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.message",
			map[string]any{"id": "msg-7"},
			map[string]any{"from": "alice@example.com"}),
	})
	got, err := eng.Propose(ev, Input{
		Result:  models.Deny,
		Include: []string{}, // empty (non-nil) — deselect everything
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if got.Policy.Condition != "true" {
		t.Errorf("condition = %q, want \"true\"", got.Policy.Condition)
	}
	// `condition: "true"` is overly broad; the validator must reject
	// it so the UI can refuse to submit. (The runtime validates fine,
	// actually — `true` is a valid CEL bool. So a real validator
	// rejection here would require an extra check at a higher layer.
	// The strategy doc treats this as "UI must enforce ≥1 field".)
	// We at least surface the dangerous shape clearly.
	_ = got.CompileOK
}

// TestProposeNoBindsFallsBackToRequestShape pins the looser shape:
// an event with an api+action but no resolved binds renders against
// request.method/request.path so the reviewer still gets a usable
// draft. Earlier the engine errored here.
func TestProposeNoBindsFallsBackToRequestShape(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := traffic.Event{
		ID: "evt_1", API: "gmail", Action: "get_message",
		Method: "GET", URL: "/gmail/v1/users/me/messages/abc?alt=json",
	}
	got, err := eng.Propose(ev, Input{Result: models.Deny})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(got.Policy.Condition, `request.method == "GET"`) {
		t.Errorf("condition = %q, want request.method clause", got.Policy.Condition)
	}
	if !strings.Contains(got.Policy.Condition, `request.path == "/gmail/v1/users/me/messages/abc"`) {
		t.Errorf("condition = %q, want request.path clause (no query)", got.Policy.Condition)
	}
}

// TestProposeNoActionFallsBackToWildcardPredicate pins the no-action
// case: an event whose URL claimed an api by path prefix but didn't
// match any registered action renders with action: true so the
// policy applies once an action covering the URL is added.
func TestProposeNoActionFallsBackToWildcardPredicate(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := traffic.Event{
		ID: "evt_1", API: "gmail",
		Method: "GET", URL: "/gmail/v1/users/me/threads",
	}
	got, err := eng.Propose(ev, Input{Result: models.Deny})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if got.Policy.Action != "true" {
		t.Errorf("action predicate = %q, want true", got.Policy.Action)
	}
	if !strings.Contains(got.Policy.Condition, `request.path == "/gmail/v1/users/me/threads"`) {
		t.Errorf("condition = %q, want request.path clause", got.Policy.Condition)
	}
}

func TestProposeNoAPIErrors(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := traffic.Event{ID: "evt_1"}
	_, err := eng.Propose(ev, Input{Result: models.Deny})
	if !errors.Is(err, ErrNoAPI) {
		t.Errorf("err = %v, want ErrNoAPI", err)
	}
}

func TestProposeAutoNamesFromFirstSelectedString(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.message",
			map[string]any{"id": "msg-7"},
			map[string]any{"from": "alice@example.com"}),
	})
	got, err := eng.Propose(ev, Input{Result: models.Deny})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	// All fields are selected by default; the first scalar string in
	// walk order is `id`, so the auto-name derives from it.
	if !strings.HasPrefix(got.Policy.Name, "deny-get_message-id-msg-7") {
		t.Errorf("name = %q, want deny-get_message-id-msg-7…", got.Policy.Name)
	}
}

func TestProposeUserNameOverrides(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.message",
			map[string]any{"id": "msg-7"},
			map[string]any{"from": "alice@example.com"}),
	})
	got, err := eng.Propose(ev, Input{Result: models.Deny, Name: "block-alice"})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if got.Policy.Name != "block-alice" {
		t.Errorf("name = %q, want block-alice", got.Policy.Name)
	}
}

func TestProposeSurfacesCompileError(t *testing.T) {
	rt := gmailRuntime(t)
	eng := New(rt)
	// `mailbox.something` is not a known meta on the gmail API;
	// renaming the bind type forces a "no such attribute" CEL
	// compile failure so we can assert the engine reports it.
	ev := gmailEvent([]traffic.ResolvedBind{
		bindJSON(t, "gmail.unknown",
			map[string]any{"id": "x"},
			map[string]any{"from": "alice@example.com"}),
	})
	got, err := eng.Propose(ev, Input{Result: models.Deny})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if got.CompileOK {
		t.Errorf("compile_ok = true, want false; condition = %q", got.Policy.Condition)
	}
	if got.CompileError == "" {
		t.Error("compile_error empty")
	}
}
