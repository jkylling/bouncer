// Package recipes turns a starter-pack name + small parameter struct
// into a list of `models.Policy` values. The onboarding wizard's
// "Pick starter policies" step renders these via /preview and
// persists them via /apply.
//
// A recipe is intentionally hand-coded Go — not a YAML template, not
// a CEL macro — because the parameters that vary between users (a
// Gmail label name, a time window, a recipient address) are easier to
// validate and substitute in real code than in template strings. The
// generated CEL still goes through the runtime's compile step before
// it persists; nothing here skips validation.
package recipes

import (
	"errors"
	"fmt"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Sentinel errors. Handlers map these onto HTTP statuses.
var (
	ErrUnknown = errors.New("unknown recipe")
	ErrInvalid = errors.New("invalid recipe parameters")
)

// Params is the loosely-typed bag the HTTP handler decodes the wizard
// form into. Each recipe knows which keys it reads; unknown keys are
// ignored. The struct lives here (rather than per-recipe types) so the
// HTTP layer decodes one shape regardless of which recipe ID arrived.
type Params struct {
	// Two-label fence.
	ScopeLabel  string `json:"scope_label,omitempty"`
	SendLabel   string `json:"send_label,omitempty"`
	AllowHeader bool   `json:"allow_header,omitempty"`

	// Summarize recent.
	Window string `json:"window,omitempty"` // "1d" / "6h" / "7d"

	// Send-to-self.
	SelfAddress string `json:"self_address,omitempty"`
}

// Recipe is the closed list. ID is the URL-friendly key
// (`/_api/recipes/<id>/preview`); Title and Description drive the
// /list endpoint a future change can expose for a recipe gallery.
type Recipe struct {
	ID          string
	Title       string
	Description string
	Render      func(Params) ([]models.Policy, error)
}

// All returns every recipe in stable order. Order is intentional so
// the wizard's accordion lays them out the same way every render.
func All() []Recipe {
	return []Recipe{
		{
			ID:          "two-label",
			Title:       "Two-label Gmail fence",
			Description: `Agent reads what's labeled "ai", drafts freely, sends only drafts you've labeled "ai/send".`,
			Render:      renderTwoLabel,
		},
		{
			ID:          "summarize-recent",
			Title:       "Summarize mail from the last 24 hours",
			Description: "Read-only agent constrained to a time window. Never drafts, sends, or modifies.",
			Render:      renderSummarizeRecent,
		},
	}
}

// Get returns the recipe with this ID, or ErrUnknown.
func Get(id string) (Recipe, error) {
	for _, r := range All() {
		if r.ID == id {
			return r, nil
		}
	}
	return Recipe{}, fmt.Errorf("%w: %q", ErrUnknown, id)
}

// renderTwoLabel produces the Gmail two-label fence: read inside
// scope, drafts unconditional, send only on the send-label gate.
// Eight rules to mirror the wizard's preview count.
func renderTwoLabel(p Params) ([]models.Policy, error) {
	scope := p.ScopeLabel
	send := p.SendLabel
	if scope == "" {
		scope = "ai"
	}
	if send == "" {
		send = "ai/send"
	}
	scopeOr := fmt.Sprintf("%q in message.labelIds", scope)
	if p.AllowHeader {
		scopeOr += " || message.headers.exists(h, h.name == 'X-AI-Managed' && h.value == 'true')"
	}
	draftScopeOr := fmt.Sprintf("%q in draft.message.labelIds", scope)
	if p.AllowHeader {
		draftScopeOr += " || draft.message.headers.exists(h, h.name == 'X-AI-Managed' && h.value == 'true')"
	}
	const api = "google.gmail"
	return []models.Policy{
		{API: api, Name: "two-label-read", Action: cel(`action.name == "get_message"`), Condition: cel(scopeOr), Result: models.Permit},
		{API: api, Name: "two-label-list", Action: cel(`action.name == "list_messages"`), Condition: cel(
			fmt.Sprintf(`request.query.exists(kv, kv.key == 'labelIds' && kv.value == %q)`, scope),
		), Result: models.Permit},
		{API: api, Name: "two-label-list-drafts", Action: cel(`action.name == "list_drafts"`), Condition: cel("true"), Result: models.Permit},
		{API: api, Name: "two-label-create-draft", Action: cel(`action.name == "create_draft"`), Condition: cel("true"), Result: models.Permit},
		{API: api, Name: "two-label-update-draft", Action: cel(`action.name == "update_draft"`), Condition: cel(draftScopeOr), Result: models.Permit},
		{API: api, Name: "two-label-get-draft", Action: cel(`action.name == "get_draft"`), Condition: cel(draftScopeOr), Result: models.Permit},
		{API: api, Name: "two-label-delete-draft", Action: cel(`action.name == "delete_draft"`), Condition: cel(draftScopeOr), Result: models.Permit},
		{API: api, Name: "two-label-send-draft", Action: cel(`action.name == "send_draft"`), Condition: cel(
			fmt.Sprintf(`%q in draft.message.labelIds`, send),
		), Result: models.Permit},
	}, nil
}

// renderSummarizeRecent produces the read-only-with-time-window recipe.
// Two rules total: list-with-window and read-with-window.
func renderSummarizeRecent(p Params) ([]models.Policy, error) {
	w := p.Window
	switch w {
	case "":
		w = "1d"
	case "1d", "6h", "7d":
	default:
		return nil, fmt.Errorf("%w: window must be one of 1d|6h|7d", ErrInvalid)
	}
	const api = "google.gmail"
	return []models.Policy{
		{API: api, Name: "recent-list", Action: cel(`action.name == "list_messages"`), Condition: cel(
			fmt.Sprintf(`request.query.exists(kv, kv.key == 'q' && kv.value.contains(%q))`, "newer_than:"+w),
		), Result: models.Permit},
		{API: api, Name: "recent-read", Action: cel(`action.name == "get_message"`), Condition: cel("true"), Result: models.Permit},
	}, nil
}

// cel is a tiny constructor since models.CelExpression is a typed
// string but the recipe code reads cleaner with a wrapper.
func cel(src string) models.CelExpression { return models.CelExpression(src) }
