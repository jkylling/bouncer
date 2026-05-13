package runtime

import (
	"testing"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
	"github.com/jkylling/bouncer/internal/runtime/models"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// User-story policy coverage.
//
// Each test exercises a representative policy distilled from
// ../../user-stories/<api>/*.md, restricted to features actually present
// in the runtime today: standard cel-go (no `principal`, no `let`), the
// bundled extensions enabled in celenv.languageOptions(), and meta
// reads against canned upstream responses returned by staticAPI.
//
// Stories that depend on missing features (`principal.is_agent`,
// `extractDomain`, claim grants) are intentionally not ported here; they
// will become tests when the runtime grows the corresponding surface.

// newStruct is a thin helper around structpb.NewValue so each test
// case stays focused on the policy under examination. Returns a Value
// (not Struct) so the result drops directly into pb.Request.Body, which
// accepts arbitrary JSON shapes.
func newStruct(t *testing.T, m map[string]any) *structpb.Value {
	t.Helper()
	v, err := structpb.NewValue(m)
	if err != nil {
		t.Fatalf("structpb.NewValue: %v", err)
	}
	return v
}

// runUserStory wires up a runtime with a single policy and evaluates one
// request against it. Centralizing the boilerplate keeps each test case
// down to "give me an API name, a policy, a fake upstream, and a
// request — tell me whether it permits or denies."
func runUserStory(
	t *testing.T,
	apiName string,
	policy models.Policy,
	api compiled.PhysicalAPI,
	req *pb.Request,
) models.PolicyResult {
	t.Helper()
	rt := loadCrossApiRuntime(t, apiName, []models.Policy{policy})
	got, err := rt.Evaluate(t.Context(), constantResolver(api), req, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate %s::%s: %v", apiName, policy.Name, err)
	}
	return got
}

// expectOutcome fails the test unless got matches want, with a label
// that pins down which sub-case failed.
func expectOutcome(t *testing.T, label string, got, want models.PolicyResult) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %s, want %s", label, got, want)
	}
}

// ---------------------------------------------------------------------------
// Gmail / 01 — Label-based read restriction
// ---------------------------------------------------------------------------

func TestUserStory_Gmail01_LabelBasedReadRestriction(t *testing.T) {
	policy := models.Policy{
		API:    "google.gmail",
		Name:   "no_sensitive_labels",
		Action: `action.name == "get_message"`,
		Condition: `!message.labelIds.exists(l,
			l in ["Label_Confidential", "Label_LegalHold", "Label_HR-Private"])`,
		Result: models.Permit,
	}

	api := staticAPI{bodies: map[string]map[string]any{
		"/gmail/v1/users/me/profile": {
			"emailAddress":  "alice@corp.example",
			"messagesTotal": 1.0,
			"threadsTotal":  1.0,
			"historyId":     "1",
		},
		"/gmail/v1/users/me/messages/m-public?format=metadata": {
			"id": "m-public", "threadId": "t1",
			"labelIds":     []any{"INBOX", "Label_Support"},
			"historyId":    "1",
			"internalDate": "0",
			"sizeEstimate": 0.0,
			"payload":      map[string]any{},
		},
		"/gmail/v1/users/me/messages/m-secret?format=metadata": {
			"id": "m-secret", "threadId": "t2",
			"labelIds":     []any{"INBOX", "Label_LegalHold"},
			"historyId":    "1",
			"internalDate": "0",
			"sizeEstimate": 0.0,
			"payload":      map[string]any{},
		},
	}}

	expectOutcome(t, "public message",
		runUserStory(t, "google.gmail", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/gmail/v1/users/me/messages/m-public",
			PathSegments: []string{"gmail", "v1", "users", "me", "messages", "m-public"},
		}), models.Permit)

	expectOutcome(t, "legal-hold message",
		runUserStory(t, "google.gmail", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/gmail/v1/users/me/messages/m-secret",
			PathSegments: []string{"gmail", "v1", "users", "me", "messages", "m-secret"},
		}), models.Deny)
}

// ---------------------------------------------------------------------------
// Gmail / 07 — Filter creation guardrails
// ---------------------------------------------------------------------------

func TestUserStory_Gmail07_FilterCreationGuardrails(t *testing.T) {
	policy := models.Policy{
		API:    "google.gmail",
		Name:   "filter_guardrails",
		Action: `action.name == "settings_create_filter"`,
		// criteria must be non-trivial AND no INBOX/UNREAD removal
		// AND not auto-trash. The story also includes external-forward
		// blocking; left out here because endsWith on optional strings
		// would need an extra null guard not relevant to these cases.
		Condition: `(
			has(request.body.criteria.from) ||
			has(request.body.criteria.to) ||
			has(request.body.criteria.subject) ||
			(has(request.body.criteria.query) && size(request.body.criteria.query) >= 4)
		)
		&& !(has(request.body.action.removeLabelIds) &&
		     ("INBOX" in request.body.action.removeLabelIds ||
		      "UNREAD" in request.body.action.removeLabelIds))
		&& !(has(request.body.action.addLabelIds) && "TRASH" in request.body.action.addLabelIds)`,
		Result: models.Permit,
	}

	good := newStruct(t, map[string]any{
		"criteria": map[string]any{"from": "alerts@pagerduty.com"},
		"action":   map[string]any{"addLabelIds": []any{"Label_PD"}},
	})
	badCatchAll := newStruct(t, map[string]any{
		"criteria": map[string]any{"query": ""},
		"action":   map[string]any{"removeLabelIds": []any{"INBOX"}},
	})

	api := staticAPI{bodies: map[string]map[string]any{
		// create_filter binds `mailbox`, so the profile fetch is needed
		// even if the policy never reads mailbox fields.
		"/gmail/v1/users/me/profile": {
			"emailAddress": "alice@corp.example", "messagesTotal": 1.0,
			"threadsTotal": 1.0, "historyId": "1",
		},
	}}

	expectOutcome(t, "precise from-filter",
		runUserStory(t, "google.gmail", policy, api, &pb.Request{
			Method:       "POST",
			Path:         "/gmail/v1/users/me/settings/filters",
			PathSegments: []string{"gmail", "v1", "users", "me", "settings", "filters"},
			Body:         good,
		}), models.Permit)

	expectOutcome(t, "catch-all hide-inbox filter",
		runUserStory(t, "google.gmail", policy, api, &pb.Request{
			Method:       "POST",
			Path:         "/gmail/v1/users/me/settings/filters",
			PathSegments: []string{"gmail", "v1", "users", "me", "settings", "filters"},
			Body:         badCatchAll,
		}), models.Deny)
}

// ---------------------------------------------------------------------------
// Gmail / 08 — Drafts yes, sends no
// ---------------------------------------------------------------------------

func TestUserStory_Gmail08_DraftsAllowedSendsDenied(t *testing.T) {
	policies := []models.Policy{
		// drafting is fine
		{API: "google.gmail", Name: "permit_create_draft", Action: `action.name == "create_draft"`, Condition: "true", Result: models.Permit},
		// send_draft / send_message / insert / import are not permitted
		// — under deny-overrides semantics, omitting a Permit produces
		// the implicit Deny we want.
	}
	rt := loadCrossApiRuntime(t, "google.gmail", policies)

	upstream := staticAPI{bodies: map[string]map[string]any{
		"/gmail/v1/users/me/profile": {
			"emailAddress": "alice@corp.example", "messagesTotal": 1.0,
			"threadsTotal": 1.0, "historyId": "1",
		},
	}}

	got, err := rt.Evaluate(t.Context(), constantResolver(upstream), &pb.Request{
		Method:       "POST",
		Path:         "/gmail/v1/users/me/drafts",
		PathSegments: []string{"gmail", "v1", "users", "me", "drafts"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate create_draft: %v", err)
	}
	expectOutcome(t, "create_draft", got, models.Permit)

	got, err = rt.Evaluate(t.Context(), constantResolver(upstream), &pb.Request{
		Method:       "POST",
		Path:         "/gmail/v1/users/me/messages/send",
		PathSegments: []string{"gmail", "v1", "users", "me", "messages", "send"},
	}, stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate send_message: %v", err)
	}
	expectOutcome(t, "send_message", got, models.Deny)
}

// ---------------------------------------------------------------------------
// Drive / 01 — External-domain sharing block
// ---------------------------------------------------------------------------

func TestUserStory_Drive01_ExternalDomainBlock(t *testing.T) {
	policy := models.Policy{
		API:    "google.drive",
		Name:   "internal_only_share",
		Action: `action.name == "create_permission"`,
		Condition: `request.body.type == "user" && request.body.emailAddress.endsWith("@acme.example")
			|| request.body.type == "group" && request.body.emailAddress.endsWith("@acme.example")
			|| request.body.type == "domain" && request.body.domain == "acme.example"`,
		Result: models.Permit,
	}

	api := staticAPI{bodies: map[string]map[string]any{
		"/drive/v3/files/f1?fields=*&supportsAllDrives=true": {
			"id": "f1", "name": "spec.doc",
			"mimeType": "application/vnd.google-apps.document",
		},
	}}

	internal := newStruct(t, map[string]any{
		"type": "user", "role": "writer",
		"emailAddress": "bob@acme.example",
	})
	external := newStruct(t, map[string]any{
		"type": "user", "role": "writer",
		"emailAddress": "attacker@gmail.com",
	})

	expectOutcome(t, "internal grant",
		runUserStory(t, "google.drive", policy, api, &pb.Request{
			Method:       "POST",
			Path:         "/drive/v3/files/f1/permissions",
			PathSegments: []string{"drive", "v3", "files", "f1", "permissions"},
			Body:         internal,
		}), models.Permit)

	expectOutcome(t, "external grant",
		runUserStory(t, "google.drive", policy, api, &pb.Request{
			Method:       "POST",
			Path:         "/drive/v3/files/f1/permissions",
			PathSegments: []string{"drive", "v3", "files", "f1", "permissions"},
			Body:         external,
		}), models.Deny)
}

// ---------------------------------------------------------------------------
// Drive / 06 — MIME type restrictions on get_file
// ---------------------------------------------------------------------------
//
// The user story gates on `principal.is_agent`; with no principal in
// scope we test the inner check directly: agent reads are restricted to
// human-document MIME types.
func TestUserStory_Drive06_MimeAllowlistOnRead(t *testing.T) {
	policy := models.Policy{
		API:    "google.drive",
		Name:   "human_doc_mimes",
		Action: `action.name == "get_file"`,
		Condition: `file.mimeType in [
			"application/vnd.google-apps.document",
			"application/vnd.google-apps.spreadsheet",
			"application/pdf",
			"text/plain",
			"text/markdown",
			"text/csv"
		]`,
		Result: models.Permit,
	}

	api := staticAPI{bodies: map[string]map[string]any{
		"/drive/v3/files/doc?fields=*&supportsAllDrives=true": {
			"id": "doc", "name": "Plan",
			"mimeType": "application/vnd.google-apps.document",
		},
		"/drive/v3/files/blob?fields=*&supportsAllDrives=true": {
			"id": "blob", "name": "payload.bin",
			"mimeType": "application/octet-stream",
		},
	}}

	expectOutcome(t, "google doc",
		runUserStory(t, "google.drive", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/drive/v3/files/doc",
			PathSegments: []string{"drive", "v3", "files", "doc"},
		}), models.Permit)

	expectOutcome(t, "octet-stream",
		runUserStory(t, "google.drive", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/drive/v3/files/blob",
			PathSegments: []string{"drive", "v3", "files", "blob"},
		}), models.Deny)
}

// ---------------------------------------------------------------------------
// Calendar / 01 — Hide private/confidential events
// ---------------------------------------------------------------------------
//
// `event.visibility` is optional in the meta. After the runtime's
// SetField unwrap an absent value reads back as null, and `null !=
// "private"` is true — so events without a visibility field permit
// implicitly. That happens to be the desired default.
func TestUserStory_Calendar01_HidePrivateEvents(t *testing.T) {
	policy := models.Policy{
		API:       "google.calendar",
		Name:      "hide_private",
		Action:    `action.name == "get_event"`,
		Condition: `event.visibility != "private" && event.visibility != "confidential"`,
		Result:    models.Permit,
	}

	baseEvent := func(id, vis string) map[string]any {
		return map[string]any{
			"id":         id,
			"status":     "confirmed",
			"htmlLink":   "https://calendar.example/" + id,
			"created":    "2099-01-01T00:00:00Z",
			"updated":    "2099-01-01T00:00:00Z",
			"iCalUID":    id + "@calendar.example",
			"sequence":   0.0,
			"summary":    "Lunch",
			"visibility": vis,
			"start":      map[string]any{"dateTime": "2099-01-01T12:00:00Z"},
			"end":        map[string]any{"dateTime": "2099-01-01T13:00:00Z"},
		}
	}
	api := staticAPI{bodies: map[string]map[string]any{
		"/calendar/v3/calendars/primary/events/e-public":  baseEvent("e-public", "default"),
		"/calendar/v3/calendars/primary/events/e-private": baseEvent("e-private", "private"),
	}}

	expectOutcome(t, "public event",
		runUserStory(t, "google.calendar", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/calendar/v3/calendars/primary/events/e-public",
			PathSegments: []string{"calendar", "v3", "calendars", "primary", "events", "e-public"},
		}), models.Permit)

	expectOutcome(t, "private event",
		runUserStory(t, "google.calendar", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/calendar/v3/calendars/primary/events/e-private",
			PathSegments: []string{"calendar", "v3", "calendars", "primary", "events", "e-private"},
		}), models.Deny)
}

// ---------------------------------------------------------------------------
// Calendar / 07 — Recurrence rule bounds on insert_event
// ---------------------------------------------------------------------------

func TestUserStory_Calendar07_RecurrenceBounds(t *testing.T) {
	policy := models.Policy{
		API:    "google.calendar",
		Name:   "bounded_recurrence",
		Action: `action.name == "insert_event"`,
		Condition: `!has(request.body.recurrence) ||
			request.body.recurrence.all(r,
				r.startsWith("EXDATE") || r.startsWith("RDATE") ||
				(
					r.startsWith("RRULE:") &&
					(r.contains("UNTIL=") || r.contains("COUNT=")) &&
					!r.contains("FREQ=MINUTELY") &&
					!r.contains("FREQ=HOURLY") &&
					!r.contains("FREQ=SECONDLY")
				)
			)`,
		Result: models.Permit,
	}

	bounded := newStruct(t, map[string]any{
		"summary":    "Weekly 1:1",
		"start":      map[string]any{"dateTime": "2099-01-06T15:00:00Z"},
		"end":        map[string]any{"dateTime": "2099-01-06T15:30:00Z"},
		"recurrence": []any{"RRULE:FREQ=WEEKLY;COUNT=12"},
	})
	unbounded := newStruct(t, map[string]any{
		"summary":    "All hands",
		"start":      map[string]any{"dateTime": "2099-01-06T15:00:00Z"},
		"end":        map[string]any{"dateTime": "2099-01-06T16:00:00Z"},
		"recurrence": []any{"RRULE:FREQ=DAILY"},
	})

	expectOutcome(t, "bounded weekly",
		runUserStory(t, "google.calendar", policy, unusedAPI{}, &pb.Request{
			Method:       "POST",
			Path:         "/calendar/v3/calendars/primary/events",
			PathSegments: []string{"calendar", "v3", "calendars", "primary", "events"},
			Body:         bounded,
		}), models.Permit)

	expectOutcome(t, "unbounded daily",
		runUserStory(t, "google.calendar", policy, unusedAPI{}, &pb.Request{
			Method:       "POST",
			Path:         "/calendar/v3/calendars/primary/events",
			PathSegments: []string{"calendar", "v3", "calendars", "primary", "events"},
			Body:         unbounded,
		}), models.Deny)
}

// ---------------------------------------------------------------------------
// Docs / 01 — Title classification prefix on create_document
// ---------------------------------------------------------------------------

func TestUserStory_Docs01_TitleClassificationPrefix(t *testing.T) {
	policy := models.Policy{
		API:    "google.docs",
		Name:   "title_prefix",
		Action: `action.name == "create_document"`,
		Condition: `has(request.body.title) &&
			request.body.title.matches("^\\[(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)\\] [A-Z]+-[0-9]+ .+$")`,
		Result: models.Permit,
	}

	good := newStruct(t, map[string]any{"title": "[INTERNAL] BIO-2141 Phase II Interim Results"})
	bad := newStruct(t, map[string]any{"title": "Phase II Interim Results Summary"})

	expectOutcome(t, "tagged title",
		runUserStory(t, "google.docs", policy, unusedAPI{}, &pb.Request{
			Method:       "POST",
			Path:         "/v1/documents",
			PathSegments: []string{"v1", "documents"},
			Body:         good,
		}), models.Permit)

	expectOutcome(t, "untagged title",
		runUserStory(t, "google.docs", policy, unusedAPI{}, &pb.Request{
			Method:       "POST",
			Path:         "/v1/documents",
			PathSegments: []string{"v1", "documents"},
			Body:         bad,
		}), models.Deny)
}

// ---------------------------------------------------------------------------
// Sheets / 02 — Sensitive spreadsheet blocklist
// ---------------------------------------------------------------------------
//
// The user story uses `developerMetadata.orValue([]).exists(...)`, which
// relies on cel-cxx's auto-unwrap of optionals. Under cel-go semantics
// (with the runtime's optional-unwrap shim) the field is either a list
// or null, so the policy guards with an explicit `!= null` check.
func TestUserStory_Sheets02_SensitiveBlocklist(t *testing.T) {
	policy := models.Policy{
		API:    "google.sheets",
		Name:   "deny_sensitive",
		Action: `action.name == "get_spreadsheet"`,
		Condition: `!(spreadsheet.properties.title.matches("(?i)\\[(confidential|restricted|secret)\\]"))
			&& (spreadsheet.developerMetadata == null
			    || !spreadsheet.developerMetadata.exists(m,
			           m.metadataKey == "classification"
			           && m.metadataValue in ["restricted", "confidential", "pii", "secrets"]))`,
		Result: models.Permit,
	}

	api := staticAPI{bodies: map[string]map[string]any{
		"/v4/spreadsheets/clean?includeGridData=false": {
			"spreadsheetId":  "clean",
			"spreadsheetUrl": "https://docs.example/clean",
			"properties":     map[string]any{"title": "Q1 Revenue Forecast"},
			"sheets":         []any{},
		},
		"/v4/spreadsheets/secret?includeGridData=false": {
			"spreadsheetId":  "secret",
			"spreadsheetUrl": "https://docs.example/secret",
			"properties":     map[string]any{"title": "[CONFIDENTIAL] 2026 Acquisition Targets"},
			"sheets":         []any{},
		},
		"/v4/spreadsheets/pii?includeGridData=false": {
			"spreadsheetId":  "pii",
			"spreadsheetUrl": "https://docs.example/pii",
			"properties":     map[string]any{"title": "Customer Roster"},
			"sheets":         []any{},
			"developerMetadata": []any{
				map[string]any{
					"metadataKey":   "classification",
					"metadataValue": "pii",
				},
			},
		},
	}}

	expectOutcome(t, "clean sheet",
		runUserStory(t, "google.sheets", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/v4/spreadsheets/clean",
			PathSegments: []string{"v4", "spreadsheets", "clean"},
		}), models.Permit)

	expectOutcome(t, "title-flagged sheet",
		runUserStory(t, "google.sheets", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/v4/spreadsheets/secret",
			PathSegments: []string{"v4", "spreadsheets", "secret"},
		}), models.Deny)

	expectOutcome(t, "metadata-flagged sheet",
		runUserStory(t, "google.sheets", policy, api, &pb.Request{
			Method:       "GET",
			Path:         "/v4/spreadsheets/pii",
			PathSegments: []string{"v4", "spreadsheets", "pii"},
		}), models.Deny)
}

// ---------------------------------------------------------------------------
// Sheets / 04 — batchUpdate sub-request allowlist
// ---------------------------------------------------------------------------

func TestUserStory_Sheets04_BatchUpdateAllowlist(t *testing.T) {
	policy := models.Policy{
		API:    "google.sheets",
		Name:   "data_only_subrequests",
		Action: `action.name == "batch_update_spreadsheet"`,
		// The user story uses `r.keys().exists_one(k, k in [...])`; cel-go
		// has no built-in `keys()` over dyn-typed maps, so we approximate
		// with an allowlist `has(...)` for the data-mutation kinds and a
		// blocklist for the high-blast-radius structural kinds we explicitly
		// reject. Functionally equivalent for this story.
		Condition: `request.body.requests.all(r,
			(has(r.updateCells) || has(r.appendCells) || has(r.appendDimension) ||
			 has(r.insertDimension) || has(r.insertRange) || has(r.deleteRange) ||
			 has(r.pasteData) || has(r.mergeCells) || has(r.unmergeCells) ||
			 has(r.autoResizeDimensions))
			&& !has(r.deleteSheet) && !has(r.duplicateSheet) && !has(r.addSheet)
			&& !has(r.addProtectedRange) && !has(r.deleteProtectedRange)
			&& !has(r.updateProtectedRange) && !has(r.updateSpreadsheetProperties)
			&& !has(r.addNamedRange) && !has(r.deleteNamedRange) && !has(r.updateNamedRange)
		)`,
		Result: models.Permit,
	}

	api := staticAPI{bodies: map[string]map[string]any{
		"/v4/spreadsheets/s1?includeGridData=false": {
			"spreadsheetId":  "s1",
			"spreadsheetUrl": "https://docs.example/s1",
			"properties":     map[string]any{"title": "Sales"},
			"sheets":         []any{},
		},
	}}

	dataOnly := newStruct(t, map[string]any{
		"requests": []any{
			map[string]any{
				"appendCells": map[string]any{"sheetId": 0.0, "rows": []any{}},
			},
			map[string]any{
				"updateCells": map[string]any{"fields": "*"},
			},
		},
	})
	withDeleteSheet := newStruct(t, map[string]any{
		"requests": []any{
			map[string]any{
				"appendCells": map[string]any{"sheetId": 0.0, "rows": []any{}},
			},
			map[string]any{
				"deleteSheet": map[string]any{"sheetId": 0.0},
			},
		},
	})

	expectOutcome(t, "data-only batch",
		runUserStory(t, "google.sheets", policy, api, &pb.Request{
			Method:       "POST",
			Path:         "/v4/spreadsheets/s1/batchUpdate",
			PathSegments: []string{"v4", "spreadsheets", "s1", "batchUpdate"},
			Body:         dataOnly,
		}), models.Permit)

	expectOutcome(t, "deleteSheet batch",
		runUserStory(t, "google.sheets", policy, api, &pb.Request{
			Method:       "POST",
			Path:         "/v4/spreadsheets/s1/batchUpdate",
			PathSegments: []string{"v4", "spreadsheets", "s1", "batchUpdate"},
			Body:         withDeleteSheet,
		}), models.Deny)
}
