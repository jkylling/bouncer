//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/jkylling/bouncer/internal/runtime/models"
)

// Each test exercises the *discriminating* power of one policy across
// ≥2 fixture resources — a denial alongside a permit — so the meta →
// policy flow and per-resource differentiation are both covered.

// ---------------------------------------------------------------------------
// Gmail
// ---------------------------------------------------------------------------

func TestGmail_GetMessageDiscriminatesByLabel(t *testing.T) {
	publicLabel := FindGmailLabelID(t, "cedar-proxy-test/public")

	publicAlice := FindGmailMessageID(t, "cedar-proxy-test-public-from-alice")
	publicBob := FindGmailMessageID(t, "cedar-proxy-test-public-from-bob")
	privateAlice := FindGmailMessageID(t, "cedar-proxy-test-private-from-alice")
	privateBob := FindGmailMessageID(t, "cedar-proxy-test-private-from-bob")

	policy := models.Policy{
		API:       "google.gmail",
		Name:      "public_read",
		Action:    "get_message",
		Condition: fmt.Sprintf("'%s' in message.labelIds", publicLabel),
		Result:    models.Permit,
	}

	p := BuildProxy(t, "gmail", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{Path: "/gmail/v1/users/me/messages/" + publicAlice, Status: http.StatusOK},
		{Path: "/gmail/v1/users/me/messages/" + publicBob, Status: http.StatusOK},
		{Path: "/gmail/v1/users/me/messages/" + privateAlice, Status: http.StatusForbidden},
		{Path: "/gmail/v1/users/me/messages/" + privateBob, Status: http.StatusForbidden},
	})
}

func TestGmail_ListMessagesRequiresQ(t *testing.T) {
	policy := models.Policy{
		API:       "google.gmail",
		Name:      "require_q",
		Action:    "list_messages",
		Condition: "request.query.exists(kv, kv.key == 'q')",
		Result:    models.Permit,
	}
	p := BuildProxy(t, "gmail", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{
			Path:   "/gmail/v1/users/me/messages?q=subject%3Acedar-proxy-test-public-from-alice&maxResults=1",
			Status: http.StatusOK,
		},
		{
			Path:   "/gmail/v1/users/me/messages?maxResults=1",
			Status: http.StatusForbidden,
		},
	})
}

// ---------------------------------------------------------------------------
// Drive
// ---------------------------------------------------------------------------

func TestDrive_GetFileDiscriminatesByMime(t *testing.T) {
	_ = FindDriveFolder(t, "cedar-proxy-test")
	publicTxt := RequireDriveFile(t, "cedar-proxy-test-public.txt", "text/plain")
	privateTxt := RequireDriveFile(t, "cedar-proxy-test-private.txt", "text/plain")
	publicPng := RequireDriveFile(t, "cedar-proxy-test-public.png", "image/png")

	policy := models.Policy{
		API:       "google.drive",
		Name:      "text_only",
		Action:    "get_file",
		Condition: "file.mimeType.startsWith('text/')",
		Result:    models.Permit,
	}
	p := BuildProxy(t, "drive", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{Path: "/drive/v3/files/" + publicTxt, Status: http.StatusOK},
		{Path: "/drive/v3/files/" + privateTxt, Status: http.StatusOK},
		{Path: "/drive/v3/files/" + publicPng, Status: http.StatusForbidden},
	})
}

func TestDrive_GetFileDiscriminatesByName(t *testing.T) {
	publicTxt := RequireDriveFile(t, "cedar-proxy-test-public.txt", "text/plain")
	privateTxt := RequireDriveFile(t, "cedar-proxy-test-private.txt", "text/plain")
	publicPng := RequireDriveFile(t, "cedar-proxy-test-public.png", "image/png")

	policy := models.Policy{
		API:       "google.drive",
		Name:      "public_only",
		Action:    "get_file",
		Condition: "file.name.contains('public')",
		Result:    models.Permit,
	}
	p := BuildProxy(t, "drive", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{Path: "/drive/v3/files/" + publicTxt, Status: http.StatusOK},
		{Path: "/drive/v3/files/" + publicPng, Status: http.StatusOK},
		{Path: "/drive/v3/files/" + privateTxt, Status: http.StatusForbidden},
	})
}

func TestDrive_ListFilesRequiresScopedQ(t *testing.T) {
	policy := models.Policy{
		API:       "google.drive",
		Name:      "require_scoped_q",
		Action:    "list_files",
		Condition: "request.query.exists(kv, kv.key == 'q' && kv.value.contains('in parents'))",
		Result:    models.Permit,
	}
	folderID := FindDriveFolder(t, "cedar-proxy-test")
	p := BuildProxy(t, "drive", []models.Policy{policy})

	q := fmt.Sprintf("'%s' in parents and trashed = false", folderID)
	scoped := "/drive/v3/files?q=" + url.QueryEscape(q) + "&fields=files(id,name)"
	unscoped := "/drive/v3/files?fields=files(id,name)"

	p.ExpectOutcomes(t, []Outcome{
		{Path: scoped, Status: http.StatusOK},
		{Path: unscoped, Status: http.StatusForbidden},
	})
}

// ---------------------------------------------------------------------------
// Calendar
// ---------------------------------------------------------------------------

func TestCalendar_GetEventDiscriminatesBySummary(t *testing.T) {
	publicID := FindCalendarEventID(t, "cedar-proxy-test-public-event")
	privateID := FindCalendarEventID(t, "cedar-proxy-test-private-event")
	attendeeID := FindCalendarEventID(t, "cedar-proxy-test-with-attendee-event")

	policy := models.Policy{
		API:       "google.calendar",
		Name:      "public_events",
		Action:    "get_event",
		Condition: "event.summary.contains('public')",
		Result:    models.Permit,
	}
	p := BuildProxy(t, "calendar", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{Path: "/calendar/v3/calendars/primary/events/" + publicID, Status: http.StatusOK},
		{Path: "/calendar/v3/calendars/primary/events/" + privateID, Status: http.StatusForbidden},
		{Path: "/calendar/v3/calendars/primary/events/" + attendeeID, Status: http.StatusForbidden},
	})
}

func TestCalendar_GetEventOnlyWithAttendees(t *testing.T) {
	publicID := FindCalendarEventID(t, "cedar-proxy-test-public-event")
	privateID := FindCalendarEventID(t, "cedar-proxy-test-private-event")
	attendeeID := FindCalendarEventID(t, "cedar-proxy-test-with-attendee-event")

	// `event.attendees` is null when the API omits the field, the real
	// list otherwise; the size-check short-circuits null safely.
	policy := models.Policy{
		API:       "google.calendar",
		Name:      "attendees_only",
		Action:    "get_event",
		Condition: "event.attendees != null && size(event.attendees) > 0",
		Result:    models.Permit,
	}
	p := BuildProxy(t, "calendar", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{Path: "/calendar/v3/calendars/primary/events/" + attendeeID, Status: http.StatusOK},
		{Path: "/calendar/v3/calendars/primary/events/" + publicID, Status: http.StatusForbidden},
		{Path: "/calendar/v3/calendars/primary/events/" + privateID, Status: http.StatusForbidden},
	})
}

func TestCalendar_ListEventsRequiresTimeWindow(t *testing.T) {
	policy := models.Policy{
		API:    "google.calendar",
		Name:   "require_time_window",
		Action: "list_events",
		Condition: "request.query.exists(kv, kv.key == 'timeMin') && " +
			"request.query.exists(kv, kv.key == 'timeMax')",
		Result: models.Permit,
	}
	p := BuildProxy(t, "calendar", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{
			Path:   "/calendar/v3/calendars/primary/events?timeMin=2099-01-01T00:00:00Z&timeMax=2099-12-31T23:59:59Z&maxResults=5",
			Status: http.StatusOK,
		},
		{
			Path:   "/calendar/v3/calendars/primary/events?maxResults=5",
			Status: http.StatusForbidden,
		},
	})
}

// ---------------------------------------------------------------------------
// Sheets
// ---------------------------------------------------------------------------

func TestSheets_GetSpreadsheetDiscriminatesByTitle(t *testing.T) {
	publicID := EnsureSpreadsheet(t, "cedar-proxy-test-public-spreadsheet")
	privateID := EnsureSpreadsheet(t, "cedar-proxy-test-private-spreadsheet")
	sharedID := EnsureSpreadsheet(t, "cedar-proxy-test-shared-spreadsheet")

	policy := models.Policy{
		API:       "google.sheets",
		Name:      "public_only",
		Action:    "get_spreadsheet",
		Condition: "spreadsheet.properties.title.contains('public')",
		Result:    models.Permit,
	}
	p := BuildProxy(t, "sheets", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{Path: "/v4/spreadsheets/" + publicID + "?includeGridData=false", Status: http.StatusOK},
		{Path: "/v4/spreadsheets/" + privateID + "?includeGridData=false", Status: http.StatusForbidden},
		{Path: "/v4/spreadsheets/" + sharedID + "?includeGridData=false", Status: http.StatusForbidden},
	})
}

// ---------------------------------------------------------------------------
// Docs
// ---------------------------------------------------------------------------

func TestDocs_GetDocumentDiscriminatesByTitle(t *testing.T) {
	publicID := EnsureDocument(t, "cedar-proxy-test-public-document")
	privateID := EnsureDocument(t, "cedar-proxy-test-private-document")
	sharedID := EnsureDocument(t, "cedar-proxy-test-shared-document")

	policy := models.Policy{
		API:       "google.docs",
		Name:      "public_only",
		Action:    "get_document",
		Condition: "document.title.startsWith('cedar-proxy-test-public-')",
		Result:    models.Permit,
	}
	p := BuildProxy(t, "docs", []models.Policy{policy})
	p.ExpectOutcomes(t, []Outcome{
		{Path: "/v1/documents/" + publicID, Status: http.StatusOK},
		{Path: "/v1/documents/" + privateID, Status: http.StatusForbidden},
		{Path: "/v1/documents/" + sharedID, Status: http.StatusForbidden},
	})
}
