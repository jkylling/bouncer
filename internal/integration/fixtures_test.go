//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// ---------------------------------------------------------------------------
// Drive lookups + on-demand seeding.
// ---------------------------------------------------------------------------

const (
	driveListURL = "https://www.googleapis.com/drive/v3/files"

	mimeFolder = "application/vnd.google-apps.folder"
	mimeSheet  = "application/vnd.google-apps.spreadsheet"
	mimeDoc    = "application/vnd.google-apps.document"
)

// driveListResponse keeps just the fields we read.
type driveListResponse struct {
	Files []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"files"`
}

func driveList(t *testing.T, q, fields string) driveListResponse {
	t.Helper()
	access := UpstreamAccessToken(t)
	u, _ := url.Parse(driveListURL)
	v := u.Query()
	v.Set("q", q)
	v.Set("fields", fields)
	u.RawQuery = v.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("drive list: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("drive list status %s: %s", resp.Status, body)
	}
	var out driveListResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("drive list decode: %v", err)
	}
	return out
}

// FindDriveFolder returns the id of a folder named name at the Drive
// root. Fails the test if the folder does not exist.
func FindDriveFolder(t *testing.T, name string) string {
	t.Helper()
	q := fmt.Sprintf("name = '%s' and mimeType = '%s' and trashed = false and 'root' in parents",
		name, mimeFolder)
	resp := driveList(t, q, "files(id,name)")
	if len(resp.Files) == 0 {
		t.Fatalf("drive folder %q not found", name)
	}
	return resp.Files[0].ID
}

// FindDriveFile returns the id of a file matching (name, mime), or "" if
// no such file exists. Searches across all of Drive (no parent filter)
// so it works for resources seeded at the root by Sheets/Docs.
func FindDriveFile(t *testing.T, name, mime string) string {
	t.Helper()
	q := fmt.Sprintf("name = '%s' and mimeType = '%s' and trashed = false", name, mime)
	resp := driveList(t, q, "files(id,name)")
	if len(resp.Files) == 0 {
		return ""
	}
	return resp.Files[0].ID
}

// RequireDriveFile is FindDriveFile but panics the test on absence.
func RequireDriveFile(t *testing.T, name, mime string) string {
	t.Helper()
	id := FindDriveFile(t, name, mime)
	if id == "" {
		t.Fatalf("drive file %q (mime %q) not found", name, mime)
	}
	return id
}

// ---------------------------------------------------------------------------
// Gmail lookups.
// ---------------------------------------------------------------------------

// FindGmailLabelID resolves a Gmail label name to its (per-user) id.
func FindGmailLabelID(t *testing.T, name string) string {
	t.Helper()
	access := UpstreamAccessToken(t)
	req, _ := http.NewRequest("GET", "https://gmail.googleapis.com/gmail/v1/users/me/labels", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list labels: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("list labels status %s: %s", resp.Status, body)
	}
	var out struct {
		Labels []struct {
			ID, Name string
		} `json:"labels"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode labels: %v", err)
	}
	for _, l := range out.Labels {
		if l.Name == name {
			return l.ID
		}
	}
	t.Fatalf("gmail label %q not found", name)
	return ""
}

// FindGmailMessageID resolves the first message matching `subject:"X"`.
func FindGmailMessageID(t *testing.T, subject string) string {
	t.Helper()
	access := UpstreamAccessToken(t)
	q := fmt.Sprintf(`subject:"%s"`, subject)
	u, _ := url.Parse("https://gmail.googleapis.com/gmail/v1/users/me/messages")
	v := u.Query()
	v.Set("q", q)
	v.Set("maxResults", "1")
	u.RawQuery = v.Encode()
	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list messages: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("list messages status %s: %s", resp.Status, body)
	}
	var out struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	if len(out.Messages) == 0 {
		t.Fatalf("gmail message with subject %q not found", subject)
	}
	return out.Messages[0].ID
}

// ---------------------------------------------------------------------------
// Calendar lookups.
// ---------------------------------------------------------------------------

// FindCalendarEventID returns the primary-calendar event id for the
// first event whose summary equals `summary` exactly.
func FindCalendarEventID(t *testing.T, summary string) string {
	t.Helper()
	access := UpstreamAccessToken(t)
	u, _ := url.Parse("https://www.googleapis.com/calendar/v3/calendars/primary/events")
	v := u.Query()
	v.Set("q", summary)
	v.Set("maxResults", "10")
	u.RawQuery = v.Encode()
	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("list events status %s: %s", resp.Status, body)
	}
	var out struct {
		Items []struct {
			ID, Summary string
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	for _, e := range out.Items {
		if e.Summary == summary {
			return e.ID
		}
	}
	t.Fatalf("calendar event %q not found on primary", summary)
	return ""
}

// ---------------------------------------------------------------------------
// Sheets / Docs idempotent seeding.
// ---------------------------------------------------------------------------

// EnsureSpreadsheet returns the id of the spreadsheet with the given
// title, creating one if absent.
func EnsureSpreadsheet(t *testing.T, title string) string {
	t.Helper()
	if id := FindDriveFile(t, title, mimeSheet); id != "" {
		return id
	}
	access := UpstreamAccessToken(t)
	body, _ := json.Marshal(map[string]any{
		"properties": map[string]any{"title": title},
	})
	req, _ := http.NewRequest("POST", "https://sheets.googleapis.com/v4/spreadsheets",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create spreadsheet: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("create spreadsheet status %s: %s", resp.Status, raw)
	}
	var out struct {
		SpreadsheetID string `json:"spreadsheetId"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode spreadsheet: %v", err)
	}
	if out.SpreadsheetID == "" {
		t.Fatalf("spreadsheet missing spreadsheetId: %s", raw)
	}
	return out.SpreadsheetID
}

// EnsureDocument returns the id of the document with the given title,
// creating one if absent.
func EnsureDocument(t *testing.T, title string) string {
	t.Helper()
	if id := FindDriveFile(t, title, mimeDoc); id != "" {
		return id
	}
	access := UpstreamAccessToken(t)
	body, _ := json.Marshal(map[string]any{"title": title})
	req, _ := http.NewRequest("POST", "https://docs.googleapis.com/v1/documents",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create document: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("create document status %s: %s", resp.Status, raw)
	}
	var out struct {
		DocumentID string `json:"documentId"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	if out.DocumentID == "" {
		t.Fatalf("document missing documentId: %s", raw)
	}
	return out.DocumentID
}
