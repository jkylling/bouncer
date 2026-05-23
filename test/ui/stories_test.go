//go:build ui

package ui

import (
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// TestLoginRejectsBadPassword (story 2): a wrong password surfaces
// the inline "Wrong password." status, no cookie is set, and a
// follow-up navigation to /_admin/ bounces back to the login screen.
func TestLoginRejectsBadPassword(t *testing.T) {
	// The default policy set (`demo`) permits anonymous on /_admin/,
	// so the post-bad-password redirect-back-to-login assertion only
	// holds under the auth-required `simple` set. Story is about the
	// login gate; pin the mode that has one.
	proc := startBouncerCustom(t, nil, "--internal-policies", "simple")
	s := newSession(t, proc)
	// The bad password POST returns 401, which the browser logs as a
	// console.error on the failed fetch. That's the path under test —
	// whitelist it so the cleanup tripwire doesn't flag it.
	s.allowConsoleError("status of 401")

	if _, err := s.page.Goto(proc.BaseURL + "/_admin/login"); err != nil {
		t.Fatalf("goto login: %v", err)
	}
	if err := s.page.Locator(`input[name="password"]`).Fill("not-the-password"); err != nil {
		t.Fatalf("fill password: %v", err)
	}
	if _, err := s.page.ExpectResponse("**/_api/admin/login", func() error {
		return s.page.Locator(`form button[type="submit"]`).Click()
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// The page is still on /login; status text is populated.
	if err := s.page.Locator(`#status`).WaitFor(playwright.LocatorWaitForOptions{
		State: playwright.WaitForSelectorStateVisible,
	}); err != nil {
		t.Fatalf("wait status: %v", err)
	}
	text, err := s.page.Locator(`#status`).InnerText()
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !containsFold(text, "wrong password") {
		t.Fatalf("status = %q, want to contain Wrong password", text)
	}
	s.shot("bad-password-error")

	// And the cookie wasn't set: a fresh navigation to /_admin/ still
	// redirects to login.
	if _, err := s.page.Goto(proc.BaseURL + "/_admin/"); err != nil {
		t.Fatalf("goto dashboard: %v", err)
	}
	if url := s.page.URL(); !strings.Contains(url, "/_admin/login") {
		t.Fatalf("expected redirect back to login, got URL=%q", url)
	}
}

// TestLogoutEndsSession (story 3): after Settings → Sign out, the
// admin cookie is cleared and a navigation to /_admin/ redirects
// back to login.
func TestLogoutEndsSession(t *testing.T) {
	// The post-logout "redirect to login" assertion only holds under
	// the auth-required `simple` set; the default `demo` permits
	// anonymous on /_admin/, so a logged-out browser keeps loading
	// the dashboard. Story is about session termination; pin the
	// mode that gates on it.
	proc := startBouncerCustom(t, nil, "--internal-policies", "simple")
	s := newSession(t, proc)
	s.login()

	if _, err := s.page.Goto(proc.BaseURL + "/_admin/settings"); err != nil {
		t.Fatalf("goto settings: %v", err)
	}
	s.shot("settings-pre-logout")

	if _, err := s.page.ExpectResponse("**/_api/admin/logout", func() error {
		return s.page.Locator(`#logout-form button[type="submit"]`).Click()
	}); err != nil {
		t.Fatalf("submit logout: %v", err)
	}
	if err := s.page.WaitForURL(func(url string) bool {
		return strings.Contains(url, "/_admin/login")
	}); err != nil {
		t.Fatalf("wait post-logout redirect: %v", err)
	}
	s.shot("post-logout-login-page")

	// Cookie cleared: a fresh navigation to /_admin/ also bounces.
	if _, err := s.page.Goto(proc.BaseURL + "/_admin/"); err != nil {
		t.Fatalf("goto dashboard: %v", err)
	}
	if url := s.page.URL(); !strings.Contains(url, "/_admin/login") {
		t.Fatalf("expected redirect to login after logout, got URL=%q", url)
	}
}

// TestSettingsShowsWorkspaceInfo (story 12): the Settings tab
// renders the mode badge, the MITM CA download link, and a
// "Logged in as" line populated from /_api/whoami.
func TestSettingsShowsWorkspaceInfo(t *testing.T) {
	proc := startBouncer(t)
	s := newSession(t, proc)
	s.login()

	if _, err := s.page.Goto(proc.BaseURL + "/_admin/settings"); err != nil {
		t.Fatalf("goto settings: %v", err)
	}
	// The mode value is rendered statically — pin its visible text.
	mode, err := s.page.Locator(`.setting-row:has(.setting-label:text-is("Mode")) .setting-value`).First().InnerText()
	if err != nil {
		t.Fatalf("read mode: %v", err)
	}
	if !containsFold(mode, "self-hosted") {
		t.Errorf("mode = %q, want self-hosted", mode)
	}

	// The MITM CA link points at the public download endpoint.
	href, err := s.page.Locator(`a[href="/_api/ca.crt"]`).First().GetAttribute("href")
	if err != nil {
		t.Fatalf("read MITM CA link: %v", err)
	}
	if href != "/_api/ca.crt" {
		t.Errorf("MITM CA href = %q, want /_api/ca.crt", href)
	}

	// "Logged in as" is filled by an async /_api/whoami fetch — wait
	// for it to leave the placeholder ellipsis state.
	if err := s.page.Locator(`#setting-subject`).WaitFor(); err != nil {
		t.Fatalf("wait subject: %v", err)
	}
	if err := waitForNonPlaceholder(s.page.Locator(`#setting-subject`)); err != nil {
		t.Fatalf("wait subject text: %v", err)
	}
	subject, _ := s.page.Locator(`#setting-subject`).InnerText()
	if subject == "" || subject == "…" {
		t.Errorf("subject still placeholder: %q", subject)
	}
	s.shot("settings-rendered")
}

// TestPoliciesDeeplinkExpandsRow: visiting
// /_admin/policies?api=<api>&policy=<name> auto-filters the dropdown
// and expands the matching row's detail panel. This is the link the
// traffic detail emits next to each evaluated policy; if it stops
// landing on the right row, "Edit policy" from traffic becomes
// "navigate to policies and scroll for it yourself."
func TestPoliciesDeeplinkExpandsRow(t *testing.T) {
	proc := startBouncerWithAPIs(t, []string{"gmail.yaml"})
	cli, base := adminHTTP(t, proc)

	postJSON(t, cli, base+"/_api/policies", map[string]any{
		"api":       "google.gmail",
		"name":      "deeplink-target",
		"action":    "true",
		"condition": "true",
		"result":    "permit",
	}, nil)

	s := newSession(t, proc)
	s.login()
	if _, err := s.page.Goto(proc.BaseURL + "/_admin/policies?api=google.gmail&policy=deeplink-target"); err != nil {
		t.Fatalf("goto deeplink: %v", err)
	}
	// The detail row is hidden in a parked tbody until selectByKey
	// attaches it to the visible list. Wait for it to land in the
	// pl-list-body (the visible tbody).
	if err := s.page.Locator(`.pl-list-body tr.pl-detail-row`).WaitFor(); err != nil {
		t.Fatalf("detail row not attached to visible list: %v", err)
	}
	apiVal, err := s.page.Locator(`.pl-f-api`).InputValue()
	if err != nil {
		t.Fatalf("read api field: %v", err)
	}
	if apiVal != "google.gmail" {
		t.Errorf("api field = %q, want google.gmail", apiVal)
	}
	nameVal, err := s.page.Locator(`.pl-f-name`).InputValue()
	if err != nil {
		t.Fatalf("read name field: %v", err)
	}
	if nameVal != "deeplink-target" {
		t.Errorf("name field = %q, want deeplink-target", nameVal)
	}
	s.shot("policies-deeplink-expanded")
}

// waitForNonPlaceholder polls until the locator's inner text differs
// from the ellipsis placeholder. The /_api/whoami call is fast in
// tests but not synchronous with page load — without this poll the
// assertion races the fetch.
func waitForNonPlaceholder(loc playwright.Locator) error {
	page, err := loc.Page()
	if err != nil {
		return err
	}
	deadline := 5000 // ms total, ~50 iterations at 100ms
	for elapsed := 0; elapsed < deadline; elapsed += 100 {
		text, err := loc.InnerText()
		if err == nil && text != "" && text != "…" {
			return nil
		}
		page.WaitForTimeout(100)
	}
	return nil
}
