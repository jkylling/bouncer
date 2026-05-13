# Admin UI user stories

Operator-facing behaviors the admin UI ships today. Each story is one
narrative; the test column references the playwright file/function
that exercises it end-to-end. Stories without a test row are gaps
worth filling.

**Persona:** Jonas — operator of a self-hosted bouncer running on his
laptop or a small team box, wants AI coding agents (Claude Code,
Cursor, Hermes) to safely call Google Workspace + Slack + the team's
own APIs. Not a security-team employee; comfortable in the terminal
but appreciates a UI for the bits that need state (connecting an
OAuth client, picking starter policies, approving agents).

The UI lives at `/_admin/...`; the wizard at `/_admin/onboarding/...`;
JSON CRUD endpoints at `/_api/...`. Auth is a bcrypt-hashed admin
password set via `--admin-password-hash` (or `--admin-password` for
dev), traded for an HttpOnly cookie via `POST /_api/admin/login`.

---

## 1. First-time login

> Jonas just ran `bouncer serve --init --admin-password swordfish`
> and opens `http://localhost:8080/_admin` in his browser. He expects
> to land on a login screen, type the password he just set, and
> arrive at the dashboard — same UX as any other self-hosted tool.

A naked GET to a `/_admin/...` UI route from an anonymous client
returns a 303 redirect to `/_admin/login?next=<original-path>`. The
login form POSTs to `/_api/admin/login`, which sets the
`bouncer_admin` HttpOnly + SameSite=Strict cookie and redirects to
`next` (or `/_admin/` when absent).

**Test:** every test invokes `s.login()` in `helpers_test.go` →
implicitly covered, but the redirect-when-anonymous shape isn't
asserted directly in playwright. The HTTP-level redirect is pinned by
`e2e/admin_test.go::TestAnonGETShellRedirects`.

## 2. Rejected by a wrong password

> Jonas mistypes the password. He needs to see a clear "wrong
> password" message *in the form* — not a console error he has to
> open DevTools to find.

The login JS calls `POST /_api/admin/login`; a 401 surfaces the text
"Wrong password." inline. The cookie is not set, so a subsequent
navigation to `/_admin/` re-redirects to login.

**Test:** added below as `TestLoginRejectsBadPassword`.

## 3. Logout from the settings page

> Jonas finishes for the day and wants to end his session on the
> shared dev box. The Settings tab has a Logout button he clicks; on
> success, the dashboard kicks him back to login.

`POST /_api/admin/logout` clears the cookie (sets `MaxAge=-1`). The
next navigation to `/_admin/...` redirects to login as if he'd never
authenticated.

**Test:** added below as `TestLogoutEndsSession`.

## 4. Walk the three-step onboarding wizard

> Jonas runs bouncer for the first time and lands on the dashboard.
> He hits "Set up" (or browses to `/_admin/onboarding/connect`) and
> walks the wizard: pick a service, paste credentials, pick a recipe,
> get a connect-an-agent install snippet, see his agent show up as
> pending, approve it.

Each step navigates by URL (`/connect → /policies → /agent → /_admin/`)
with state read from the backend on entry. The "Continue" button
between steps does not currently POST through the UI — the wizard
test pokes the backend out-of-band to advance state.

**Test:** `uitest/wizard_test.go::TestWizardFlow` covers the happy
path end-to-end including pending → approved.

## 5. Connect a service by pasting OAuth credentials

> Jonas already has a Google OAuth client in his GCP console. He
> copies the `client_id` / `client_secret` / `refresh_token` triple
> into the textarea on Step 1 and hits Continue.

Posts to `POST /_api/connections/{provider}`. The list endpoint
returns the connection with `provider` + `client_id` visible but
`client_secret` and `refresh_token` zeroed — the wizard's design
explicitly avoids re-rendering secrets after the initial paste.

**Test:** secret redaction is pinned inside
`uitest/wizard_test.go::TestWizardFlow` (the "Secrets must not leak"
assertion after step 1).

## 6. Preview a recipe before applying it

> Jonas doesn't trust an "Apply" button that does something he can't
> see. At Step 2 he opens the Two-label Gmail fence recipe, sees the
> generated CEL/YAML preview, then clicks Apply.

`POST /_api/recipes/{id}/preview` renders the YAML + policy list
without persisting. `POST /_api/recipes/{id}/apply` writes through
`policies.Service.Create`.

**Test:** preview is asserted inside
`uitest/wizard_test.go::TestWizardFlow`.

## 7. Pick an agent harness on Step 3

> Jonas runs Cursor (not Claude Code). On Step 3 he clicks the
> "Cursor" tab; the panel below it should swap to Cursor-specific
> install copy.

Each `.conn-tab` toggles the matching `.conn-panel` to active. The
Hermes tab carries a "first-party" badge; others are equivalent.

**Test:** tab swap is asserted inside
`uitest/wizard_test.go::TestWizardFlow`.

## 8. Approve a pending agent

> An agent (Cursor on Jonas's laptop) finishes its self-registration
> and posts to `/_api/agents/register`. Jonas, watching the
> dashboard, sees a `pending` row appear and clicks Approve. The row
> flips to `approved` and the agent can proceed.

`POST /_api/agents/{id}/approve` flips status; the row's classes
update via the list re-render.

**Test:** approval is the closing assertion in
`uitest/wizard_test.go::TestWizardFlow`.

## 9. Reject a pending agent

> A request arrives from a fingerprint Jonas doesn't recognize. He
> clicks Reject; the row turns into a `rejected` tag, and the agent
> never gets a usable JWT.

Symmetric to Approve but `POST /_api/agents/{id}/reject` with an
optional reason.

**Test:** added below as `TestRejectPendingAgent`.

## 10. Navigate between dashboard tabs without re-logging-in

> Jonas clicks between Traffic / Policies / Agents / Connections /
> Settings in the sidebar without his session needing to re-auth.

Each tab is a full page navigation (no SPA) but the cookie persists.
Heading reads `<feature>` for each tab.

**Test:** `uitest/dashboard_test.go::TestDashboardTabs` walks each
tab and asserts its h1.

## 11. Inspect every registered API

> Jonas is drafting a policy and needs to see which actions are
> available on `gmail` and `drive`. The APIs tab lists every API
> bouncer has loaded, with its actions and meta blocks, in a
> collapsible card per API.

`GET /_api/apis` backs it. Apis from a bundle carry a `readme_url`
the operator can follow.

**Test:** smoke covered by `TestDashboardTabs`; deeper content
assertion left as a gap (the test fixture loads zero bundles).

## 12. See workspace info on the Settings tab

> Jonas wants to confirm his data dir, version, and the MITM CA
> download link without rummaging through `bouncer serve --help`.

Settings renders mode, admin API base, and a download link for the
MITM CA cert.

**Test:** added below as `TestSettingsShowsWorkspaceInfo`.

---

## Out of scope today

- **Editing or creating policies through the UI.** Phase 2 of the
  policies page is a render-only viewer; mutation happens via
  `/_api/policies` and the proposal review surface.
- **Reviewing proposals from a UI button** (the proposals tab
  renders the queue but the editor is not playwright-tested yet).
- **Traffic-row expand / pin from the UI.** Backend pin exists; the
  click-to-expand handler is rendered but the test suite only smokes
  the tab heading.

These are roadmap items rather than missing tests for shipped UX.
