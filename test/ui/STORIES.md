# Admin UI user stories

Operator-facing behaviors the admin UI ships today. Each story is one
narrative; the test column references the playwright file/function
that exercises it end-to-end.

**Persona:** Jonas — operator of a self-hosted bouncer running on his
laptop or a small team box, wants AI coding agents (Claude Code,
Cursor, …) to safely call Google Workspace + Slack + the team's own
APIs. Comfortable in the terminal but appreciates a UI for inspecting
state and issuing tokens.

The UI lives at `/_admin/...`; JSON CRUD endpoints at `/_api/...`.
Auth is a bcrypt-hashed admin password set via
`--admin-password-hash` (or `--admin-password` for dev), traded for
an HttpOnly cookie via `POST /_api/admin/login`.

---

## 1. First-time login

> Jonas just ran `bouncer serve --init --admin-password swordfish`
> and opens `http://localhost:8080/_admin` in his browser. He expects
> to land on a login screen, type the password he just set, and
> arrive at the dashboard.

A naked GET to a `/_admin/...` UI route from an anonymous client
returns a 303 redirect to `/_admin/login?next=<original-path>`. The
login form POSTs to `/_api/admin/login`, which sets the
`bouncer_admin` HttpOnly + SameSite=Strict cookie and redirects to
`next` (or `/_admin/` when absent).

## 2. Rejected by a wrong password

> Jonas mistypes the password. He needs to see a clear "wrong
> password" message *in the form*.

The login JS calls `POST /_api/admin/login`; a 401 surfaces the text
"Wrong password." inline. The cookie is not set, so a subsequent
navigation to `/_admin/` re-redirects to login.

## 3. Logout from the settings page

> Jonas finishes for the day and wants to end his session on the
> shared dev box.

`POST /_api/admin/logout` clears the cookie; the next navigation to
`/_admin/...` redirects to login.

## 4. Issue a token for a service

> Jonas wants to give Claude Code access to his Gmail. He opens
> `/_admin/tokens`, picks Google Workspace + the Access-token
> variant, pastes the token, hits Issue, copies the JWT.

`POST /_api/tokens/issue` accepts the service slug + variant ID +
field map and returns a bouncer JWT (or a refresh JWT on
`/_api/tokens/issue/refresh`). Nothing is persisted server-side.
The same form is embedded on `/_admin/services/{slug}` as the
Tokens tab, scoped to that service.

## 5. Navigate between dashboard tabs without re-logging-in

> Jonas clicks between Services / Tokens / Policies / Traffic /
> Settings in the sidebar without his session needing to re-auth.

Each tab is a full page navigation but the cookie persists.

## 6. Inspect every registered API

> Jonas is drafting a policy and needs to see which actions are
> available on `gmail` and `drive`. The Services view links into a
> per-service detail page with an APIs tab.

`GET /_api/apis` backs the underlying data. APIs from a bundle
carry a `readme_url` the operator can follow on the Docs tab.

## 7. See workspace info on the Settings tab

> Jonas wants to confirm the admin API base and the MITM CA
> download link without rummaging through `bouncer serve --help`.

Settings renders mode, admin API base, and a download link for the
MITM CA cert.

---

## Out of scope today

- **Editing or creating policies through the UI.** The policies
  page is a render-only viewer today; mutation happens via
  `/_api/policies` (admin JWT) or the MCP `propose_policy` tool.
- **Traffic-row expand / pin from the UI.** Backend pin exists;
  the click-to-expand handler is rendered but only smoke-tested.
