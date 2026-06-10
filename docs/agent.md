# bouncer — agent guide

This proxy fronts a fixed set of upstream APIs (Google Workspace,
your own services, etc.) and gates every inbound request through a
policy engine. Each request is matched to a registered API + action
and either forwarded to the upstream with the JWT-embedded upstream
credential, or denied.

You — the agent or operator-script — present a Bearer JWT issued by
this proxy. The JWT itself carries the upstream credential (access
token + any extra headers); bouncer is stateless about it.

## Getting a JWT

The operator issues a JWT for the service you need on the
`/_admin/tokens` page (or via the `bouncer issue-token` CLI) and
hands it to you. You set it as a Bearer header on every request
against the proxy. There is no per-agent registration step.

## Authentication

Every data-plane request must carry an access JWT in the
`Authorization` header:

```
Authorization: Bearer <access-jwt>
```

The JWT is issued by one of:

- `/_admin/tokens` — operator UI. Pick a service + token variant, fill
  in the declared fields (access token, refresh token + client pair,
  cookies, …), copy the JWT.
- `bouncer issue-token` — operator CLI. Same shape; useful for
  scripted issuance and CI.
- `POST /token` — refresh flow. Trade a refresh JWT for a fresh
  access JWT (RFC 6749 §6).
- `POST /_api/tokens/issue` — admin-only JSON issue endpoint.
  Accepts the UI form shape ({subject, service, variant, fields}) or
  a raw spec (the same JSON `bouncer issue-token` reads).
- `POST /_api/admin/login` — password-based login for the dashboard
  itself. Returns an admin JWT both as a JSON `token` and on the
  HttpOnly `auth_proxy_admin` cookie.

A request without a valid Authorization header gets `401
unauthorized`.

### MITM trust bootstrap

If the proxy is running in MITM mode (CONNECT hijack + per-SNI leaf
certs signed by an internal CA), an off-the-shelf SDK that points at
`HTTPS_PROXY=<bouncer>` will see a self-signed chain and refuse to
talk to it. Fetch the CA cert and trust it:

```
curl -fsS http://<bouncer>/_api/ca.crt -o bouncer-mitm-ca.crt
export SSL_CERT_FILE=$PWD/bouncer-mitm-ca.crt
# (or drop into the system trust store, or bake into the container image)
```

The endpoint is **open** by design — the agent fetches it before it
has any credential. Only the public certificate is exposed; the CA
private key never leaves the proxy. Localhost-only deployments are
the intended use; do not expose this endpoint over an untrusted
network where a man-in-the-middle could swap CAs at fetch time. The
endpoint returns `404` when the proxy was started with `--mitm=false`.

### Tiers

Control-plane endpoints fall into three tiers:

- **Open** — no JWT needed. Schema discovery (`/_api/apis`,
  `/_api/policies:capabilities`), the doc surface (`/_api/docs`,
  `/_api/docs/policies`, `/_api/docs/apis`), the login page
  (`/_admin/login`), and the MITM CA download (`/_api/ca.crt`) sit
  here.
- **Authenticated** — any valid JWT, admin or not. Reads on policies
  and traffic. Subject-scoped: a non-admin sees only their own
  traffic events.
- **Admin** — JWT must carry `admin: true`. Token issuance, policy
  writes, and the full traffic viewer gate here.

Anonymous calls to JSON endpoints get `401`. Anonymous browser
navigations to UI shells (`/_admin/...`) get `303` to the login
page with a `?next=` round-trip.

## Making a request

The proxy listens on `<addr>` and routes by path prefix to the
matching registered API. To issue a request, point your HTTP client
at the proxy's address with the upstream's path appended:

```
GET <proxy-addr>/gmail/v1/users/me/messages/abc HTTP/1.1
Authorization: Bearer <access-jwt>
```

The proxy:

1. Verifies the JWT.
2. Looks up the registered API whose `path_prefixes` claim the
   inbound path.
3. Picks the matching action by method + path template (or by
   `filter:` predicate).
4. Evaluates every applicable policy's `condition:` against the
   request, the matched parameters, the principal, and any meta
   side-call values.
5. Forwards the request verbatim to the upstream with the
   operator's bearer token if the decision is `permit`.

A request whose path matches no registered API returns `404 not
found` — the proxy doesn't know what to do with it.

A request whose path matches an API but is rejected by policy
returns `403 forbidden`. The body carries:

- `api` — the registered API the path-prefix routed to.
- `matched_actions` — the action names whose match logic fired on
  this request. The set you'd write a policy against to flip the
  decision (predicate over `action.name in [...]` covers them
  uniformly when they share a bind).
- `next_steps` — JSON pointers to the discovery endpoints below.

Both denial bodies carry the `next_steps` block — read them when a
denied request surprises you. The 401 / 404 paths omit `api` and
`matched_actions` since neither applies.

## MCP integration

```
POST /_api/mcp     (JSON-RPC 2.0)
```

Bouncer ships an MCP (Model Context Protocol) server that re-projects
the JSON surface above as standard `tools/list` + `resources/list`
calls. Agent harnesses (Claude Desktop, Cursor, Continue, etc.) can
wire bouncer in through their MCP integration rather than custom HTTP
plumbing — the harness handles auth and the agent reads tool
descriptions instead of hand-coded URLs.

Tools (subset of the catalogue, full list via `tools/list`):

- `list_apis` / `list_policies` / `get_policy` / `dry_run_policy`
- `propose_policy` — validates a draft; with an admin bearer it
  applies the policy directly, otherwise it returns the draft for
  the operator to surface.
- `list_traffic` / `get_traffic_event`

Resources:

- `bouncer://docs/agent`     — this page
- `bouncer://docs/policies`  — policy authoring
- `bouncer://docs/apis`      — API integration
- `bouncer://apis`           — JSON snapshot of every registered API
- `bouncer://bundles/<name>/readme` — markdown README shipped with
  an installed bundle (one entry per installed bundle that ships one)

Auth uses the same Bearer JWT as the rest of `/_api/*`. Admin-only
tools refuse with a clear message when the JWT lacks `admin: true`.

### Wiring an agent harness

Bouncer's MCP endpoint uses **pre-issued Bearer JWTs** — there is no
OAuth code-grant flow, no dynamic client registration, no
`/.well-known/oauth-*` discovery surface. (Probes to those paths
get a clean 404 with `auth_method: "pre_issued_bearer"` so a spec-
compliant harness knows to fall back.)

Issue a JWT once and configure the harness to send it on every
request:

```sh
# Admin JWT (control-plane writes — apply a propose_policy draft).
bouncer issue-token --subject claude-code --admin --access-token "$UPSTREAM_TOKEN"
```

Claude Code: `claude mcp add` with header injection, or edit the
project's `.mcp.json`:

```json
{
  "mcpServers": {
    "bouncer": {
      "type": "http",
      "url": "http://localhost:8080/_api/mcp",
      "headers": {
        "Authorization": "Bearer eyJhbGciOi…"
      }
    }
  }
}
```

Cursor / Continue / other harnesses speaking the same MCP HTTP
transport take the same shape — a JSON config that declares the URL
and an `Authorization` header. Bouncer's MCP handler doesn't reject
anonymous calls (so `tools/list` and `resources/list` still work for
discovery without a JWT), but every tool that mutates state checks
the caller's role and refuses without it.

## Discovering supported APIs

```
GET /_api/apis
```

Returns every registered API with `name`, `base_url`,
`path_prefixes`, `actions` (method/path/filter/binds), and `meta`
(input/output fields). APIs sourced from an installed bundle also
carry a `readme_url` pointing at the bundle's README. This is the
canonical schema; do not assume an API exists that isn't listed
here.

### Bundle READMEs

An installed bundle (`bouncer apis add <ref>`) may ship a
top-level `README.md` describing the operator-facing knobs of that
upstream — common policy patterns, placeholder values to
substitute, gotchas. The proxy serves it as `text/markdown` at
`/_api/apis/<bundle>/readme` and over MCP at
`bouncer://bundles/<bundle>/readme`. When drafting a policy
against an API from an installed bundle, read its README first.

A typical workflow:

1. `GET /_api/apis` and pick the API for the action you need.
2. If the entry has `readme_url`, fetch it for the API author's
   guidance and any placeholder tokens worth substituting.
3. Validate the draft via `POST /_api/policies:dryRun`.
4. If you carry the `admin` claim, apply directly via `POST
   /_api/policies`. Otherwise surface the draft to the operator —
   the MCP `propose_policy` tool returns the validated draft when
   the caller isn't admin.

## Authoring

Two guides cover the two things an agent might write against this
proxy:

- [`/_api/docs/policies`](./docs/policies) — write a CEL policy that
  permits or denies a specific action. Includes a self-contained CEL
  primer (literals, optionals, list/map ops, common idioms). Read
  this when you got a `403 forbidden` and want to draft an exception,
  or when you're authoring the rule set from scratch.
- [`/_api/docs/apis`](./docs/apis) — describe a new upstream API to
  bouncer (resources, fetch URLs, actions). Read this when you're
  adding support for an upstream the proxy doesn't already front;
  the live catalogue is at [`/_api/apis`](./apis).

## Policies

Policies are the rules that gate forwarding. Each policy targets one
API + one action (predicate over actions, actually) and either
permits or denies based on a CEL expression over the request,
match captures, principal, and meta-fetched values.

```
GET /_api/policies                 # list every policy
GET /_api/policies/{api}/{name}    # one policy
POST /_api/policies                # create
PUT  /_api/policies/{api}/{name}   # replace
DELETE /_api/policies/{api}/{name} # delete
POST /_api/policies:dryRun         # validate without persisting
GET  /_api/policies:capabilities   # is the store writeable?
```

The human review surface lives at `/_admin/policies`.

If `--policies-readonly` is set on the proxy, every mutating verb
returns `403 forbidden` and the `:capabilities` endpoint reports
`writeable: false`.

## Proposing a new policy

When a request is denied and you believe the policy should be
relaxed (or you're adding coverage for an unhandled case), use the
MCP `propose_policy` tool. It validates the draft against the live
runtime; with an admin bearer it applies the policy directly, and
without one it enqueues a draft on the proposals queue at
`/_admin/proposals` for an operator to review.

```
tools/call propose_policy
{
  "api": "gmail",
  "name": "let-me-list-labels",
  "action": "action.name == \"list_labels\"",
  "condition": "true",
  "result": "permit"
}
```

The non-admin result includes `proposal_id`; surface it to the user
so they can follow up at `/_admin/proposals/<id>`. The operator may
edit the draft (the runtime re-validates the edit), then approve to
promote it into the live policy set or reject with a reason.

HTTP equivalents for non-MCP harnesses:

- `POST /_api/proposals` (any auth) — submit a draft.
- `GET /_api/proposals` — list drafts (subject-scoped for non-admin).
- `PATCH /_api/proposals/{id}` — edit a `proposed` draft.
- `POST /_api/proposals/{id}/approve` (admin) — promote into the
  live policy set.
- `POST /_api/proposals/{id}/reject` (admin) — close with a reason.

## Inspecting traffic

If `--traffic-store` is configured, every recorded request
(including denials) is queryable:

```
GET /_api/traffic                  # list recent requests
GET /_api/traffic/{id}             # one request, with binds + meta fetches
PUT /_api/traffic/{id}/pin         # pin past the byte/age budget
DELETE /_api/traffic/{id}/pin      # unpin
```

The UI is at `/_admin/traffic`.

Subjects (the JWT `sub` claim) are scoped: an unauthenticated
caller sees only its own subject's events. The viewer does not
expose other principals' traffic without operator opt-in.

## Quick troubleshooting

- `401 unauthorized` — your JWT is missing, malformed, or expired.
  Refresh via `POST /token` with your refresh JWT, or re-issue via
  `issue-token`.
- `404 not found` — the path prefix isn't registered. Check
  `GET /_api/apis` for the canonical list.
- `403 forbidden` — a policy denied your request. Look at
  `/_admin/policies` for the rule set, or call the MCP
  `propose_policy` tool to draft an exception.
- `502 bad gateway` — the upstream returned an error the proxy
  could not classify. Inspect `/_api/traffic/{id}` for the captured
  upstream status and any meta-fetch errors.
- `503 temporarily_unavailable` (on `POST /token`) — the upstream
  refused to refresh, or the upstream's TTL is too short for the
  proxy to issue a usable access JWT. Re-authenticate.

## Where the canonical schema lives

The on-disk schema files (one YAML per upstream API) are the
ground truth. The `/_api/apis` listing is generated from them at
boot. Operators can extend the catalogue by adding a YAML to
`--apis-dir` and restarting; agents should re-fetch `/_api/apis`
after a known restart to pick up new APIs.
