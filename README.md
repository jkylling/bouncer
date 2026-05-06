# bouncer

Bouncer is a policy-enforcing HTTP proxy for safely exposing HTTP APIs to AI agents.

Existing APIs grant access at the token level — too coarse for an
agent that should read your inbox but not delete it, or post to one
channel but not the whole workspace. Bouncer sits in front of the
upstream and gates every request with narrow CEL policies. Agents
call the proxy with a bouncer-issued JWT carrying an encrypted
upstream credential; the credential never leaves the proxy and is
swapped in only on a Permit decision.

## Quickstart

### Google Workspace

```sh
# Install:
curl -fsSL https://raw.githubusercontent.com/jkylling/bouncer/main/install.sh | sh

# 1a. For simple testing, get an access token from https://developers.google.com/oauthplayground with scope https://www.googleapis.com/auth/gmail.modify
# 1b. Or follow the steps [here](https://github.com/jkylling/bouncer-gws#Authentication) to set up a Google project

# 2. Start the proxy
bouncer serve --init \
    --with-apis github.com/jkylling/bouncer-gws \
    --admin-password <secret-password>

# 3. Issue a bouncer access token from the Google access/refresh token.
BOUNCER_JWT=$(bouncer issue-token \
    --subject my-agent \
    --access-token ya29...)

# 4a. (optional) Install [gws-cli](https://github.com/googleworkspace/cli): `brew install googleworkspace-cli`
# 4b. (optional) Install [gogcli](https://github.com/openclaw/gogcli): `brew install gogcli`

# 5. (optional) Wire bouncer's MCP server into your agent harness so
#    the agent can list policies, read the traffic viewer, and propose
#    new policies through `tools/list`. Reuses the JWT from step 3 —
#    MCP read/propose tools don't need extra scopes. For Claude Code:
#       claude mcp add --transport http bouncer \
#           http://localhost:8080/_api/mcp \
#           --header "Authorization: Bearer $BOUNCER_JWT"

# 6. Hand the bouncer token to your agent and instruct it to call the
#    Google Workspace API at host localhost:8080. Or, to use gws-cli /
#    gogcli unmodified, trust bouncer's CA and route via HTTPS_PROXY:
curl -fsS http://localhost:8080/_api/ca.crt -o ca.crt && export SSL_CERT_FILE=$PWD/ca.crt HTTPS_PROXY=http://localhost:8080
#    Watch the traffic viewer at http://localhost:8080/_admin/ and
#    turn first-call traffic into proposed policies.
```

### Slack

```sh
# Install:
curl -fsSL https://raw.githubusercontent.com/jkylling/bouncer/main/install.sh | sh

# 1. Obtain Slack credentials, see [how here](http://github.com/jkylling/bouncer-slack#Authentication).

# 2. Boot the proxy with the Slack API bundle.
bouncer serve --init \
    --with-apis github.com/jkylling/bouncer-slack \
    --admin-password <secret-password>

# 3. Issue a long-lived access JWT carrying the Slack token. Slack
#    tokens don't expire, so an access JWT is enough — no refresh
#    flow needed.
BOUNCER_JWT=$(bouncer issue-token \
    --subject my-agent \
    --access-token "$SLACK_XOXC_TOKEN" \
    --header "Cookie=d=$SLACK_XOXD_VALUE" \
    --header "Origin=https://app.slack.com" \
    --header "Referer=https://app.slack.com/" \
    --ttl 240h)

# 4. (optional) Install [agent-slack](https://github.com/stablyai/agent-slack): `curl -fsSL https://raw.githubusercontent.com/stablyai/agent-slack/main/install.sh | sh`

# 5. (optional) Wire bouncer's MCP server into your agent harness so
#    the agent can list policies, read the traffic viewer, and propose
#    new policies through `tools/list`. Reuses the JWT from step 3 —
#    MCP read/propose tools don't need extra scopes. For Claude Code:
#       claude mcp add --transport http bouncer \
#           http://localhost:8080/_api/mcp \
#           --header "Authorization: Bearer $BOUNCER_JWT"

# 6. Hand the bouncer token to your agent and instruct it to call the
#    Slack API at host localhost:8080. Or, to use agent-slack
#    unmodified, trust bouncer's CA and route via HTTPS_PROXY:
curl -fsS http://localhost:8080/_api/ca.crt -o ca.crt && export SSL_CERT_FILE=$PWD/ca.crt HTTPS_PROXY=http://localhost:8080
#    Watch the traffic viewer at http://localhost:8080/_admin/ and
#    turn first-call traffic into proposed policies.
```

## Configuration

`bouncer init` (or `bouncer serve --init`) lays out a self-contained
data directory:

```
<data-dir>/
  secret.hex            32-byte server secret (mode 0600). Treat like a private key.
  admin-password.hash   bcrypt of the admin password used at /_admin/login.
  store/                sqlite databases for traffic, policies, proposals.
  apis/                 API specs. Top-level *.yaml are loose specs the operator drops in;
                        immediate subdirectories are bundles installed via `bouncer apis add`.
  policies/             CEL policies (one YAML per policy). Drop files in and restart.
  mitm-ca.crt           self-signed MITM CA certificate (skipped with --mitm=false).
  mitm-ca.key           MITM CA private key (mode 0600; skipped with --mitm=false).
  bouncer.yaml          (optional) constrains which `apis add` refs the operator allows.
```

`bouncer serve --data-dir <dir>` reads each file in place; passing
`--secret-hex`, `--apis-dir`, etc. overrides any individual derived
default. With no `--data-dir`, `serve` defaults to cwd — either an
already-initialized cwd (`cd ./bouncer-data && bouncer serve`) or,
under `--init`, a fresh cwd to bootstrap into.

The CLI prompts for an admin password on first init; pipe via
`BOUNCER_ADMIN_PASSWORD` or `--admin-password` for scripted
deployments.

## Bouncer CLI commands

All subcommands print a full help banner with examples on `--help`.
The headline surface:

| Command                       | Purpose                                                                              |
|-------------------------------|--------------------------------------------------------------------------------------|
| `bouncer init [<dir>]`        | Bootstrap a data directory: secret, admin password, MITM CA, apis/policies layout.   |
| `bouncer serve`               | Run the proxy. `--init` and `--with-apis` chain init + bundle install on first run.  |
| `bouncer apis add <ref>`      | Resolve a `github.com/<owner>/<repo>[@<ver>]` ref and install the bundle.            |
| `bouncer apis list`           | List installed bundles (and any rename overrides).                                   |
| `bouncer apis remove <name>`  | Delete an installed bundle by name.                                                  |
| `bouncer apis upgrade <name>` | Re-resolve a bundle's recorded ref against upstream.                                 |
| `bouncer issue-token`         | Issue an access JWT (stdout) or a credentials.json with a refresh JWT (`--out`).     |

### Issuing tokens

Three equivalent paths for ad-hoc access tokens:

- **CLI** — `bouncer issue-token --subject demo --access-token "$ACCESS"`. No running proxy needed.
- **HTTP API** — `POST /_api/issue/tokens` (admin-only). Same JSON body as the CLI flags.
- **HTML UI** — `GET /_admin/`, browser form.

For long-lived OAuth2 credentials with transparent refresh, pass
`--out ./credentials.json` to the CLI. The output is a Google-shaped
`credentials.json` (`client_id`, `client_secret`, `refresh_token`,
`token_uri`) that any OAuth2 client can use against the proxy.
`--token-url` defaults to Google's endpoint; override it for
Microsoft, Okta, etc. — the URL rides inside the refresh JWT, so
one proxy can serve multiple providers.


## How it works

### APIs, metas, actions, policies

The runtime is built around four concepts that compose into a single
decision per request.

- **APIs.** Each upstream is one YAML spec — identity (`name`,
  `base_url`, `path_prefixes`), the resources its policies can reason
  about, and the HTTP surface the proxy accepts. Specs live under
  `<data-dir>/apis/` (loose `*.yaml` or installed bundles). The set
  of APIs is the runtime's frozen type system; adding one needs a
  restart.
- **Metas.** A meta is a fetchable resource — Gmail's `message`,
  Drive's `file`, Slack's `channel`. It's keyed by its inputs and
  exposes output fields as CEL expressions over the upstream's
  response body. Outputs may also link to other metas
  (`message.thread = thread{thread_id: response.body.threadId}`),
  and the runtime fetches each meta lazily on first access during
  policy eval — unread fields cost nothing.
- **Actions.** One per `(method, path-template)` pair the proxy
  routes. Path captures populate a `match` map (`/users/{user_id}`
  → `match.user_id`). Each action declares which metas it binds, so
  a policy on that action sees those metas as variables in scope.
- **Policies.** YAML rules with three CEL predicates —
  `principal:` (cheapest, decides whether the rule applies to this
  caller), `action:` (which actions it gates), `condition:` (the
  actual rule, may read meta fields) — and a `result: permit|deny`.
  Deny rules run before permit; a request is forwarded only when
  *some* permit matches and *no* deny matches. No match at all is
  deny-by-default.

The flow on every proxied request: route → match action → run each
applicable policy's `principal`/`action`/`condition` chain → fetch
metas as the conditions reference them → permit or deny → forward
upstream with the embedded credential swapped.

[`bouncer-gws`](https://github.com/jkylling/bouncer-gws) (Gmail /
Drive / Calendar / Docs / Sheets) and
[`bouncer-slack`](https://github.com/jkylling/bouncer-slack) are
the reference bundles. See [`docs/apis.md`](./docs/apis.md) for
authoring a new API spec and
[`docs/policies.md`](./docs/policies.md) for the policy primer.

### Tokens

Two JWT types share an Ed25519 signing key but use distinct
ChaCha20-Poly1305 encryption keys (HKDF info `encrypt/access` vs
`encrypt/refresh`) so a refresh blob can never decrypt under the
access key:

| typ        | TTL                       | Carries                                | Where presented                              |
|------------|---------------------------|----------------------------------------|----------------------------------------------|
| `access`   | short (~upstream's TTL)   | `{access_token, headers}`              | `Authorization: Bearer …` on data plane      |
| `refresh`  | long (default no `exp`)   | `{refresh_token, token_url, headers}`  | `refresh_token` field on `POST /token` only  |

**OAuth2 refresh.** The client POSTs `token_uri` with `grant_type=
refresh_token`, the refresh JWT, and the upstream `client_id` /
`client_secret` — the same wire shape as a direct upstream refresh.
The proxy unwraps the refresh JWT, exchanges the embedded upstream
refresh token at the real upstream `/token`, and returns a fresh
access JWT. The upstream refresh token never leaves the proxy.

**API keys / custom auth headers.** Upstreams that don't use
`Authorization: Bearer` (Slack browser sessions, `X-Api-Key`,
cookie auth) carry the headers on the JWT itself: `bouncer
issue-token --header 'X-Api-Key=…'`. The proxy stamps them on every
forwarded request. Headers ride on refresh JWTs too, so rotation
preserves them.


### MITM mode (`HTTPS_PROXY` for unmodified clients)

Many SDKs hard-code the upstream URL (`https://gmail.googleapis.com`,
`https://slack.com`) and can't be redirected to a different origin.
MITM mode lets bouncer sit in front of these clients without code
changes: point them at the proxy via `HTTPS_PROXY`, trust bouncer's
CA, and the client transparently calls bouncer thinking it's the
upstream.

It's on by default. Disable with `--mitm=false`.

A localhost-bound proxy serves its public CA so the agent can
bootstrap without manual cert-copying:

```sh
curl -fsS http://localhost:8080/_api/ca.crt -o bouncer-mitm-ca.crt
export SSL_CERT_FILE=$PWD/bouncer-mitm-ca.crt
export HTTPS_PROXY=http://localhost:8080
```

`HTTPS_PROXY` points at the proxy's own listener (the same address
in `--addr`); `SSL_CERT_FILE` points at the CA you just downloaded.
Adjust both for non-local deployments.

Don't expose `/_api/ca.crt` over an untrusted network — a LAN
attacker who can answer for the proxy's host could swap CAs at
fetch time.

### Observability

Structured logs (`log/slog`) and OpenTelemetry tracing are wired
throughout. Switch the trace exporter with `--otel-exporter
{none|stdout|otlphttp}`; `otlphttp` honours the standard
`OTEL_EXPORTER_OTLP_*` env vars. Forwarded-request spans expose
`api.name`, `policy.decision`, `policy.name`, `action.name`, and
`proxy.subject`, so a log line, a traffic-viewer row, and the otel
span describing the same request all join on `trace_id`.

### Status

The proxy hot path (auth → policy eval → forward) and the OAuth2
refresh flow are complete. The control plane (`/_api/...`) exposes
the token-issue endpoints plus a small set of read-only routes
behind the admin UI; the rest (policy CRUD, proposal workflow,
traffic viewer, policy-from-request) is in progress.

`POST /token` and `/_api/issue/*` are intentionally unauthenticated
for now. Keep the listener on a trusted network until the
control-plane auth gate lands.

## Development

### Build and test

```sh
go build ./...
go test ./...                       # unit tests
make e2e                            # black-box binary tests
```

Integration tests live behind a build tag and require credentials in
`<repo>/.secrets/`:

```sh
go test -tags=integration ./internal/integration/...
```

`make ci` chains `fmt-check`, `vet`, `test`, and `e2e` — the same
sequence the GitHub Actions workflow runs, so a green local
`make ci` is a green PR.

### Repo layout

| Path                                | Purpose                                                                      |
|-------------------------------------|------------------------------------------------------------------------------|
| `cmd/bouncer/`                      | the proxy + CLI (`init`, `serve`, `apis`, `issue-token`)                     |
| `internal/auth/`                    | issue / verify access + refresh JWTs, secret derivation                      |
| `internal/auth/z85/`                | ZeroMQ Base-85 encoding (used by the JWT enc claim)                          |
| `internal/apiclient/`               | net/http-backed PhysicalApi shim (forward + side calls)                      |
| `internal/observability/`           | slog + OpenTelemetry tracer setup                                            |
| `internal/runtime/`                 | policy engine — the public Runtime + Builder surface                         |
| `internal/runtime/{compiled,messages,celenv,models}/` | engine internals + YAML schema                             |
| `internal/server/`                  | HTTP handler (proxy data plane)                                              |
| `internal/server/admin/`            | control-plane routes (UI + token-issue endpoints)                            |
| `internal/server/oauth/`            | `POST /token` (RFC 6749 refresh flow)                                        |
| `internal/server/mitm/`             | CONNECT-and-TLS-terminate forward proxy (`--mitm`)                           |
| `internal/control/`                 | control-plane primitives (tokens, bundles, policies, …)                      |
| `internal/cli/`                     | subcommand implementations                                                   |
| `internal/integration/`             | network-touching tests (build tag: `integration`)                            |
| `e2e/`                              | black-box binary tests (build tag: `e2e`)                                    |
| `testdata/apis/`                    | API specs used by tests (mirror of `bouncer-gws`)                            |
| `testdata/policies/`                | sample policy YAMLs used by tests                                            |
| `proto/`                            | `.proto` → `internal/pb/` (`Request` / `Response` / `Principal`)             |

### Cutting a release

Releases are tag-driven. Pushing a tag matching `v*` runs
`.github/workflows/release.yml`, which calls `make release` and
attaches every `dist/<cmd>-<version>-<os>-<arch>` binary plus a
`SHA256SUMS` file to a new GitHub Release page. Notes are
auto-generated from PRs merged since the previous tag, bucketed by
the categories in `.github/release.yml`.

```sh
# From a clean main, with all the changes you want in the release
# already merged:
git tag -a v0.2.0 -m "release v0.2.0"
git push origin v0.2.0
```

Pre-releases use a tag containing `-` (the workflow flips
`prerelease: true` automatically): `v0.2.0-rc1`.

The cross-compile is reproducible locally with the same Makefile the
workflow uses:

```sh
make release VERSION=v0.2.0
```


## Limitations

- **TOCTOU on meta lookups.** Policy decisions sometimes fetch
  upstream metadata (e.g. `conversations.info`) before forwarding
  the gated request. A concurrent write — through bouncer or
  external to it — can change the resource between the lookup and
  the forward. Serialising bouncer-originated writes will land in a
  future release; truly external concurrent mutations remain out of
  scope.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
