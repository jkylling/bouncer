# bouncer

Policy-enforcing HTTP proxy. The user-facing usage is in `README.md`;
this file is for the agent.

## Make targets

Use `make` rather than raw `go test`/`go build` so local runs match
CI. The full list lives in the `Makefile`; the ones worth knowing:

| Target          | What it does                                                                            |
|-----------------|-----------------------------------------------------------------------------------------|
| `make ci`       | `fmt-check` + `vet` + `staticcheck` + `test` + `e2e`. Mirrors `.github/workflows/ci.yml`. |
| `make test`     | Unit tests only. Excludes the `e2e` build tag.                                          |
| `make e2e`      | Black-box binary tests under `test/e2e/`. Builds the binary once, drives it as a subprocess. |
| `make fmt`      | `gofmt -w .`                                                                            |
| `make fmt-check`| Fail on gofmt drift without mutating the tree (CI gate).                                |
| `make vet`      | `go vet ./...`                                                                          |
| `make staticcheck` | `go tool staticcheck ./...` — honnef.co/go/tools pinned via the `tool` directive in go.mod. |
| `make build`    | Host-platform binaries into `./bin/`.                                                   |
| `make release`  | Cross-compile every cmd × OS/arch into `./dist/` with version stamping. Tag-driven CI.  |
| `make ui`       | Browser tests under `test/ui/`. Drives `bouncer serve` + a real Chromium via playwright-go; saves screenshots to `test/ui/screenshots/`. **Not** part of `make ci`. |

`make ci` is the per-PR gate. Run it after any non-trivial change.

Integration tests are gated by `-tags=integration` and require live
Google credentials in `<workspace-root>/.secrets/`. They are **not**
part of `make ci`. Touch them only when changing the integration
harness; ordinary changes don't need them.

```sh
go test -tags=integration ./internal/integration/...
```

Browser (`ui`) tests are gated by `-tags=ui` and require a
one-time playwright-go bundle download (~150 MB into
`~/.cache/ms-playwright/`):

```sh
go run ./test/ui/cmd/install-playwright  # once per machine
make ui                                  # ~3 s, headless
```

Touch them when changing the dashboard sidebar, the tokens-form
flow, or the wire shape any of those pages POST to
(`/_api/tokens/issue*`, `/_api/policies/*`). Ordinary changes don't
need them.

### Screenshot tool — `test/ui/cmd/screenshot`

Iterating on visuals goes through `test/ui/cmd/screenshot`. It logs
into a running bouncer, captures every dashboard page at one or
more viewports, and (optionally) screenshots the hosted-mockup as
a side-by-side reference:

```sh
# Live UI only, both wide and narrow viewports
go run ./test/ui/cmd/screenshot \
    -live http://127.0.0.1:8080 -password <admin-pw>

# Live + mockup, screenshots into /tmp/screens/
go run ./test/ui/cmd/screenshot \
    -live http://127.0.0.1:8080 -password <admin-pw> \
    -mockup file:///path/to/hosted-mockup/0/index.html \
    -out /tmp/screens
```

Use it when polishing CSS / layout — make a change, restart
bouncer, re-run the tool, open the PNGs. Headless playwright, ~1
second per page, requires the same one-time `install-playwright`
download as `make ui`.

## Documentation

Agent- and operator-facing docs live in `docs/` and are also served
at `/_api/docs/*` and over MCP as `bouncer://docs/*`:

- `docs/agent.md` — orientation: auth, request shape, MCP wiring,
  troubleshooting.
- `docs/policies.md` — CEL policy authoring + primer. Read this
  when drafting a policy or recovering from a 403.
- `docs/apis.md` — authoring a new upstream-API spec (the YAML
  schema, the enumerate-actions-and-metas process, the validation
  checklist). Read this **before** vibe-coding a new
  `bouncer-<svc>/apis/*.yaml`.

The `.md` files are the ground truth; the `docs` Go package embeds
them so `admin` and `mcp` serve byte-identical content. Edits ship
as the docs.

## Architecture

Three concentric layers. **The runtime is the load-bearing piece;
everything else is scaffolding around it.**

```
┌─────────────────────────────────────────────────────────────┐
│ control plane                                               │
│ admin UI, /_api/*, bundle install/upgrade, traffic recorder │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ data plane                                              │ │
│ │ HTTP server, OAuth2 refresh, MITM, observability        │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ runtime — policy engine                             │ │ │
│ │ │ apis + policies + actions, CEL eval, decisions      │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Runtime — `internal/runtime/`

The policy engine. Takes API specs + CEL policies + a typed
`pb.Request`/`Principal`, returns a `Decision` (Permit / Deny /
NotApplicable). **Keep it minimal, clean, and few-deps:**

- The package's only third-party dependencies are `cel-go` and
  `gopkg.in/yaml.v3` (transitively, via `models`). Don't add others.
  Anything HTTP / persistence / auth-related must live one layer up.
- The runtime is **pure logic**: no I/O, no `net/http`, no
  filesystem, no global state. The `Builder → Runtime` split freezes
  the type system at build time; only policies (self-contained) can
  be added afterwards.
- Sub-packages:
  - `compiled/` — compiled meta + policy + action types (post-CEL-compile).
  - `messages/` — type registry shared across APIs.
  - `celenv/` — CEL environment helpers + custom adapter (see memory note).
  - `models/` — YAML schema (engine input). The only entry point that touches YAML.

If a feature needs to reach outside the runtime (HTTP, DB, secrets,
clock), put it in the data or control plane and pass results in via
the existing function signatures.

### Data plane — `internal/server/` (+ `internal/auth/`, `internal/apiclient/`)

The proxy hot path: receive request → verify access JWT → ask the
runtime for a decision → forward upstream with the unwrapped
credential. Plus the OAuth2 refresh handler (`server/oauth/`) and
the optional MITM forward proxy (`server/mitm/`).

- `server/server.go` is the chi router and the public construction
  surface (`server.Load`, `server.New`).
- `auth/` owns Issue/Verify for access + refresh JWTs and the secret
  derivation. The two JWT types use distinct ChaCha20-Poly1305 keys
  (HKDF info `encrypt/access` vs `encrypt/refresh`) for domain
  separation.
- `apiclient/` is a thin `net/http` shim for upstream calls; the
  runtime sees it as an interface so tests can substitute.
- `observability/` wires slog + OpenTelemetry. `otelhttp` instruments
  inbound + upstream so a proxied request shows up as parent/child
  spans in one trace.

### Control plane — `internal/server/admin/`, `internal/control/*`, `internal/cli/*`

Operator-facing surface. Sits **around** the runtime, never inside
it.

- `server/admin/` — control-plane HTTP routes (`/_admin/...` UI +
  `/_api/...` JSON). Authentication today is admin-cookie-or-nothing.
- `control/tokens/` — in-process access-token-issue primitive shared
  by the HTTP API, the admin UI, and the CLI's `issue-token`
  subcommand.
- `control/bundles/` — apis-dir bundle install/upgrade/remove. The
  fetcher resolves a Git ref → SHA via the GitHub API, downloads the
  tarball, validates the manifest, and atomically renames into
  `<apis-dir>/<bundle-name>/`. Loose top-level `*.yaml` files in the
  same dir are loaded as single-API specs.
- `control/{policies,traffic,services,store}/` — primitives the
  control plane composes into the policy-CRUD, traffic-viewer, and
  services surfaces.
- `cli/{initcmd,serve,apiscmd,issuetoken}/` — subcommand
  implementations. `cmd/bouncer/main.go` is just argv routing.

## Invariants worth preserving

- **`internal/runtime/` keeps its small dep list.** If you find
  yourself wanting `net/http` or a database driver in there,
  something belongs further out.
- **`lib.rs`-style files contain only declarations.** Per
  user-global rules: `mod.rs` / package-level files are exports +
  doc only, not implementation. (Applies to Rust; Go uses package
  comments + `doc.go`.)
- **CLI surface changes update the e2e suite in the same change.**
  The full list of what counts as "CLI surface" is below.
- **Apis live in `testdata/apis/` for tests and in `bouncer-gws`
  (sibling repo) for production.** Don't move them back under
  `config/`. Don't duplicate.
- **`--apis-dir` default `./apis`** is the single root. Loose
  `*.yaml` at the top level are operator-dropped specs; subdirs with
  a `bouncer.yaml` are bundles installed via `bouncer apis add`. A
  `--data-dir`-driven layout overrides the default when the flag
  wasn't explicitly passed.
- **`bouncer serve` defaults `--data-dir` to cwd** when (a) cwd looks
  initialized (secret.hex + admin-password.hash present), or (b)
  `--init` is set. Lets an operator drop into their data dir and run
  a bare `bouncer serve`, or kick off a quickstart with `bouncer
  serve --init` from a fresh dir. An explicit flag or
  `$BOUNCER_DATA_DIR` always wins; an empty / uninitialized cwd
  without `--init` is never silently consumed.
- **`--mitm` defaults to true on both `init` and `serve`.** Init
  generates the CA cert; serve activates the CONNECT handler when
  the cert/key are available. Default-on with no CA available
  silently falls back to off; explicit `--mitm` with no CA still
  errors. Pass `--mitm=false` to opt out.
- **`serve --init` is idempotent.** Re-running with the same
  `--data-dir` is safe — it short-circuits via
  `initcmd.IsInitialized`. A blanket re-init would invalidate every
  JWT issued against the previous secret. The same applies to
  `--with-apis`: already-installed refs are skipped, not reinstalled.

## E2E binary tests

`test/e2e/` is a black-box suite that builds the `bouncer` binary and
drives it as a subprocess. **Whenever you change the CLI surface
area — subcommands, flags, env vars, data-dir layout, admin HTTP
routes, error messages clients depend on — update the e2e tests in
the same change.**

This includes:

- adding/removing/renaming a subcommand or flag in `cmd/bouncer`,
  `internal/cli/initcmd`, `internal/cli/issuetoken`,
  `internal/cli/serve`, `internal/cli/apiscmd`
- changing the `bouncer init` on-disk layout (file names, modes,
  contents) or what `serve --data-dir` consumes
- changing the `bouncer apis ...` verbs, the apis-dir on-disk shape
  (`<apis-dir>/<bundle-name>/` layout, `source.yaml` schema), or
  the `bouncer.yaml#apis.allowlist` rules
- changing the `/_admin/...` or `/_api/...` HTTP routes, request
  shapes, or response shapes
- changing the validation messages an operator would script against
  (e.g. the "must set --secret-hex" banner)

Run with `make e2e` (or `go test -tags=e2e ./test/e2e/...`). The suite is
behind the `e2e` build tag so it doesn't slow down `go test ./...`;
that's a convenience, not a license to skip it on a CLI change.
