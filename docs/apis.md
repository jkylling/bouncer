# Authoring an API integration

Bouncer fronts a fixed set of upstream APIs. Each upstream is one YAML
file — a *spec* — describing the resources policies can reason about
and the HTTP actions the proxy will route. This guide tells you how
to write one.

The live catalogue is at [`GET /_api/apis`](./apis). The same JSON is
generated from the on-disk YAML at boot. Operators install a new spec
either by:

- dropping a YAML into `--apis-dir` (typically
  `<data-dir>/apis/`) and restarting, or
- vendoring a spec bundle via `bouncer apis add <ref>` (a
  GitHub-hosted bundle like `bouncer-gws`).

There is no live HTTP endpoint for adding APIs — the spec is the
runtime's frozen type system, and Build time is when the type
registry is sealed.

## What you produce

One YAML file per upstream API. The file declares:

1. **Identity & routing** — `name`, `base_url`, `path_prefixes`. The
   proxy routes by path prefix; first match wins.
2. **Meta** — every fetchable resource the API exposes. A meta is
   keyed by its inputs and produces output fields a policy can read.
   Fetched lazily on first access during a request.
3. **Actions** — one per `(method, path-template)` pair the proxy
   should accept. Each action binds the metas its policies need.

The schema in full:

```yaml
name: <api_id>                  # snake_case
base_url: https://<host>        # the upstream's origin
path_prefixes: [<prefix>, ...]  # one or more "/segment/v1"

meta:
- name: <snake_case>
  kind: endpoint
  input:
  - name: <key_field>           # one entry per parameter the meta is keyed by
  request: <CEL expr>           # produces a MetaRequest via get/post/...
  output:
  - name: <field>
    expr: <CEL over response.body, OR a meta constructor>

actions:
- name: <verb>_<resource>       # snake_case; pluralise list endpoints
  method: <GET|POST|PUT|...>    # required iff path is set
  path: /literal/{capture}/path # {name} captures a path segment into match.<name>
  filter: <optional CEL bool>   # extra match — sees request, match
  bind:  |                      # one meta to bind, single literal block
    <meta>{ key: match.x }
  binds:                        # multiple — same shape per entry
    - |
      <meta>{ key: match.x }
    - |
      <scope_meta>{ ... }
```

## CEL recap

API specs use CEL in three places: `meta.request`, `meta.output[].expr`,
and action `bind` / `binds`. Most idioms are the same as in policies
— see [`/_api/docs/policies`](./policies) for the full primer. The
parts you specifically need here:

- **HTTP-helper functions** are exposed *only* in `meta.request`:
  `get(path)`, `delete(path)`, `post(path, body)`, `put(path, body)`,
  `patch(path, body)`. They return a `MetaRequest`.
- **Constructor literals** — `<meta>{ key: value }` in any of the
  three CEL surfaces builds a meta value. The runtime fetches it
  lazily on first access. Use `{?key: optional_value}` for keys whose
  source is optional; `optional.of(x)` lifts a non-optional into an
  optional when it has to pair with a `?key:`.
- **Optionals on response bodies** — JSON makes no guarantees, so
  reach into a response body with `?` chains:
  `response.body.?action.?forward`.

## Process

For each API:

1. **Enumerate the surface.** From the upstream's REST reference,
   list every `(method, path)` pair. Your action count should match.
   Verb-suffix endpoints (`/widgets/{id}:enable`) become actions
   with a single `{...}` capture and a `filter:` narrowing
   (`match.<capture>.endsWith(':enable')`).

2. **Identify fetchable resources.** A resource is fetchable iff it
   has a single-id GET (or equivalent) returning its body. List,
   search, batch, and verb-suffix endpoints are *not* separate metas
   — they are actions that bind an existing meta.

3. **Read each resource's schema.** Note every field whose value is
   the id of *another* fetchable resource in the same API. These are
   cross-meta `output` candidates. Three sources of cross-refs:
   - **Body-derived** — the response body holds another resource's
     id (`message.threadId` → `thread`).
   - **Input-derived (parent chains)** — the meta's own input keys
     already address a parent (e.g. `permission{file_id, ...}`, so
     `permission.file = file{file_id: input.file_id}`).
   - **Same-id-space pairs** — two metas keyed by the same id but
     served behind different URLs (Drive `file` and Docs `document`
     share an id). Add the ref in *both* directions.

4. **Map endpoints to actions.** One action per `(method, path)`. Bind
   the resource(s) the URL addresses, plus any per-user / per-account
   *scope* meta the upstream has (e.g. Gmail's `mailbox`).

5. **Add cross-meta `output` entries.** For each cross-ref:
   ```yaml
   - name: <relation_name>
     expr: '<other_meta>{ key: response.body.<id_field> }'
   ```
   Use `?key: optional_value` for optional source fields. The flat id
   field can stay alongside the relation; both costs nothing.

6. **Validate.** `python3 -c "import yaml; yaml.safe_load(open('<file>'))"`
   parses. Then drop the file in `--apis-dir`, restart, and check
   `GET /_api/apis` includes the new spec with the action and meta
   counts you expect.

## Mechanics worth knowing

### Constructor literals build cross-meta links lazily

```yaml
- name: message
  ...
  output:
  - name: threadId
    expr: response.body.threadId
  - name: thread
    expr: 'thread{ user_id: input.user_id, thread_id: response.body.threadId }'
```

A policy that writes `message.thread.messages.exists(...)` triggers
the thread fetch *only* when `.thread` is dotted into. Recursion
works (`event.parent_event` returning another `event`); cycles work
(`a.b.a`).

### Optional source fields

For body fields that may be absent, use `{?key: optional_value}` so
the bind no-ops rather than fetching with an empty id:

```yaml
- name: forward_to
  expr: 'forwarding_address{?user_id: optional.of(input.user_id), ?address: response.body.?action.?forward}'
```

`optional.of(...)` is required when pairing a non-optional source
(here `input.user_id`) with `?key:` syntax — both keys must be
optional or the constructor mixes types.

### `request:` cost discipline

`request:` runs on every policy evaluation that touches the meta. Use
the cheapest variant of each GET — metadata-only projections, `fields=`
filters, `include*=false` toggles. For paginated lists pulled to
scope a resource, prefer the lightest available form. Document the
choice in a comment.

### YAML quoting traps

CEL constructor expressions and `?` chains contain `:` and `?`, both
special in YAML flow style. Two safe shapes:

- Single-quote the whole expression as a string:
  `expr: 'thread{ user_id: input.user_id }'`
- For action `bind`/`binds`, use the `|` literal block scalar:
  ```yaml
  bind: |
    message{ user_id: match.user_id, message_id: match.message_id }
  ```

Don't unquote a flow-style mapping that contains `:` — `expr:
{thread_id: x}` parses as a YAML map literal, not a CEL string.

## Naming conventions

- `snake_case` for meta names and action names.
- `<verb>_<resource>` for actions: `list_messages`, `get_message`,
  `create_message`. Pluralise list endpoints.
- When the upstream has a sub-namespace that groups many endpoints,
  mirror it as a prefix on both meta and action names so they sort
  together (e.g. `settings_` for `users.settings.*`).
- Use `id` rather than `<resource>_id` for the input key when the
  latter would collide with an output field after JSON normalisation
  — call out the choice in a comment.

## Validation checklist

Before you call the spec done:

- [ ] `bouncer apis verify <dir>` is clean. This runs the same
      manifest + parse + runtime-build chain the proxy uses at
      boot, so a verify-clean spec is one a proxy will accept.
      Auto-detects bundle vs bare apis-dir mode.
- [ ] Action count matches the upstream REST reference.
- [ ] Every meta has at least one action that binds it (else nothing
      reaches its outputs).
- [ ] Every cross-meta `output` entry uses `optional.of(...)` for
      non-optional inputs paired with `?key:` syntax.
- [ ] `bind:` values use the `|` literal block scalar; flow-style
      `expr:` values are single-quoted.
- [ ] After restarting the proxy, `GET /_api/apis` returns the spec
      with the expected action and meta counts.

## Layout

The `--apis-dir` directory mixes two shapes:

```
<apis-dir>/
  my-spec.yaml          # loose: a single API spec the operator dropped in
  another-spec.yaml
  bouncer-gws/          # bundle: any subdir with a bouncer.yaml is one
    bouncer.yaml        # manifest — schema_version, name, version,
                        # description, apis: [...]
    source.yaml         # generated by `apis add` on install
    apis/               # convention: API specs live here. The manifest
      gmail.yaml        # may list any path though, and an operator using
      drive.yaml        # a different layout is fine as long as the
                        # manifest entries point at the actual files.
    README.md           # optional; served at /_api/apis/<name>/readme
                        # and bouncer://bundles/<name>/readme over MCP.
  bouncer-slack/        # another bundle; collisions on bundle name are
    bouncer.yaml        # the operator's problem to resolve via --rename.
    apis/
      slack.yaml
```

Loose specs at the top level work for one-off additions; `bouncer
apis add` writes installed bundles into subdirectories named after
the manifest's `name:` field. Bundle names need not match the source
slug — the same upstream installed twice (different forks) collides
on the bundle name, so `--rename` or a manual fork is the workaround.

The on-disk shape of one bundle:

```
<apis-dir>/<bundle-name>/
  bouncer.yaml        # manifest — schema_version, name, version,
                      # description, apis: [...]
  source.yaml         # install record (ref, resolved_sha, fetched_at,
                      # api_renames). Generated by `apis add`.
  apis/<name>.yaml    # per-manifest paths
  README.md           # optional documentation
```

The manifest schema (full spec lives in
`internal/control/bundles/types.go`):

```yaml
schema_version: 1                     # required; only `1` is supported
name: bouncer-myservice               # required; identifier for `apis list`
version: 0.3.1                        # required; upstream's semver
description: |                        # optional; free-form prose
  One-line summary used by `apis list`.
min_proxy_version: "0.5.0"            # optional; bouncer release floor
max_proxy_version: ""                 # optional; bouncer release ceiling
apis:                                 # required; every spec the runtime
  - apis/                             # should load. Each entry is bundle-
  - extras/admin.yaml                 # root-relative; a directory entry
                                      # globs every *.yaml/*.yml inside
                                      # (non-recursive); a file entry loads
                                      # that file directly.
```

Path traversal (`..`, leading `/`) is rejected at decode time; the
loader refuses bundles whose manifest claims a path outside the
bundle root.

### Producing a bundle tarball

Two paths produce the wire-format tarball `bouncer apis add
--from-tarball` consumes:

- `bouncer apis fetch <ref> --output <path>` — resolves a GitHub
  ref to a SHA, downloads, validates, packs. Use this for any
  bundle published on GitHub.
- `bouncer apis pack <dir> --output <path> --ref <ref>` —
  local-author counterpart. Validates the manifest + every listed
  file is on disk, stamps a `source.yaml` (with the supplied
  `--ref` and a deterministic 40-hex SHA derived from the packed
  files), then packs with prefix `<name>-<version>/`. No network
  round-trip — useful when iterating on a `bouncer-<svc>` repo
  before the first push.

Both produce gzipped tar with the same shape (a single top-level
directory holding the bundle), normalised file modes (0o755 dirs,
0o644 regular files), and zero mtimes. Both also embed a
`source.yaml` so `apis add --from-tarball` knows the install
record without the operator re-supplying `--ref`:

```
bouncer apis pack ./bouncer-myservice \
    --output bundle.tar.gz \
    --ref github.com/me/bouncer-myservice@v0.3.1

bouncer apis add --from-tarball bundle.tar.gz
```

`--ref` on `apis add` overrides the embedded record when the
operator wants to install under a different identity (e.g.
testing an upstream's bundle locally before publishing).

## Worked example — Gmail in one shot

1. Fetch the Gmail REST overview → 14 resources, ~80 methods.
2. For each resource with a single-id GET, write a meta. For
   sub-resources under `users.settings.*`, prefix them `settings_`
   so they sort together.
3. For each `(method, path)`, write an action. Bind the addressed
   meta(s) plus `mailbox` (the per-user scope).
4. Read each resource's schema once more for body-derived cross-refs:
   `message.threadId`, `draft.message.threadId`,
   `filter.action.forward`, `cse_identity.primaryKeyPairId`. Add four
   cross-meta `output` entries.
5. Validate. Install. Hit `/_api/apis` to confirm.

The complete additive diff for adding a *new* upstream is roughly
*number of (method, path) pairs* + *number of fetchable resources* +
*number of cross-refs* lines. Larger upstreams (Drive's recursive
folder hierarchy, Calendar's recurrence chain) add a few more cross-
ref entries; the *kind* of edit stays the same.
