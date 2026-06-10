# Authoring policies

A bouncer policy is a YAML document describing one rule:
*for this caller, on this action, in this state, permit (or deny) the
request.* The runtime evaluates every applicable policy on every
proxied request; if no policy permits and none denies, the request is
denied by default.

This guide is self-contained — read it top to bottom and you have
enough to write a policy that compiles and matches what you intend on
the first try.

## TL;DR — the smallest working policy

```yaml
api: gmail
name: list-my-labels
action: action.name == "list_labels"
condition: "true"
result: permit
```

That permits any caller to call `list_labels` on the `gmail` API. To
install it:

```sh
curl -X POST <proxy>/_api/policies \
    -H "authorization: Bearer <admin-jwt>" \
    -H "content-type: application/json" \
    -d '{"api":"gmail","name":"list-my-labels",
         "action":"action.name == \"list_labels\"",
         "condition":"true","result":"permit"}'
```

To validate without persisting, POST the same body to
`/_api/policies:dryRun`. Non-admin agents can draft a policy via
the MCP `propose_policy` tool (or `POST /_api/proposals`); the draft
lands on the queue at `/_admin/proposals` where an operator reviews,
edits, then approves to promote it into the live policy set.

Before writing a real policy, fetch `GET /_api/apis` — the response
lists every API + every action + every meta the proxy knows about.
Your `action:` predicate must reference an action *name* that exists
there; your `condition:` may read meta fields the matched action
*binds*.

## YAML schema

```yaml
api:        <string>            # required. The API id, matching api.name in /_api/apis.
name:       <string>            # required. Unique within (api). Lowercase, dashes ok.
principal:  <CEL bool, optional># default true. Cheapest filter — runs once per request.
action:     <CEL bool>          # required. Decides which matched actions this rule applies to.
condition:  <CEL bool>          # required. The actual rule. May read meta fields.
result:     permit | deny       # required. Typo'd values fail at load time.
```

Every CEL expression is a *string* in YAML — quote, fold, or use the
`|` block scalar to keep `:` and `?` characters from confusing the
YAML parser.

Multi-document files (`---`-separated) are supported on disk; the
HTTP API takes one policy per request. The on-disk and HTTP-loaded
sets are merged at boot.

### Permit / deny ordering

Deny policies are evaluated before permit policies. A request is
forwarded only when *some* permit matches and *no* deny matches.
Practical implication:

- Default to **permit** policies. Each one is an explicit permission.
- Use **deny** policies sparingly, for invariants that must hold no
  matter which permit fires (e.g. *never forward to an external
  domain*, *never modify the immutable `Important` label*).

A request that matches no policy at all is denied — the proxy is
deny-by-default.

## What's in scope where

A policy compiles into three CEL expressions. Each runs in its own
environment with a deliberately small set of variables:

### `principal:` env

Cheapest, runs first.

| Variable    | Type                   | Notes                                           |
|-------------|------------------------|-------------------------------------------------|
| `principal` | `Principal`            | `subject`, `kind`, `scopes` (list), `attributes` (map). |
| `request`   | `Request`              | See *the request shape* below.                  |
| `now`       | `Timestamp`            | Wall-clock at request entry. See *time-based gates* below. |

No meta types, no `action`, no `match`. Use this to short-circuit
expensive policies on the wrong caller (`principal.kind == "user"`,
`"admin" in principal.scopes`).

### `action:` env

Runs once per (policy, matched action). Slightly richer.

| Variable    | Type                       | Notes                                    |
|-------------|----------------------------|------------------------------------------|
| `action`    | `map<string, dyn>`         | `{name: <action name>}` today; future fields slot in. |
| `request`   | `Request`                  |                                          |
| `match`     | `map<string, string>`      | Path-template captures (e.g. `match.user_id`). |
| `principal` | `Principal`                |                                          |
| `now`       | `Timestamp`                | Wall-clock at request entry — same value as the `principal:` env. |

Still no meta. The intent is *which actions does this policy gate?*
The canonical predicate is `action.name == "<name>"`; equivalent for
multiple is `action.name in ["a", "b"]`.

### `condition:` env

The richest env, and the one that pays for upstream side calls — meta
fields are fetched lazily on access.

| Variable        | Type                  | Notes                                       |
|-----------------|-----------------------|---------------------------------------------|
| `request`       | `Request`             |                                             |
| `action`        | `map<string, dyn>`    | Same as in the action env.                  |
| `principal`     | `Principal`           |                                             |
| `now`           | `Timestamp`           | Wall-clock at request entry — same value as the predicate envs. |
| `<meta-name>`   | `<MetaType>`          | One variable per meta the matched action binds. |

The set of `<meta-name>` variables that are *bound* depends on which
action matched. A multi-action policy has to guard each branch:

```yaml
# good — `message` is unbound while evaluating get_thread, but the
# left operand is already false so cel-go never reaches it.
condition: |
  (action.name == "get_message" && message.labelIds.exists(l, l == "AI"))
  || (action.name == "get_thread" && thread.messages.exists(m, "AI" in m.labelIds))
```

### The request shape

```protobuf
message Request {
  string method = 1;        // "GET", "POST", ...
  string path = 3;          // decoded path; in-segment %2F / %25 stay escaped
  repeated string path_segments = 4;
  repeated KeyValue query = 5;  // [{key, value}, ...]
  google.protobuf.Value body = 6;  // dyn — JSON object/array/scalar
}
message KeyValue { string key = 1; string value = 2; }
```

Idioms:

- **Header / query parameters** are a list of `{key, value}` pairs:
  ```cel
  request.query.exists(kv, kv.key == "labelIds" && kv.value == "INBOX")
  ```
  Repeat keys are preserved — `exists` matches any occurrence.
- **JSON body** is `dyn`, so `request.body.foo` works for object
  bodies, `request.body[0]` for array bodies. Wrap optional reads
  in `?` (see *optionals* below).
- **Path captures** live on `match`, not `request.path` — let the
  action template do the parsing.
- **`request.path` is slash-safe**: it is rendered from the decoded
  segments, with an encoded slash kept visible as `%2F` (and a
  literal `%` as `%25`). `/files/a%2Fb` reads as `"/files/a%2Fb"`,
  never `"/files/a/b"`, so string comparisons agree with
  `path_segments` about where the separators are.

### The principal shape

```protobuf
message Principal {
  string subject = 1;          // JWT sub claim
  string kind = 2;             // "user" | "agent" | "service"
  repeated string scopes = 3;  // ["admin", "gmail:read", ...]
  map<string, string> attributes = 4;
}
```

`principal.attributes.team`, `"admin" in principal.scopes`, etc.

### Time-based gates

`now` is a `Timestamp` captured once per request at proxy entry, so
every predicate in a multi-policy evaluation sees the same value. CEL
arithmetic on timestamps and durations works as you'd expect:

```yaml
# Permit reads of files uploaded in the last 24h. Slack returns
# `created` as Unix seconds; timestamp_seconds() casts to Timestamp.
condition: |
  timestamp_seconds(file.created) > now - duration("24h")
```

`timestamp_seconds(int) -> Timestamp` is a bouncer-specific helper —
CEL's stdlib `timestamp()` only parses RFC3339 strings, but most
upstream APIs (Slack, GitHub, syslog) expose creation times as
integer Unix seconds, so the cast is the common path.

Other patterns:

```cel
now.getDayOfWeek() in [1, 2, 3, 4, 5]   # weekdays only (Mon=1)
now.getHours("America/Los_Angeles") < 18  # business hours, PT
now < timestamp("2025-12-31T00:00:00Z") # expiring permit
```

## CEL primer

CEL is a typed expression language. Every policy CEL is a
*single expression* that evaluates to `bool` (for predicates) or to
the meta type expected at the call site (for binds, covered in the
API guide). No statements, no loops, no assignments.

### Literals

```cel
true   false                        # bool
42     -7    3.14                   # int / double
"hi"   'hi'   "tab\there"           # string (both quote styles)
b"raw" b'raw'                       # bytes
null
[1, 2, 3]                           # list
{"k": "v", "n": 42}                 # map
duration("1h30m")  timestamp("2026-05-04T00:00:00Z")
```

### Operators

Boolean: `&&  ||  !`. Short-circuit — left operand decides whether
the right runs, which is how multi-action policies guard unbound
metas.

Comparison: `==  !=  <  <=  >  >=`. Lexicographic for strings.

Arithmetic: `+  -  *  /  %`. `+` also concatenates strings and lists.

Membership: `x in collection` — works for lists, maps (key
membership), and strings (substring? no — use `.contains(s)`).

Conditional: `cond ? a : b`.

### Strings

The `ext.Strings` library is enabled, so:

```cel
"hello".startsWith("he")           # true
"hello".endsWith(":enable")        # true
"hello".contains("ell")            # true
"hello".matches("h.*o")            # regex — RE2 syntax
"hello".size()                     # 5
"a,b,c".split(",")                 # ["a","b","c"]
"a-b-c".replace("-", "/")
"  x  ".trim()
"x".upperAscii()  "X".lowerAscii()
```

### Lists

`ext.Lists` is enabled. The macros every policy uses:

```cel
xs.exists(x, <pred>)        # any element matches
xs.all(x, <pred>)           # every element matches
xs.exists_one(x, <pred>)    # exactly one
xs.filter(x, <pred>)        # sublist
xs.map(x, <expr>)           # transform
xs.size()
xs[0]                       # index — fails on out-of-bounds
```

The macros bind a fresh variable (`x` in the examples) — pick a name
that doesn't collide with anything else in scope.

### Maps

```cel
m["k"]                # explicit lookup — fails if absent
m.k                   # field selection — same, terser
"k" in m              # presence check
m.size()
m.exists(k, <pred>)   # iterate keys
```

`request.body.foo` is map field selection on a `dyn` body.

### Sets / Math

`ext.Sets` and `ext.Math` are enabled (full list in `celenv/options.go`):

```cel
sets.contains(xs, ys)       # ys ⊆ xs
sets.equivalent(xs, ys)
math.greatest(a, b, c)  math.least(...)
math.ceil(x)  math.floor(x)
```

### Optionals and meta nulls — the most important pattern

`cel.OptionalTypes` is enabled. Two cases that look similar but
behave differently:

1. **JSON body fields** are `dyn`. Reaching with `?` produces a real
   `optional<T>`; stay in optional-land until you call `.orValue` /
   `.hasValue`:

   ```cel
   request.body.?addLabelIds                 # optional<list>
   request.body.?addLabelIds.orValue([])     # list, possibly empty
   request.body.?addLabelIds.hasValue()      # bool
   ```

2. **Meta output fields** declared with `?` in their YAML expr (e.g.
   `expr: response.body.?ownedByMe`) are unwrapped on output. The
   runtime collapses *field absent* and *field set to JSON null*
   into the same `null`, so the policy sees the natural type or
   `null`:

   ```cel
   file.ownedByMe == true              # null == true → false; safe
   file.parents != null                # presence test
   ```

   Methods on null fail loudly — `headers.exists(...)` errors as
   "no such overload" when `headers` is null — so guard with
   `!= null` before reaching in:

   ```cel
   message.headers != null
   && message.headers.exists(h, h.name == "X-Agent")
   ```

   Don't reach for `.orValue` / `.hasValue` on a meta `?` field:
   those are *optional* methods, the runtime has already unwrapped,
   and the call errors at eval time. Reaching for `.orValue()` on a
   meta field is the most common cause of "no such overload" in the
   traffic viewer.

Lift a non-optional into an optional with `optional.of(x)`. **Size +
membership** is the safe way to assert "this body field has exactly
the values I expect":

```cel
request.body.?addLabelIds.orValue([]).size() == 1 &&
"Label_AI" in request.body.?addLabelIds.orValue([]) &&
request.body.?removeLabelIds.orValue([]).size() == 0
```

The codebase has a known cel-go quirk worth flagging: there is *no*
auto-unwrap from `optional<T>` to `T` even where one would obviously
succeed. Use `?field` to keep the optional, then `.orValue` /
`.hasValue` to land back on a concrete value.

### Common pitfalls (and the loud failure mode)

- **Bare action name** — `action: get_message` used to mean "the
  action with this name". It does not anymore. It now compiles as a
  CEL identifier reference and fails at load time with a clear error.
  The migration is `action: action.name == "get_message"`.

- **Misspelled `result:`** — `result: dney` is rejected at YAML load
  with line/column context, not silently coerced.

- **Unknown YAML field** — the loader runs in `KnownFields(true)`
  mode. A typo'd `conditions:` (instead of `condition:`) returns 400
  with the field name, not a 200 with a silently-dropped rule.

- **Reading an unbound meta** — a policy that targets two actions
  with different binds (`get_message` binds `message`, `list_messages`
  binds nothing) must guard each branch with `action.name == "..."`.
  Without the guard, the unbound branch hits "no such attribute" at
  evaluate time. Short-circuit `&&` is the fix.

- **Optionals everywhere in JSON bodies** — even fields the upstream
  always returns are optional in CEL because JSON makes no
  guarantees. `request.body.foo` works for an object body where `foo`
  is always present, but `request.body.?foo.orValue("")` is the safe
  default.

## Workflow — what an agent should do

1. **`GET /_api/apis`** — confirm the API exists and find the action
   you want to gate. Note its `binds:` — those are the meta variables
   you can read in `condition:`. Note each meta's `output:` — those
   are the field names you can dot into.

2. **`GET /_api/policies`** — see what's already there. Avoid
   collisions on `(api, name)`. A duplicate POST returns 409.

3. **Draft the policy.** Use `dryRun` to validate before persisting:

   ```sh
   curl -X POST <proxy>/_api/policies:dryRun \
       -H "authorization: Bearer <jwt>" \
       -H "content-type: application/json" \
       -d '{...}'
   # {"ok": true}     — compiles
   # {"ok": false, "error": "<message>"}  — fix and retry
   ```

4. **Decide the install path:**
   - **Direct CRUD** (admin JWT) — `POST /_api/policies`. Live
     immediately. For operators.
   - **MCP `propose_policy`** — any authenticated agent can call
     this tool. With an admin bearer it applies the policy; without
     one it enqueues a draft for review at `/_admin/proposals`.
   - **`POST /_api/proposals`** — the HTTP equivalent of the above
     for non-MCP harnesses.

5. **Verify.** Hit the original request again. On success, you're
   done. On `403`, read the denial body's `next_steps` — it points
   at this guide and the live policy list.

## Worked examples

### Permit list-by-label

```yaml
api: gmail
name: list-ai-labelled
action: action.name in ["list_messages", "list_threads"]
condition: |
  request.query.exists(kv,
    kv.key == "labelIds" && kv.value == "Label_AI"
  )
result: permit
```

### Permit a get when the resource carries a marker label or header

```yaml
api: gmail
name: read-ai-managed
action: action.name == "get_message"
condition: |
  "Label_AI" in message.labelIds
  || message.headers.exists(h,
       h.name == "X-AI-Managed" && h.value == "true")
result: permit
```

### Deny modify-message that touches the `Important` label

```yaml
api: gmail
name: deny-touch-important
action: action.name == "modify_message"
condition: |
  "IMPORTANT" in request.body.?addLabelIds.orValue([])
  || "IMPORTANT" in request.body.?removeLabelIds.orValue([])
result: deny
```

### Per-principal: agent-only on a sub-namespace

```yaml
api: drive
name: agents-can-list
principal: principal.kind == "agent"
action: action.name == "list_files"
condition: "true"
result: permit
```

### Cross-resource via meta — only forward to allowlisted addresses

```yaml
api: gmail
name: filter-allowlist
action: action.name == "create_filter"
condition: |
  !request.body.?action.?forward.hasValue()
  || request.body.action.forward.endsWith("@example.com")
result: permit
```

(Pair with a `deny` policy that catches every other forward target if
you want allowlist-only semantics.)
