# bouncer end-to-end binary tests

This package builds the `bouncer` binary and drives it as a black
box: real subprocesses, real HTTP, real on-disk data dirs. Nothing
in `internal/*` is imported. The tests behave like a CI smoke suite
that an operator could replicate by hand.

## Running

```sh
make e2e          # from the repo root
# or directly:
go test -tags=e2e -timeout 5m ./e2e/...
```

The `e2e` build tag keeps this suite out of the default `go test
./...` run — the per-package `go build` (~5s cold, <1s warm) is
only paid when explicitly requested.

A single `TestMain` compiles the binary into a per-package temp dir
and shares it across every test. Each test then writes its scratch
state under `t.TempDir()`, so a successful run leaves nothing on
disk.

## What's covered

- `init_test.go`  — `bouncer init`: layout, file modes, double-init refusal, `--force`, `--mitm`, password from env, `--help`.
- `apis_test.go`  — `bouncer apis`: help banner enumerates every verb, add (incl. `--rename`, `--from-tarball`), list, remove, upgrade, fetch, **pack** (round-trip via `add --from-tarball`), **verify** (valid bundle accepted; malformed CEL rejected with non-zero exit).
- `issuetoken_test.go` — `bouncer issue-token`: access-only mode, env-var secret, validation, credentials-file mode, `--proxy-url` normalisation, `--admin`.
- `serve_test.go` — `bouncer serve`: data-dir round-trip, cwd-auto-detect, `/_api/apis` surfaces `readme_url` + the per-bundle README route, `kind=delete` proposal round-trip, `--version` / `--help`, missing-secret refusal, flag overrides data-dir, clean SIGTERM, `--traffic-store sqlite` records a request, `--policies-readonly` rejects writes.
- `admin_test.go` — admin API + UI: login round-trip, bad password 401, anon → 303 to login, authed shell, favicon unauth, `/_api/whoami` reflects caller, `/_api/issue/tokens` and `/_api/issue/refresh` admin-only, `/_api/ca.crt` open (404 without MITM), `/_api/mcp` initialize + tools/list, logout clears cookie, `issue-token --admin` bootstrap accepted as admin.

## Cross-OS coverage (Linux / macOS / Windows)

The default suite runs on whatever OS `go test` is invoked from.
Three ways to get the binary exercised on the other targets:

### Local VM matrix (`make test-e2e`)

Drives `make e2e` inside each configured VM. Assumes the VMs
already exist and are running, with the worktree mounted inside
each guest:

```sh
make test-e2e                                    # full matrix
make test-e2e E2E_LIMA_VMS='linux-arm64'         # subset
make test-e2e -j                                 # fan out concurrently
```

Defaults assume Lima VMs named `linux-amd64` / `linux-arm64` /
`windows-amd64` and a Tart VM named `macos-arm64` (Apple Silicon
hosts only). Override `E2E_LIMA_VMS`, `E2E_TART_VMS`,
`LIMA_WORK_DIR`, or `TART_WORK_DIR` if your layout differs.

Why VMs instead of `GOOS=foo go test`: the e2e harness's TestMain
runs `go build` and then `exec`s the binary, so the spawned process
has to actually run on the target arch — cross-compiling alone
doesn't help.

### CI matrix (recommended)

Add a GitHub Actions matrix that runs `make e2e` on
`ubuntu-latest`, `macos-latest`, `windows-latest`, with a job per
`GOARCH` if you also want amd64/arm64 split. The Makefile's existing
`make release` target already cross-compiles for the same matrix
(see `TARGETS` in `../Makefile`); the e2e suite uses `go test` on
the host so `runs-on:` covers it natively.

A starting point:

```yaml
jobs:
  e2e:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - run: make e2e
```

### Ad-hoc VM

`make test-e2e` covers the common case (named VMs, mounted
worktree). For a one-off — a fresh Lima/Multipass/Vagrant VM where
you don't want a make rule — just shell in and run `make e2e`
yourself:

```sh
limactl start --name=scratch template://default
limactl shell scratch -- bash -c \
    'cd /Users/.../bouncer && make e2e'
```

The suite has no special VM hooks; whatever can run `go test
-tags=e2e ./e2e/...` is enough.

## Adding a test

1. Pick the file that matches the surface (`init_test.go`,
   `issuetoken_test.go`, `serve_test.go`, `admin_test.go`).
2. Use the helpers from `helpers_test.go`:
   - `run(t, args...)` — one-shot subcommand.
   - `mustInit(t, opts)` — bootstrap a data dir.
   - `startServe(t, opts)` — launch serve, wait for ready, register cleanup.
   - `loginAdmin(t, baseURL, password)` — return JWT + cookie.
   - `httpDo(t, client, method, url, body, hdr)` — JSON helper.
3. Keep the test body short. The harness exists so each test reads
   as "given X, hit Y, assert Z."
