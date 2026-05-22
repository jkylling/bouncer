# bouncer UI tests

Browser-driven end-to-end tests for the admin UI. Each test:

1. Builds the `bouncer` binary into a temp dir (once per package run).
2. Boots `bouncer serve --init` into a per-test `t.TempDir()`.
3. Spins up a headless Chromium via playwright-go.
4. Drives the dashboard, asserts DOM + backend state, and drops
   screenshots under `screenshots/<TestName>/<step>.png`.

The build tag `ui` keeps this suite out of `make ci` so a contributor
without playwright installed isn't blocked.

## Running

```sh
make ui            # from the repo root
# or directly:
go test -tags=ui -timeout 5m ./test/ui/...
```

## First-time setup

playwright-go ships its own Chromium build via a one-time install
step. Run once per machine:

```sh
go run ./test/ui/cmd/install-playwright
```

The binaries land in `~/.cache/ms-playwright/`. Re-runs are no-ops.

## Layout

```
test/ui/
├── README.md                this file
├── STORIES.md               operator-facing scenarios this suite mirrors
├── helpers_test.go          spawn bouncer, login, screenshot helpers
├── dashboard_test.go        sidebar / tab smoke
├── stories_test.go          login / logout / settings / policies deep links
├── cmd/install-playwright/  one-time browser-bundle downloader
└── screenshots/<test>/      written at runtime, gitignored
```
