# bouncer UI tests

Browser-driven end-to-end tests for the admin UI. Each test:

1. Builds the `bouncer` binary into a temp dir (once per package run).
2. Boots `bouncer serve --init` into a per-test `t.TempDir()`.
3. Spins up a headless Chromium via playwright-go.
4. Drives the wizard / dashboard, asserts DOM + backend state, and
   drops screenshots under `screenshots/<TestName>/<step>.png`.

The build tag `ui` keeps this suite out of `make ci` so a contributor
without playwright installed isn't blocked.

## Running

```sh
make ui            # from the repo root
# or directly:
go test -tags=ui -timeout 5m ./uitest/...
```

## First-time setup

playwright-go ships its own Chromium build via a one-time install
step. Run once per machine:

```sh
go run ./uitest/cmd/install-playwright
```

The binaries land in `~/.cache/ms-playwright/`. Re-runs are no-ops.

## Layout

```
uitest/
├── README.md                this file
├── helpers_test.go          spawn bouncer, login, screenshot helpers
├── wizard_test.go           end-to-end onboarding flow
├── dashboard_test.go        sidebar / tab smoke
├── cmd/install-playwright/  one-time browser-bundle downloader
└── screenshots/<test>/      written at runtime, gitignored
```
