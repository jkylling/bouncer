# Cross-compile release binaries for the bouncer CLIs.
#
# `make release` produces one binary per (cmd, GOOS, GOARCH) tuple
# under dist/, e.g. dist/bouncer-v0.1.0-linux-amd64. The bouncer
# stack uses pure-Go sqlite (modernc.org/sqlite), so CGO is disabled
# and no cross C toolchain is required.
#
# Stamp a release tag by passing VERSION on the command line:
#   make release VERSION=v0.1.0
# The default picks up the latest annotated git tag (falling back
# to "dev" outside a repo). COMMIT comes from `git rev-parse`.

CMDS    := bouncer
TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Hard cap on a single release binary, in MiB. Bump this when a
# legitimate addition (new bundled UI, new dependency, larger embed)
# pushes us over — but read the diff first: a 50% jump usually means
# something landed by accident.
MAX_BINARY_MB := 30

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

DIST    := dist
PKG     := github.com/jkylling/bouncer/internal/buildinfo
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT)
GOFLAGS := -trimpath -ldflags '$(LDFLAGS)'

.PHONY: all build test e2e ui fmt fmt-check vet staticcheck ci release clean help

help:
	@echo 'Targets:'
	@echo '  build      — go build all CLIs into ./bin (host platform)'
	@echo '  test       — go test ./... (excludes the e2e suite)'
	@echo '  e2e        — go test -tags=e2e ./test/e2e/... on the host'
	@echo '  fmt        — gofmt -w .'
	@echo '  fmt-check  — fail if anything in the tree needs gofmt'
	@echo '  vet        — go vet ./...'
	@echo '  staticcheck — honnef.co/go/tools/cmd/staticcheck via go tool'
	@echo '  ci         — fmt-check + vet + staticcheck + test + e2e (CI aggregator)'
	@echo '  release    — cross-compile every CMD × TARGET into ./dist'
	@echo '  clean      — rm -rf bin/ dist/'
	@echo
	@echo 'Variables:'
	@echo '  VERSION         (default: $(VERSION))'
	@echo '  COMMIT          (default: $(COMMIT))'
	@echo '  TARGETS         (default: $(TARGETS))'

all: build

build:
	@mkdir -p bin
	@for cmd in $(CMDS); do \
	  echo "  build  bin/$$cmd"; \
	  CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$$cmd ./cmd/$$cmd; \
	done

test:
	go test ./...

# e2e drives the compiled binary as a black box (subprocess + HTTP).
# Behind a build tag so the regular `make test` doesn't pay the
# go-build cost. The 5m timeout covers a slow CI box where bcrypt
# (the admin-password hash on every init) is the cliff; a local run
# finishes in well under a minute.
e2e:
	go test -tags=e2e -timeout 5m ./test/e2e/...

# ui drives a real browser via playwright-go against a real `bouncer
# serve`. Behind a separate build tag so a contributor without
# Playwright's Chromium bundle isn't blocked. One-time install:
#   go run ./test/ui/cmd/install-playwright
ui:
	go test -tags=ui -timeout 5m ./test/ui/...

# go_files lists the .go files under this module's tree, excluding
# .claude/ (agent-managed worktrees we don't own), .git/, and the
# build outputs. Used by fmt / fmt-check.
go_files = $(shell find . \
	-path ./.claude -prune -o \
	-path ./.git -prune -o \
	-path ./bin -prune -o \
	-path ./dist -prune -o \
	-name '*.go' -print)

fmt:
	@gofmt -w $(go_files)

# Fail (without mutating the tree) if anything needs gofmt. Used by CI.
fmt-check:
	@out=$$(gofmt -l $(go_files)); \
	if [ -n "$$out" ]; then \
	  echo "gofmt needed for:" >&2; \
	  echo "$$out" >&2; \
	  exit 1; \
	fi

vet:
	go vet ./...

# staticcheck via the module's `tool` directive so the version is
# pinned in go.mod / go.sum. `go tool` resolves the named tool
# without a global `go install` step on the developer or CI host.
staticcheck:
	go tool staticcheck ./...

# CI aggregator. Mirrors what .github/workflows/ci.yml runs so a
# green local `make ci` is a green workflow.
ci: fmt-check vet staticcheck test e2e

# release fans out over CMDS × TARGETS. Each call to `go build`
# drops a single binary into dist/ named so it's unambiguous when
# downloaded standalone. Windows binaries get the .exe suffix.
#
# Filenames are stable: `<cmd>-<os>-<arch>[.exe]`. The version is
# stamped *into* the binary via ldflags so `<cmd> version` reports
# it; keeping it out of the path means dist/ doesn't thrash on every
# commit (where `git describe` would shift the suffix). For the
# tag-driven Release page the tag is part of the URL anyway.
#
# Each freshly-built binary is gated by MAX_BINARY_MB — a hard cap
# so a careless dep / embed addition can't quietly bloat the
# downloaded artefact past the budget.
release: clean-dist
	@mkdir -p $(DIST)
	@max=$$(($(MAX_BINARY_MB) * 1024 * 1024)); \
	for cmd in $(CMDS); do \
	  for target in $(TARGETS); do \
	    os=$${target%/*}; arch=$${target#*/}; \
	    ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	    out=$(DIST)/$$cmd-$$os-$$arch$$ext; \
	    echo "  build  $$out"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	      go build $(GOFLAGS) -o $$out ./cmd/$$cmd || exit 1; \
	    size=$$(wc -c < "$$out"); \
	    if [ $$size -gt $$max ]; then \
	      mb=$$(awk "BEGIN { printf \"%.1f\", $$size / 1048576 }"); \
	      echo "" >&2; \
	      echo "ERROR: $$out is $${mb} MiB (cap: $(MAX_BINARY_MB) MiB)." >&2; \
	      echo "" >&2; \
	      echo "       The release size cap lives in MAX_BINARY_MB at the top of" >&2; \
	      echo "       the Makefile. Bump it if the growth is justified — but check" >&2; \
	      echo "       what landed first (new dependency? embedded asset?). A 50%" >&2; \
	      echo "       jump usually means something snuck in by accident." >&2; \
	      exit 1; \
	    fi; \
	  done; \
	done
	@echo
	@echo "Wrote release binaries to $(DIST)/ (cap: $(MAX_BINARY_MB) MiB each):"
	@ls -lh $(DIST)/ | awk 'NR>1 {printf "  %5s  %s\n", $$5, $$NF}'

clean: clean-dist
	rm -rf bin

clean-dist:
	rm -rf $(DIST)
