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

.PHONY: all build test e2e test-e2e test-e2e-list e2e-vms-up e2e-vms-down fmt fmt-check vet staticcheck ci release clean help

help:
	@echo 'Targets:'
	@echo '  build      — go build all CLIs into ./bin (host platform)'
	@echo '  test       — go test ./... (excludes the e2e suite)'
	@echo '  e2e        — go test -tags=e2e ./e2e/... on the host'
	@echo '  test-e2e   — fan `make e2e` out across configured VMs (lima + tart)'
	@echo '                stops the lima VMs after success; pass KEEP_VMS=1 to keep them'
	@echo '  e2e-vms-up — provision/start every lima VM listed in E2E_LIMA_VMS'
	@echo '  e2e-vms-down — stop every lima VM listed in E2E_LIMA_VMS'
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
	@echo '  E2E_LIMA_VMS    (default: $(E2E_LIMA_VMS))'
	@echo '  E2E_TART_VMS    (default: $(E2E_TART_VMS))'
	@echo '  LIMA_WORK_DIR   (default: $(LIMA_WORK_DIR))'
	@echo '  TART_WORK_DIR   (default: $(TART_WORK_DIR))'

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
	go test -tags=e2e -timeout 5m ./e2e/...

# test-e2e: multi-arch fan-out. Drives `make e2e` inside each named
# VM. `e2e` itself only ever runs on the host that invokes it, so a
# single-host go-test run can't actually exercise a foreign arch's
# binary — that has to happen inside a VM. This target is the
# fan-out, on top of `make e2e` which is the unit of work.
#
# Assumed setup:
#   - Each lima VM listed in E2E_LIMA_VMS exists (or `e2e-vms-up`
#     will provision it from template://default — see below) and
#     each tart VM in E2E_TART_VMS already exists.
#   - The worktree is mounted inside the VM at LIMA_WORK_DIR /
#     TART_WORK_DIR (defaults match the conventional mount points
#     for each tool — override per-invocation if your launcher uses
#     a different layout).
#   - `go` (1.25+) and `make` are on PATH inside each guest.
#
# Lima auto-bind-mounts $HOME at the same path inside Linux guests,
# so LIMA_WORK_DIR defaulting to $(CURDIR) Just Works as long as
# the worktree lives under $HOME on the host. (Lima can't host
# Windows guests on macOS — Windows coverage has to go through
# tart or a separate runner.)
#
# Tart shares dirs explicitly: launch with
#   tart run --dir=src:<host-repo-root> <vm-name>
# and the directory surfaces under /Volumes/My Shared Files/src on
# the guest — TART_WORK_DIR points there.
#
# Override the matrix to match what's actually configured:
#   make test-e2e E2E_LIMA_VMS='linux-arm64' E2E_TART_VMS=
#
# Pass `-j` to fan VMs out concurrently — each `limactl shell` /
# `tart ssh` is a separate client so they don't contend.
E2E_LIMA_VMS  ?= linux-amd64 linux-arm64 alpine-arm64
E2E_TART_VMS  ?= macos-arm64
LIMA_WORK_DIR ?= $(CURDIR)
TART_WORK_DIR ?= /Volumes/My Shared Files/src

LIMA_TARGETS := $(addprefix test-e2e-lima-,$(E2E_LIMA_VMS))
TART_TARGETS := $(addprefix test-e2e-tart-,$(E2E_TART_VMS))

# Per-VM targets are defined via pattern rules below (test-e2e-lima-%
# / test-e2e-tart-%). They aren't listed in .PHONY because doing so
# would register each name with no recipe, masking the pattern
# match — GNU make then reports "Nothing to be done" instead of
# running the rule. The pattern rule itself has no file output, so
# make rebuilds it on every invocation regardless.

# test-e2e tears the lima VMs back down on success — they idle at
# ~2GB RAM each and most flows don't want them sitting around. On
# a *failed* run we leave them up so you can `limactl shell …` to
# poke at the broken state. Pass KEEP_VMS=1 to opt out of the
# teardown even on success (useful for tight iteration loops where
# the boot cost matters more than the resource drain).
KEEP_VMS ?=

test-e2e: e2e-vms-up $(LIMA_TARGETS) $(TART_TARGETS)
	@echo
	@echo "test-e2e: every configured VM passed."
	@if [ -n "$(KEEP_VMS)" ]; then \
	  echo "test-e2e: KEEP_VMS=$(KEEP_VMS) — leaving lima VMs running."; \
	else \
	  $(MAKE) --no-print-directory e2e-vms-down; \
	fi

test-e2e-list:
	@echo "lima:"
	@for vm in $(E2E_LIMA_VMS); do echo "  $$vm"; done
	@echo "tart:"
	@for vm in $(E2E_TART_VMS); do echo "  $$vm"; done

# e2e-vms-up: idempotent provision/start of every lima VM in
# E2E_LIMA_VMS. We auto-create from one of the wrapper YAMLs in
# e2e/lima/ based on a naming convention, so a fresh checkout
# can run `make test-e2e` without first hand-rolling each
# instance:
#
#   linux-{amd64,arm64}   → e2e/lima/default.yaml (Ubuntu LTS, glibc)
#   alpine-{amd64,arm64}  → e2e/lima/alpine.yaml  (musl)
#
# Each YAML wraps the corresponding lima `template://` and adds
# a `provision:` block that installs `make` + Go at the version
# pinned in go.mod (the bare templates ship with neither). First
# boot pays that cost once; subsequent `e2e-vms-up` runs just
# `limactl start` an existing instance.
#
# alpine is in the default matrix as a regression check that the
# binary stays CGO-free / glibc-free — pure-Go sqlite means it
# *should* run on musl, and we want to notice the day that stops
# being true. Names we don't recognise (e.g. windows-amd64 — lima
# can't host a Windows guest on a macOS host) are flagged with a
# pointer at what to do instead, rather than silently skipped.
#
# Cross-arch guests run under emulation and are *slow*; on Apple
# Silicon, expect linux-amd64 e2e to take many minutes. Prune the
# matrix if you don't need that coverage locally.
#
# Tart isn't covered here: tart pulls images from registries
# (cirruslabs/macos-sequoia-base, etc.) and the right tag depends
# on what you're testing — there's no neutral default to pick.
LIMA_UP_TARGETS := $(addprefix e2e-vms-up-lima-,$(E2E_LIMA_VMS))

e2e-vms-up: $(LIMA_UP_TARGETS)

e2e-vms-up-lima-%:
	@command -v limactl >/dev/null || { echo "e2e-vms-up: limactl not on PATH (https://lima-vm.io)"; exit 1; }
	@if limactl list -q | grep -qx '$*'; then \
	  status=$$(limactl list --format '{{.Status}}' '$*'); \
	  if [ "$$status" != "Running" ]; then \
	    echo "==> [lima/$*] start (was $$status)"; \
	    limactl start --tty=false '$*'; \
	  fi; \
	else \
	  case '$*' in \
	    linux-amd64)   tmpl=$(CURDIR)/e2e/lima/default.yaml; arch=x86_64;; \
	    linux-arm64)   tmpl=$(CURDIR)/e2e/lima/default.yaml; arch=aarch64;; \
	    alpine-amd64)  tmpl=$(CURDIR)/e2e/lima/alpine.yaml;  arch=x86_64;; \
	    alpine-arm64)  tmpl=$(CURDIR)/e2e/lima/alpine.yaml;  arch=aarch64;; \
	    *) echo "e2e-vms-up: no auto-provision recipe for lima vm '$*' — create it manually (limactl create --name=$* ...) or drop it from E2E_LIMA_VMS"; exit 1;; \
	  esac; \
	  echo "==> [lima/$*] create from $$tmpl (arch=$$arch)"; \
	  limactl start --tty=false --name='$*' --arch=$$arch $$tmpl; \
	fi

# e2e-vms-down: counterpart to e2e-vms-up — `limactl stop` every
# lima VM in E2E_LIMA_VMS that's currently running. We stop, not
# delete: the disk image stays on disk so the next `e2e-vms-up`
# is a fast restart rather than a full re-provision (which would
# re-run the Go bootstrap in alpine.yaml — minutes). Skips VMs
# that don't exist or aren't running, so it's safe to invoke when
# the matrix has shifted.
LIMA_DOWN_TARGETS := $(addprefix e2e-vms-down-lima-,$(E2E_LIMA_VMS))

e2e-vms-down: $(LIMA_DOWN_TARGETS)

e2e-vms-down-lima-%:
	@command -v limactl >/dev/null || { echo "e2e-vms-down: limactl not on PATH"; exit 0; }
	@if limactl list -q | grep -qx '$*'; then \
	  status=$$(limactl list --format '{{.Status}}' '$*'); \
	  if [ "$$status" = "Running" ]; then \
	    echo "==> [lima/$*] stop"; \
	    limactl stop '$*'; \
	  fi; \
	fi

# Per-VM targets share a tiny pre-flight: confirm the runner is
# installed and the named VM exists before we shell in. The two
# guards turn a confusing "command not found" / "instance not found"
# trace into one clear line, which matters when the matrix is six
# VMs deep and one is mis-spelt.
test-e2e-lima-%:
	@command -v limactl >/dev/null || { echo "test-e2e: limactl not on PATH (https://lima-vm.io)"; exit 1; }
	@limactl list -q | grep -qx '$*' || { echo "test-e2e: lima vm '$*' not found (limactl list)"; exit 1; }
	@echo "==> [lima/$*] make e2e"
	@limactl shell $* -- bash -lc 'cd "$(LIMA_WORK_DIR)" && make e2e'

test-e2e-tart-%:
	@command -v tart >/dev/null || { echo "test-e2e: tart not on PATH (https://tart.run)"; exit 1; }
	@tart get $* >/dev/null 2>&1 || { echo "test-e2e: tart vm '$*' not found (tart list)"; exit 1; }
	@echo "==> [tart/$*] make e2e"
	@tart ssh $* -- 'cd "$(TART_WORK_DIR)" && make e2e'

fmt:
	gofmt -w .

# Fail (without mutating the tree) if anything needs gofmt. Used by CI.
fmt-check:
	@out=$$(gofmt -l .); \
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
# green local `make ci` is a green workflow. test-e2e (multi-VM
# fan-out) is intentionally left out — that's the operator's
# release-side check, not the per-PR gate.
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
