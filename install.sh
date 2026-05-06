#!/bin/sh
# Install bouncer from a GitHub release.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/jkylling/bouncer/main/install.sh | sh
#
# Environment overrides:
#   BOUNCER_VERSION  release tag to install (default: latest)
#   BOUNCER_PREFIX   install root, binaries go in $BOUNCER_PREFIX/bin (default: $HOME/.local)
#   BOUNCER_BIN      explicit bin dir; overrides $BOUNCER_PREFIX/bin
#
# The script is POSIX sh and relies only on curl, uname, mktemp,
# install, and a sha256 hasher (sha256sum on Linux, shasum on macOS).

set -eu

REPO="jkylling/bouncer"
CMDS="bouncer"
PREFIX="${BOUNCER_PREFIX:-$HOME/.local}"
BIN="${BOUNCER_BIN:-$PREFIX/bin}"

err() { printf 'install: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

need() {
    command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1"
}
need curl
need uname
need mktemp
need install

# Pick the sha256 hasher — every BSD/macOS ships shasum, Linux ships
# sha256sum. Both produce "<hex>  <file>" so the consumer is uniform.
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        err "neither sha256sum nor shasum available"
    fi
}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
    linux)  ;;
    darwin) ;;
    *) err "unsupported OS: $os (linux and darwin are supported)" ;;
esac

arch=$(uname -m)
case "$arch" in
    x86_64|amd64)   arch=amd64 ;;
    aarch64|arm64)  arch=arm64 ;;
    *) err "unsupported arch: $arch (amd64 and arm64 are supported)" ;;
esac

# Resolve VERSION via the /releases/latest redirect — the redirected
# URL ends in /tag/<version>, so we don't need a JSON parser. The
# curl is split from the parsing so a 4xx from GitHub doesn't get
# swallowed by the pipeline (POSIX sh has no `pipefail`).
version="${BOUNCER_VERSION:-}"
if [ -z "$version" ]; then
    resolved=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest") \
        || err "could not reach https://github.com/$REPO/releases/latest — does the repo have a public release?"
    case "$resolved" in
        */tag/*) version=${resolved##*/tag/} ;;
        *) err "unexpected redirect target: $resolved" ;;
    esac
    version=$(printf '%s' "$version" | tr -d '\r\n')
    [ -n "$version" ] || err "could not resolve latest version from GitHub"
fi

base="https://github.com/$REPO/releases/download/$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

log "Resolved $REPO@$version for $os/$arch"

# Pull SHA256SUMS once; verify each downloaded artefact against it.
log "Fetching SHA256SUMS"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" \
    || err "could not fetch $base/SHA256SUMS — does the release exist?"

mkdir -p "$BIN"

for cmd in $CMDS; do
    artifact="$cmd-$os-$arch"
    log "Downloading $artifact"
    curl -fsSL "$base/$artifact" -o "$tmp/$artifact" \
        || err "could not fetch $base/$artifact"

    expected=$(awk -v f="$artifact" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
    [ -n "$expected" ] \
        || err "SHA256SUMS has no entry for $artifact"

    got=$(sha256 "$tmp/$artifact" | awk '{print $1}')
    [ "$expected" = "$got" ] \
        || err "checksum mismatch for $artifact: want $expected, got $got"

    install -m 0755 "$tmp/$artifact" "$BIN/$cmd"
done

log "Installed to $BIN:"
for cmd in $CMDS; do
    printf '    %s\n' "$BIN/$cmd"
done

case ":$PATH:" in
    *":$BIN:"*) ;;
    *)
        printf '\n'
        printf 'Note: %s is not on your PATH. Add this to your shell rc:\n' "$BIN"
        # shellcheck disable=SC2016 # literal $PATH in the printed snippet
        printf '    export PATH="%s:$PATH"\n' "$BIN"
        ;;
esac
