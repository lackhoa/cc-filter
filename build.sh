#!/usr/bin/env bash
# Build, test, and install cc-filter.
#
# Installs to two places:
#   1. $GOBIN (or $GOPATH/bin) — on PATH, used by the Claude Code hook (`command: cc-filter`).
#   2. ~/.cc-filter/            — where the opencode bridge plugin looks for the binary first.
#
# Works on git-bash (Windows), macOS, and Linux.
# Usage: ./build.sh [--skip-tests]
set -euo pipefail

cd "$(dirname "$0")"

# Windows needs the .exe suffix; git-bash reports MINGW*/MSYS* from `uname -s`.
binary=cc-filter
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) binary=cc-filter.exe ;;
esac

if [[ "${1:-}" != "--skip-tests" ]]; then
  echo "==> Running tests"
  go test ./...
fi

echo "==> Building + installing to GOBIN"
go install .

# Resolve where `go install` actually placed the binary.
gobin="$(go env GOBIN)"
if [[ -z "$gobin" ]]; then
  gobin="$(go env GOPATH)/bin"
fi
installed="$gobin/$binary"
if [[ ! -f "$installed" ]]; then
  echo "ERROR: expected installed binary at $installed but it's missing" >&2
  exit 1
fi

echo "==> Copying to ~/.cc-filter (for the opencode bridge plugin)"
mkdir -p "$HOME/.cc-filter"
cp "$installed" "$HOME/.cc-filter/$binary"

echo "==> Done. Installed:"
ls -la "$installed" "$HOME/.cc-filter/$binary"
