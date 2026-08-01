#!/usr/bin/env bash
#
# Build pocketwg (WireGuard client-tunnel manager) as fully-static binaries for multiple
# targets. CGO is disabled, so each binary is self-contained (no libc) and runs on
# glibc or musl systems alike — generic Linux clients, routers, SBCs, embedded devices.
#
# Usage: ./build.sh [arch ...]      default: arm64 amd64 arm mipsle
#   arch = a valid GOARCH (arm64, amd64, arm, mipsle, mips, riscv64, 386, ...)
# Output: ./dist/pocketwg-<arch>
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ARCHES="${*:-arm64 amd64 arm mipsle}"

docker run --rm -v "$HERE":/src -w /src golang:1.23 bash -euo pipefail -c '
  go env -w GOFLAGS=-mod=mod
  go mod download
  mkdir -p dist
  for a in '"$ARCHES"'; do
    armenv=""; [ "$a" = "arm" ] && armenv="GOARM=7"
    echo "  building pocketwg-$a"
    env CGO_ENABLED=0 GOOS=linux GOARCH="$a" $armenv \
        go build -trimpath -ldflags="-s -w" -o "dist/pocketwg-$a" .
  done
  ls -la dist
'
echo "Done -> $HERE/dist/"
