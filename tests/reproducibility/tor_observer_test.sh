#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T081 / Principle VI: compare the observer executable from two cold builds.
# Image config timestamps are outside this byte reproducibility claim.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
dockerfile=sidecars/tor-observer/Dockerfile
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo 'SKIP: Docker unavailable for observer reproducibility' >&2
  exit 0
fi
builder="$(sed -nE 's/^FROM ([^[:space:]]+).* AS builder$/\1/p' "$dockerfile")"
if [[ "$builder" != *@sha256:* ]]; then
  echo 'FAIL: observer builder is not digest-pinned' >&2
  exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/stargate-t081-observer.XXXXXXXX")"
id="${work##*.}"
tags=("stargate-t081-observer:$id-one" "stargate-t081-observer:$id-two")
containers=()
cleanup() {
  local result=$?
  trap - EXIT
  if [ "${#containers[@]}" -gt 0 ]; then
    docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
  fi
  docker image rm "${tags[@]}" >/dev/null 2>&1 || true
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT

for ordinal in 0 1; do
  docker build --no-cache --target builder --file "$dockerfile" --tag "${tags[$ordinal]}" . \
    || { echo "FAIL: observer cold build $((ordinal + 1))" >&2; exit 1; }
  container="$(docker create "${tags[$ordinal]}")" \
    || { echo 'FAIL: cannot create observer builder container' >&2; exit 1; }
  [ -n "$container" ] || { echo 'FAIL: empty builder container ID' >&2; exit 1; }
  containers+=("$container")
  docker cp "$container:/out/tor-observer" "$work/observer-$ordinal" \
    || { echo 'FAIL: cannot extract observer binary' >&2; exit 1; }
  [ -s "$work/observer-$ordinal" ] || { echo 'FAIL: empty observer binary' >&2; exit 1; }
  docker rm "$container" >/dev/null
  containers=()
done

if ! cmp -s "$work/observer-0" "$work/observer-1"; then
  echo 'FAIL: two independent observer executable outputs differ' >&2
  exit 1
fi
printf 'PASS: observer executable byte-identical across two cold builds (sha256:%s)\n' \
  "$(sha256sum "$work/observer-0" | cut -d' ' -f1)"
