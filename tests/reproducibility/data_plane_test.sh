#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T075: compare the bytes produced by two independent builds of the pinned
# data-plane builder stage. Docker image metadata is deliberately excluded:
# arch §12.1 promises reproducible binaries, and image timestamps are not
# part of that property.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

dockerfile="$repo_root/data-plane/Dockerfile"
if ! command -v docker >/dev/null 2>&1; then
  echo "FAIL: Docker is required for the T075 reproducibility comparison" >&2
  exit 1
fi
if [ ! -f "$dockerfile" ]; then
  echo "FAIL: missing $dockerfile" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "FAIL: Docker daemon is unavailable for the T075 reproducibility comparison" >&2
  exit 1
fi

builder_image="$(sed -nE 's/^FROM ([^[:space:]]+).* AS builder$/\1/p' "$dockerfile" | head -n 1)"
if [ -z "$builder_image" ] || [[ "$builder_image" != *@sha256:* ]]; then
  echo "FAIL: builder base image is missing or not digest-pinned in $dockerfile" >&2
  exit 1
fi
platform="$(docker info --format '{{.OSType}}/{{.Architecture}}' 2>/dev/null)" || {
  echo "FAIL: could not determine the local Docker platform" >&2
  exit 1
}
if [ -z "$platform" ]; then
  echo "FAIL: Docker returned an empty platform" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/stargate-t075.XXXXXX")"
resource_id="${tmp_dir##*.}"
image_one="stargate-t075:${resource_id}-one"
image_two="stargate-t075:${resource_id}-two"
container_one="stargate-t075-${resource_id}-one"
container_two="stargate-t075-${resource_id}-two"

cleanup() {
  local status=$?
  trap - EXIT
  docker rm -f "$container_one" "$container_two" >/dev/null 2>&1 || true
  docker image rm -f "$image_one" "$image_two" >/dev/null 2>&1 || true
  rm -rf -- "$tmp_dir"
  exit "$status"
}
trap cleanup EXIT

echo "T075 builder image: $builder_image"
echo "T075 platform: $platform (both builds use this host platform)"

build_and_extract() {
  local ordinal="$1" image="$2" container="$3" output="$4"
  echo "T075 build $ordinal/2: clean Docker builder target"
  docker build --no-cache --target builder --file data-plane/Dockerfile \
    --tag "$image" .
  docker create --name "$container" "$image" >/dev/null
  docker cp "$container:/out/stargate-proxy" "$output"
  docker rm "$container" >/dev/null
  if [ ! -s "$output" ]; then
    echo "FAIL: build $ordinal produced a missing or empty /out/stargate-proxy" >&2
    return 1
  fi
}

build_and_extract 1 "$image_one" "$container_one" "$tmp_dir/stargate-proxy.one"
build_and_extract 2 "$image_two" "$container_two" "$tmp_dir/stargate-proxy.two"
if ! cmp -s "$tmp_dir/stargate-proxy.one" "$tmp_dir/stargate-proxy.two"; then
  echo "FAIL: independent data-plane builder outputs differ" >&2
  exit 1
fi

echo "PASS: two independent $platform builds produced identical nonempty data-plane binaries."
