#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# Deterministically (re)generate the Go gRPC stubs for the stargate.v1
# surface from proto/stargate/v1/*.proto into proto/stargate/v1/grpcpb/.
#
# Host-native: uses protoc (a pinned release in ~/.local) plus the go-installed,
# version-pinned plugins protoc-gen-go and protoc-gen-go-grpc, matched to
# data-plane/go.mod (protobuf v1.36.11, grpc v1.81.1). No Docker. protoc's own
# bundled include/ supplies the well-known types (google/protobuf/timestamp.proto)
# that events.proto imports.
#
# Committed-output workflow: the generated *.pb.go are checked in (T009). Re-run
# after editing any .proto, then review the diff. A future CI drift-gate:
#     scripts/regen-proto.sh && git diff --exit-code -- proto/
#
# Idempotent: unchanged .proto sources yield no diff.

set -euo pipefail

# Make go + the toolchain reachable even from a minimal/non-login shell
# (go: /usr/local/go/bin; protoc: ~/.local/bin; plugins: $GOPATH/bin).
export PATH="/usr/local/go/bin:$HOME/.local/bin:$PATH"
command -v go >/dev/null 2>&1 || { echo "error: go not found (expected /usr/local/go/bin)" >&2; exit 1; }
export PATH="$(go env GOPATH)/bin:$PATH"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: $1 not found. $2" >&2; exit 1; }; }
need protoc             "Install a pinned protoc release into ~/.local (bin + include)."
need protoc-gen-go      "go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11"
need protoc-gen-go-grpc "go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

MODPATH="github.com/zcat-app/stargate/proto"
OUT_DIR="proto/stargate/v1/grpcpb"
INCLUDE="$HOME/.local/include"   # protoc's bundled well-known-type .proto files

echo "==> $(protoc --version)"
echo "==> generating Go stubs -> $OUT_DIR"
mkdir -p "$OUT_DIR"
( cd proto
  protoc -I . -I "$INCLUDE" \
    --go_out=. --go_opt=module="$MODPATH" \
    --go-grpc_out=. --go-grpc_opt=module="$MODPATH" \
    stargate/v1/control.proto stargate/v1/events.proto
)

echo "==> pin proto module deps (match data-plane) + tidy + compile-check"
# GOWORK=off isolates this to the proto module only; pin to data-plane's exact
# versions so the go.work workspace stays coherent.
( cd proto
  export GOWORK=off GOFLAGS=-mod=mod
  go get google.golang.org/protobuf@v1.36.11
  go get google.golang.org/grpc@v1.81.1
  go mod tidy
  go build ./...
)

echo "==> inject Apache SPDX headers into generated files"
# check-license-headers.sh globs *.go, so generated *.pb.go must carry the SPDX
# marker near the top. protoc emits none; prepend ours, leaving protoc's own
# "DO NOT EDIT" generated-file marker intact below it.
marker="SPDX-License-Identifier: Apache-2.0"
for f in "$OUT_DIR"/*.pb.go; do
  [ -e "$f" ] || { echo "error: no generated files in $OUT_DIR — codegen failed?" >&2; exit 1; }
  if ! head -n 5 "$f" | grep -qF "$marker"; then
    tmp="$(mktemp)"
    { printf '// Copyright 2026 The Stargate Authors\n// SPDX-License-Identifier: Apache-2.0\n//\n// Regenerate via scripts/regen-proto.sh — do not edit by hand.\n\n'; cat "$f"; } >"$tmp"
    mv "$tmp" "$f"
  fi
done

echo "==> done. Generated:"
ls -1 "$OUT_DIR"
