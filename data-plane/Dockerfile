# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# data-plane/Dockerfile — Stargate Go data-plane container.
#
# Multi-stage build:
#   1. builder stage uses the pinned Go toolchain (matches data-plane/go.mod
#      `toolchain go1.26.3`, research.md §1) to compile a statically-linked
#      stargate-proxy binary with the byte-reproducible flags from
#      data-plane/Makefile (-trimpath -buildvcs=false -ldflags=-buildid=,
#      CGO_ENABLED=0; arch §12.1).
#   2. runtime stage is FROM scratch — the data plane is a "dumb router"
#      (Principle I): no TLS termination, no DNS resolution, no payload
#      parsing, so it needs no CA bundle, no /etc/resolv.conf, no glibc.
#      Zero attack surface in the runtime.
#
# Base image is digest-pinned per Principle IV (constitution §IV). The
# digest below is the OCI image index (multi-arch manifest list) so
# `docker build` on amd64 or arm64 hosts both resolve to the exact
# tested bytes for their platform. Renovate-style automation updates
# the digest on this line; promotion is manual (Principle IV).
#
# Runtime identity: uid=5102 (stargate-dp), supplementary gid=5100
# (stargate-ipc). Numerics match T015 compose `user:` directive and
# contracts/control-grpc.md §"Socket topology". /etc/passwd and
# /etc/group are synthesised in the builder and copied into scratch so
# the symbolic name resolves at runtime (audit story / journal output).
#
# Contract status: `docker build` against this file will fail until
# T007 lands data-plane/cmd/stargate-proxy/main.go and the
# data-plane/internal/ packages exist. T075
# (tests/reproducibility/data_plane_test.sh) is the byte-for-byte
# reproducibility gate; T015 pins this image's output digest in
# compose/docker-compose.local.yml.

FROM golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c AS builder

WORKDIR /src

# Dependency-only layer: rebuilds only when go.mod / go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Synthesise the runtime passwd/group entries here so the scratch
# runtime can resolve `USER stargate-dp` symbolically without shipping
# useradd or shadow-utils.
RUN printf 'stargate-dp:x:5102:5100::/:/sbin/nologin\n' > /tmp/passwd \
 && printf 'stargate-ipc:x:5100:stargate-dp\n'         > /tmp/group

# Source layer; targeted COPYs keep the build context small and the
# layer cache friendly (re-runs only when source actually changes).
COPY cmd/      ./cmd/
COPY internal/ ./internal/

# Build flags duplicate data-plane/Makefile (arch §12.1 is the
# authority; the Makefile and this Dockerfile are two consumers of the
# same flag set). CGO_ENABLED=0 yields a statically-linked binary that
# runs against scratch.
ENV CGO_ENABLED=0
RUN go build \
      -trimpath \
      -buildvcs=false \
      -ldflags=-buildid= \
      -o /out/stargate-proxy \
      ./cmd/stargate-proxy

# -----------------------------------------------------------------------------

FROM scratch

COPY --from=builder /tmp/passwd         /etc/passwd
COPY --from=builder /tmp/group          /etc/group
COPY --from=builder /out/stargate-proxy /opt/stargate/stargate-proxy

USER stargate-dp
WORKDIR /opt/stargate
ENTRYPOINT ["/opt/stargate/stargate-proxy"]
