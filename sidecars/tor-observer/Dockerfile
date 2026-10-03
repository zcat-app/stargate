# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T203 observer: a separate static process with only its own key, the
# finite read-only health publication and CP-only health fabric at runtime.
FROM golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c AS builder
WORKDIR /src
COPY data-plane/go.mod data-plane/go.sum ./
COPY proto/go.mod proto/go.sum /proto/
COPY data-plane/cmd/tor-observer/ ./cmd/tor-observer/
COPY data-plane/internal/torhealth/ ./internal/torhealth/
ENV CGO_ENABLED=0
RUN go build -trimpath -buildvcs=false -ldflags=-buildid= \
    -o /out/tor-observer ./cmd/tor-observer

FROM scratch
COPY --from=builder /out/tor-observer /opt/stargate/tor-observer
USER 5103:5100
ENTRYPOINT ["/opt/stargate/tor-observer"]
