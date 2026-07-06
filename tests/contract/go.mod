// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

module github.com/zcat-app/stargate/tests/contract

go 1.26

toolchain go1.26.3

// Docker SDK for Go (research.md §5). The v28+ release of
// github.com/docker/docker split api/types into a separately-versioned
// github.com/docker/docker/api module that declares its own path as
// github.com/moby/moby/api — Go's toolchain rejects that path mismatch.
// We use the monolithic github.com/docker/docker v28.5.2+incompatible
// (same source tree, single module) and pin two of its transitive deps
// to versions whose public symbols still match the v28.5.2 call sites:
//
//   - github.com/docker/go-connections v0.5.0 (last release with
//     sockets.DialPipe — removed in v0.6.0+; v28.5.2 client/client.go
//     references it on Windows codepaths).
//   - github.com/docker/distribution v2.8.2+incompatible (last release
//     whose reference package still exposes SplitHostname —
//     v2.8.3's reference_deprecated.go references SplitHostname that
//     v2.8.3 itself removed; MVS would otherwise bump to v2.8.3).
//
// The client uses API-version negotiation against the host daemon
// (Docker 29.x), so v28 client ↔ v29 daemon interop is supported per
// Docker's backwards-compat policy.
require github.com/docker/docker v28.5.2+incompatible

// The stargate.v1 proto stubs (T009) live in the sibling workspace module
// github.com/zcat-app/stargate/proto — unpublished, so module-mode
// commands (`go mod tidy`) need the relative replace below; workspace
// builds resolve it via go.work either way.
replace github.com/zcat-app/stargate/proto => ../../proto

// The synthetic SOCKS5 backend (T019a's fake_socks5_tor.go) lives in
// the sibling workspace module github.com/zcat-app/stargate/tests/
// integration. Importing it from tests/contract lets the SOCKS5
// contract family (T024, T025, T025a–d, T026, T028) exercise the
// data plane's forward path against an in-process upstream rather
// than duplicating the ~400-line fake. Same unpublished-module
// rationale as the proto replace above.
replace github.com/zcat-app/stargate/tests/integration => ../integration

require (
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/distribution/reference v0.5.0 // indirect
	github.com/docker/go-connections v0.5.0
	github.com/docker/go-units v0.5.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/sys/atomicwriter v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/morikuni/aec v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.69.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)

require (
	github.com/zcat-app/stargate/proto v0.0.0-00010101000000-000000000000
	github.com/zcat-app/stargate/tests/integration v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.51.0
	google.golang.org/grpc v1.81.1
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
