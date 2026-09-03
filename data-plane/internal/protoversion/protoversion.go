// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package protoversion is the single source of the DP's compiled-in
// inter-plane wire-version identity (wire-auth.md §5.3): the major/minor of
// the stargate.v<major> proto package this binary compiled against and the
// closed capability set it exercises. The client interceptor (T045
// client.go) announces these on every outgoing RPC; the server interceptor
// (T045 server.go) checks the peer's against them. A future stargate.v2
// bump touches exactly this one package per binary — never a call site
// (wire-auth.md §5.3; Constitution Principle II).
//
// The major is derived from the proto package name (stargate.v1 → 1): a
// major bump is a package rename to stargate.v2 plus a documented migration
// test (arch §5.3), not an edit here alone.
package protoversion

// Major is the receiver's proto major version. Additive changes never touch
// it; a breaking wire change renames the proto package (stargate.v2) and
// bumps this with a migration test (arch §5.3; control-grpc.md header).
const Major = 1

// Minor is the additive version of the stargate.v1 surface. Bumped on each
// backwards-compatible proto addition (arch §5.3); never a gate on either
// side (wire-auth.md §5.2 — equal major accepts any minor).
const Minor = 0

// Capabilities is the caller's closed set of exercised RPCs/features
// (wire-auth.md §5.4), comma-separated, ASCII, no spaces. Advisory in v1
// (the server accepts the union and never rejects on it) but ALWAYS sent so
// the v2 cut can start enforcing without a wire-shape change. Extending
// this set is same-PR-with-the-proto-service per wire-auth.md §5.4.
const Capabilities = "reload-tokens,watch-events,get-status-minimum"

// The authenticated gRPC metadata keys (wire-auth.md §5.1). HTTP/2 lowercases
// header names; both Go and Java gRPC metadata are lowercased in transit, so
// the implementations must not rely on case. Declared here next to the
// values they carry so client-set and server-checked keys cannot drift.
const (
	MetaMajor        = "x-stargate-proto-major"
	MetaMinor        = "x-stargate-proto-minor"
	MetaCapabilities = "x-stargate-capabilities"
)
