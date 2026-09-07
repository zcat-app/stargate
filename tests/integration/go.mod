// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

module github.com/zcat-app/stargate/tests/integration

go 1.26

toolchain go1.26.3

require golang.org/x/net v0.55.0

require (
	github.com/google/gopacket v1.1.19
	github.com/zcat-app/stargate/tests/contract v0.0.0
	golang.org/x/crypto v0.51.0
	golang.org/x/sys v0.45.0 // indirect
)

// T060: the circuit-isolation integration tests read circuit state through
// the T062 cookie-authenticated control-port helper (tests/contract/tor),
// a sibling module in the same go.work workspace. The replace keeps the
// import resolvable with GOWORK=off (fresh clones without the workspace
// file, containerized builds); locally replaced modules need no go.sum
// entry. (T061 adds golang.org/x/crypto for the corpus checksum
// validation's SHA3-256.)
replace github.com/zcat-app/stargate/tests/contract => ../contract
