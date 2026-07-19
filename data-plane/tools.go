// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

//go:build tools
// +build tools

// Package tools registers build-time dependencies that production source
// files in this module do not yet import, so that `go mod tidy` records
// them as DIRECT requires in go.mod (per T002 in specs/001-tor-route/
// tasks.md, and the reproducibility property in research.md §1 / arch
// §12.1). The `tools` build tag means this file is never compiled into
// any normal build of the data plane — to compile it explicitly:
//
//	go build -tags=tools ./...
//
// Once T013 (auth), T038 / T045 (gRPC client/server), and T009
// (generated proto stubs) land, the blank imports below become real
// imports in production code and this file can be deleted.
package tools

import (
	_ "golang.org/x/net/proxy"
	_ "google.golang.org/grpc"
	_ "google.golang.org/protobuf/proto"
)
