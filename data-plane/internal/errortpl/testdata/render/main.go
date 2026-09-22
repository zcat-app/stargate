// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only subprocess bridge for the contract module's internal-import boundary.
// It exposes no listener and is excluded from production builds under testdata.
package main

import (
	"bytes"
	"github.com/zcat-app/stargate/data-plane/internal/errortpl"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(64)
	}
	var response bytes.Buffer
	err := new(errortpl.Renderer).WriteFailure(&response, errortpl.ErrorCode(os.Args[1]))
	if _, e := os.Stdout.Write(response.Bytes()); e != nil {
		os.Exit(1)
	}
	if err != nil {
		os.Exit(2)
	}
}
