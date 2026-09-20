// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || (!amd64 && !arm64)

package confinement

import (
	"errors"
	"net"
)

// Apply refuses platforms without a reviewed native filter implementation.
func Apply(_ *net.TCPListener) error { return errors.New("network confinement unavailable") }
