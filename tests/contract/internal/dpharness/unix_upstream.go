// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package dpharness

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// UnixUpstream exposes an existing synthetic TCP backend through a pathname
// Unix adapter. T168 makes the production DP incapable of TCP upstream dials;
// this test-only adapter preserves existing backend protocol/failure behavior
// while exercising the deployed transport. It runs outside the confined DP.
func UnixUpstream(t *testing.T, address string) string {
	t.Helper()
	if strings.HasPrefix(address, "unix://") {
		return address
	}
	dir, err := os.MkdirTemp("", "sg-test-adapter")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tor.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); os.RemoveAll(dir) })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				upstream, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				done := make(chan struct{})
				go func() { io.Copy(upstream, client); upstream.Close(); close(done) }()
				io.Copy(client, upstream)
				client.Close()
				<-done
			}()
		}
	}()
	return "unix://" + path
}
