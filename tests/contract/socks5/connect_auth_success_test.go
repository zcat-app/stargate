// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package socks5

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

// T173 migrates HTTP success coverage to supported SOCKS: real upstream byte
// relay without HEALTHY, existing/new admission during CP loss, and upstream
// close without injected bytes or a retry. Early payload and exact partition
// transport are additionally pinned by the unchanged refusal regression.
func TestSOCKSAuthSuccessSurvivesCPOutageAndUpstreamClose(t *testing.T) {
	address, accepts, _ := refusalUpstream(t)
	bridge, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bridge.Close() })
	cut := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(cut) }) }
	defer stop()
	var rawAccepts atomic.Int64
	go func() {
		for {
			c, e := bridge.Accept()
			if e != nil {
				return
			}
			rawAccepts.Add(1)
			go func() {
				defer c.Close()
				up, e := net.DialTimeout("tcp", address, time.Second)
				if e != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{})
				go func() {
					select {
					case <-cut:
						c.Close()
						up.Close()
					case <-done:
					}
				}()
				go func() { io.Copy(up, c); up.Close() }()
				io.Copy(c, up)
				close(done)
			}()
		}
	}()
	h := dpharness.Start(t, dpharness.WithUpstream(bridge.Addr().String()), dpharness.WithControlPlane())
	dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, refusalToken)})
	waitForWatchEventsDial(t, h.CP)
	before := h.Journal.String()
	first := openSOCKSTunnel(t, h, refusalTarget, refusalToken)
	exchange := func(c net.Conn) {
		t.Helper()
		const payload = "opaque-success-and-CP-outage"
		if _, e := io.WriteString(c, payload); e != nil {
			t.Fatal(e)
		}
		if string(readN(t, c, len(payload))) != payload {
			t.Fatal("byte pipe changed payload")
		}
	}
	exchange(first)
	// Remove the fixture endpoint as well as ending the stream: new IPC dials
	// cannot restore the CP connection during these positive controls.
	if err := os.Remove(filepath.Join(h.IPCDir, "control.sock")); err != nil {
		t.Fatal(err)
	}
	h.CP.CloseFromServer()
	exchange(first)
	second := openSOCKSTunnel(t, h, refusalTarget, refusalToken)
	exchange(second)
	stop()
	expectEOF(t, first, "upstream close during established SOCKS tunnel")
	expectEOF(t, second, "upstream close during CP outage")
	time.Sleep(100 * time.Millisecond)
	if accepts.Load() != 2 || rawAccepts.Load() != 2 {
		t.Fatalf("upstream accepts=%d, want exactly 2 without retry", accepts.Load())
	}
	delta := h.Journal.String()[len(before):]
	loginvariants.AssertOnlyAllowedLines(t, delta)
	loginvariants.AssertNoSecrets(t, delta, []byte(refusalTarget), []byte(refusalToken), []byte("opaque-success-and-CP-outage"), []byte(refusalIdentity(refusalToken, "transport-profile", refusalTarget)))
	loginvariants.AssertNoSubHourTimestamp(t, delta)
}
