// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package socks5

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

const refusalToken = "abababababababababababababababab"
const refusalOtherToken = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
const refusalTarget = "same-target.invalid"

// Synthetic complete partition inputs; the browser's derivation is T136's
// responsibility. These opaque identities test transport, not browser fidelity.
func refusalIdentity(token, profile, site string) string {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte(profile + "\x00normal\x00" + site))
	return "sg1:" + hex.EncodeToString(m.Sum(nil))
}

type refusalHandshake struct {
	user, password, host string
	port                 uint16
	method               byte
}

// Counts raw accepts BEFORE parsing; observing only successful handshakes would
// miss an upstream dial that sends no bytes. The same socket serves controls.
func refusalUpstream(t *testing.T) (string, *atomic.Int64, <-chan refusalHandshake) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	count := new(atomic.Int64)
	records := make(chan refusalHandshake, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				r := bufio.NewReader(c)
				read := func(n int) ([]byte, error) { b := make([]byte, n); _, e := io.ReadFull(r, b); return b, e }
				h, e := read(2)
				if e != nil || h[0] != 5 {
					return
				}
				methods, e := read(int(h[1]))
				if e != nil {
					return
				}
				rec := refusalHandshake{}
				if bytes.Contains(methods, []byte{2}) {
					rec.method = 2
				}
				if _, e = c.Write([]byte{5, rec.method}); e != nil {
					return
				}
				if rec.method == 2 {
					h, e = read(2)
					if e != nil || h[0] != 1 {
						return
					}
					u, e := read(int(h[1]))
					if e != nil {
						return
					}
					rec.user = string(u)
					p, e := read(1)
					if e != nil {
						return
					}
					pw, e := read(int(p[0]))
					if e != nil {
						return
					}
					rec.password = string(pw)
					if _, e = c.Write([]byte{1, 0}); e != nil {
						return
					}
				}
				h, e = read(5)
				if e != nil || !bytes.Equal(h[:4], []byte{5, 1, 0, 3}) {
					return
				}
				target, e := read(int(h[4]) + 2)
				if e != nil {
					return
				}
				rec.host = string(target[:len(target)-2])
				rec.port = uint16(target[len(target)-2])<<8 | uint16(target[len(target)-1])
				records <- rec
				if _, e = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
					return
				}
				io.Copy(c, r)
			}()
		}
	}()
	return ln.Addr().String(), count, records
}

func assertHTTPRefusal(t *testing.T, conn net.Conn, request string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	// A reset during an oversized write is valid refusal; a timeout is not.
	if _, err := io.WriteString(conn, request); err != nil && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("probe write: %v", err)
	}
	var b [1]byte
	n, err := conn.Read(b[:])
	if n != 0 {
		t.Error("HTTP ingress returned response bytes")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("HTTP ingress did not close silently: %v", err)
	}
}

// This test is unchanged across the red/green production snapshots. Its binary
// harness uses main's real wiring; the paired controls falsify a disconnected
// upstream and observe exact credentials/hostname plus early opaque bytes.
func TestHTTPConnectSameDestinationDistinctFirstPartyRefused(t *testing.T) {
	address, accepts, records := refusalUpstream(t)
	h := dpharness.Start(t, dpharness.WithUpstream(address), dpharness.WithControlPlane())
	if r := dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, refusalToken), dpharness.MintToken(t, refusalOtherToken)}); r.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatal("auth fixture not loaded")
	}
	waitForWatchEventsDial(t, h.CP) // No HEALTHY event: admission remains advisory-independent.
	contexts := []struct{ label, token, profile, site string }{
		{"site_a", refusalToken, "profile-a", "https://a.example"},
		{"site_b", refusalToken, "profile-a", "https://b.example"},
		{"profile_b", refusalToken, "profile-b", "https://a.example"},
		{"device_b", refusalOtherToken, "profile-a", "https://a.example"},
	}
	const payload = "early-opaque-TLS-like-\x16\x03\x01\x00\xff"
	beforeReq, beforeBytes := t025dCounterTotals(dpharness.Status(t, h))
	for _, ctx := range contexts {
		t.Run("SOCKS_control_"+ctx.label, func(t *testing.T) {
			conn := dialProxy(t, h)
			defer conn.Close()
			doMethodNegotiation(t, conn)
			user := refusalIdentity(ctx.token, ctx.profile, ctx.site)
			if !bytes.Equal(doSubnegotiation(t, conn, user, ctx.token), []byte{1, 0}) {
				t.Fatal("control authentication failed")
			}
			req := append([]byte{5, 1, 0, 3, byte(len(refusalTarget))}, []byte(refusalTarget)...)
			req = append(req, 1, 187)
			req = append(req, []byte(payload)...)
			if _, err := conn.Write(req); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readN(t, conn, 10), []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) {
				t.Fatal("control failed upstream admission")
			}
			if string(readN(t, conn, len(payload))) != payload {
				t.Fatal("early payload changed")
			}
			select {
			case rec := <-records:
				if rec.method != 2 || rec.user != user || rec.password != "" || rec.host != refusalTarget || rec.port != 443 {
					t.Fatal("upstream partition/password/hostname changed")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("control has no observed upstream handshake")
			}
		})
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		requests, n := t025dCounterTotals(dpharness.Status(t, h))
		if requests == beforeReq+4 && n == beforeBytes+uint64(8*len(payload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("positive control counts not exact: requests=%d bytes=%d", requests-beforeReq, n-beforeBytes)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if accepts.Load() != 4 {
		t.Fatal("positive control did not observe four raw upstream accepts")
	}
	journal := h.Journal.String()
	for _, ctx := range contexts {
		t.Run("HTTP_"+ctx.label, func(t *testing.T) {
			baseReq, baseBytes := t025dCounterTotals(dpharness.Status(t, h))
			baseAccept := accepts.Load()
			c := dialProxy(t, h)
			request := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nProxy-Authorization: Bearer %s\r\nProxy-Stargate-Isolation: %s\r\nOrigin: %s\r\nX-Profile: %s\r\n\r\n", refusalTarget, ctx.token, refusalIdentity(ctx.token, ctx.profile, ctx.site), ctx.site, ctx.profile)
			assertHTTPRefusal(t, c, request)
			c.Close()
			// Socket close plus bounded observation catches asynchronous admission too.
			time.Sleep(30 * time.Millisecond)
			req, n := t025dCounterTotals(dpharness.Status(t, h))
			if accepts.Load() != baseAccept {
				t.Errorf("HTTP opened upstream sockets: delta=%d", accepts.Load()-baseAccept)
			}
			if req != baseReq || n != baseBytes {
				t.Errorf("HTTP changed counters: requests=%d bytes=%d", req-baseReq, n-baseBytes)
			}
		})
	}
	for _, tc := range []struct{ name, request string }{
		{"missing", "CONNECT " + refusalTarget + ":443 HTTP/1.1\r\n\r\n"},
		{"malformed", "CONNECT " + refusalTarget + ":443 HTTP/1.1\r\nProxy-Authorization: Bearer malformed\r\n\r\n"},
		{"invalid", "CONNECT " + refusalTarget + ":443 HTTP/1.1\r\nProxy-Authorization: Bearer " + strings.Repeat("0", 32) + "\r\n\r\n"},
		{"pipelined", "CONNECT " + refusalTarget + ":443 HTTP/1.1\r\nProxy-Authorization: Bearer " + refusalToken + "\r\n\r\n" + payload},
		{"slow_after_first_byte", "C"},
		{"oversized", "CONNECT " + refusalTarget + ":443 HTTP/1.1\r\nX-Padding: " + strings.Repeat("x", 16384) + "\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseReq, baseBytes := t025dCounterTotals(dpharness.Status(t, h))
			baseAccept := accepts.Load()
			c := dialProxy(t, h)
			assertHTTPRefusal(t, c, tc.request)
			c.Close()
			time.Sleep(30 * time.Millisecond)
			req, n := t025dCounterTotals(dpharness.Status(t, h))
			if accepts.Load() != baseAccept || req != baseReq || n != baseBytes {
				t.Error("HTTP refusal changed upstream accepts or counters")
			}
		})
	}
	delta := strings.TrimPrefix(h.Journal.String(), journal)
	loginvariants.AssertNoSecrets(t, delta, []byte(refusalTarget), []byte(refusalToken), []byte(refusalOtherToken), []byte(payload))
	loginvariants.AssertOnlyAllowedLines(t, delta)
}
