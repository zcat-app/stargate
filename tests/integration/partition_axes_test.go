// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// partition_axes_test.go is T155's live evidence for the device and
// first-party-site axes of the isolation partition (spec FR-002;
// Constitution III stream isolation; contracts/foundation-boundaries.md).
// T126 varies only the browser-profile axis. The partition username is
// HMAC-SHA-256 keyed by the device's bearer token over the tuple
// (profile, context, site), so two devices (two tokens) or two first-party
// sites reaching ONE destination must also land on distinct Tor circuits.
//
// The live subtests run inside TestStreamIsolationDPUNAMEForwarding's stack
// (same bring-up, same calibration): each axis pair holds one axis different
// and everything else (target, profile, context) equal, and the pair must
// attach to distinct, non-zero, BUILT circuits. The calibration there (one
// partition twice shares one circuit) is what makes a green result
// meaningful: a data plane that fused, dropped or constant-folded the
// upstream username collapses every pair onto one circuit and fails them.
//
// The hermetic test below pins the derivation of each axis to independently
// computed vectors (Python hmac/hashlib over the same JSON tuple), so a
// drift that stops an axis from changing the username fails in the PR gate.
// Reproduction command and transcript: specs/001-tor-route/evidence/
// T155-live-results.json, partition_vector_provenance (synthetic inputs).
package integration

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// Second device token (synthetic, FR-017 shape) and a second first-party site
// (v3-onion shape) for the axis pairs; built, not literal, like the T126
// reference vector's token.
var (
	t155DeviceTwoToken = strings.Repeat("a1b2c3d4", 4)
	t155SiteTwoOnion   = strings.Repeat("wxyz2345", 7) + ".onion"
)

// t155Cred is one SOCKS5 identity: the complete partition (UNAME) and the
// device bearer token (PASSWD, DP-facing only).
type t155Cred struct {
	user  string
	token string
}

// TestT155PartitionAxesDerivation pins each axis to an independent vector.
func TestT155PartitionAxesDerivation(t *testing.T) {
	const token = "0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c"
	profile := strings.Repeat("11", 32)
	onion := strings.Repeat("abcd2345", 7) + ".onion"
	vectors := []struct {
		name, got, want string
	}{
		{"base (foundation-boundaries reference)", t126PartitionUsername(token, profile, onion),
			"sg1:1940cde7068246610f120ee0926ad88113942aa2e83d71ba649deab843077a06"},
		{"device axis (other token)", t126PartitionUsername(t155DeviceTwoToken, profile, onion),
			"sg1:fb949c3678076ecb821ae348014b63e26545145dcb8a92ac4c505ddfb5c82f3d"},
		{"site axis (other first-party site)", t126PartitionUsername(token, profile, t155SiteTwoOnion),
			"sg1:0b6165577bb38306bd5e76aa90517c20580a65d25da9eb0ff19ea7babed62189"},
		{"profile axis (other profile)", t126PartitionUsername(token, strings.Repeat("22", 32), onion),
			"sg1:625891e4088b29c3c9134a12055b82d13b63ddc7f9156b47156f8fb74e94c2ac"},
	}
	seen := map[string]string{}
	for _, v := range vectors {
		if v.got != v.want {
			t.Errorf("%s: username %q, want independently computed %q", v.name, v.got, v.want)
		}
		if prior, dup := seen[v.got]; dup {
			t.Errorf("%s and %s derive the same username — that axis would not split circuits", v.name, prior)
		}
		seen[v.got] = v.name
	}
}

// t155RunAxisPair drains the target's streams, dials base and variant in
// parallel through the DP, and requires distinct, non-zero, BUILT circuits.
// The pair differs on exactly one axis, named for the failure message.
func t155RunAxisPair(t *testing.T, ctx context.Context, ctl t126ControlFn, composeFile, envFile, target, axis string,
	base, variant t155Cred, forensics func() string) {
	t.Helper()
	if base.user == variant.user {
		t.Fatalf("%s axis pair has identical usernames — the pair would not test isolation", axis)
	}
	if _, err := t126WaitStreams(ctx, ctl, target, 0, t126DrainWait); err != nil {
		t.Fatalf("drain before %s pair: %v\n%s", axis, err, forensics())
	}
	c0, c1 := t155ParallelConnect(t, ctx, composeFile, envFile, base, variant, t126ConnectWait)
	defer c0.Close()
	defer c1.Close()
	circ, err := t126WaitStreams(ctx, ctl, target, 2, t126StreamWait)
	if err != nil {
		t.Fatalf("%v\n%s", err, forensics())
	}
	if circ[0] == "0" || circ[1] == "0" {
		t.Fatalf("%s axis: stream(s) reported unattached (CircID 0): %v\n%s", axis, circ, forensics())
	}
	if circ[0] == circ[1] {
		t.Fatalf("ISOLATION: partitions differing only in the %s axis shared circuit %s to the same target through %s — "+
			"the upstream SOCKS5 username was fused, dropped or constant-folded (FR-007/FR-002)\n%s",
			axis, circ[0], t126DPAddr, forensics())
	}
	for _, id := range circ {
		built, err := t126CircuitBuilt(ctx, ctl, id)
		if err != nil || !built {
			t.Errorf("%s axis: circuit %s not found BUILT (err: %v)\n%s", axis, id, err, forensics())
		}
	}
	t.Logf("OK: %s axis → distinct circuits %s / %s, both BUILT", axis, circ[0], circ[1])
}

// t155ParallelConnect is t126ParallelConnect with a token per identity (the
// device axis needs two bearers). Same starting gun, per-dial retry window and
// forensics.
func t155ParallelConnect(t *testing.T, ctx context.Context, composeFile, envFile string, c0, c1 t155Cred, wait time.Duration) (net.Conn, net.Conn) {
	t.Helper()
	type result struct {
		idx  int
		conn net.Conn
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for i, cred := range []t155Cred{c0, c1} {
		go func(idx int, cred t155Cred) {
			<-start
			wCtx, wCancel := context.WithTimeout(ctx, wait)
			defer wCancel()
			for {
				conn, err := t126Connect(wCtx, cred.user, cred.token)
				if err == nil {
					results <- result{idx: idx, conn: conn}
					return
				}
				if wCtx.Err() != nil {
					results <- result{idx: idx, err: err}
					return
				}
				time.Sleep(t126StreamPoll)
			}
		}(i, cred)
	}
	close(start)
	var conns [2]net.Conn
	var errs [2]error
	for n := 0; n < 2; n++ {
		r := <-results
		conns[r.idx], errs[r.idx] = r.conn, r.err
	}
	if errs[0] != nil || errs[1] != nil {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
		t.Fatalf("parallel CONNECT through %s did not establish both streams within %s\n  #0: %s\n  #1: %s\n%s\n%s",
			t126DPAddr, wait, t059ClassifyDialErr(errs[0]), t059ClassifyDialErr(errs[1]),
			t126LogTail(ctx, composeFile, envFile, "stargate-dp", 12),
			t126LogTail(ctx, composeFile, envFile, "tor", 15))
	}
	return conns[0], conns[1]
}
