// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Negative controls for the harness's journal leak scan (redteam finding
// 20260706-001-leakscan-encoding-gaps): each case renders a known secret
// the way a real logger would and asserts findSecretLeaks catches it. A
// DP implementation that logs a hash via slog's TextHandler or a stray
// %v verb must not be able to pass the ReloadTokens no-logging clause
// because the scan didn't recognise the rendering. Pure function under
// test — no DP process needed, so this runs (and gates) even while
// TestReloadTokens skips on the T045/T050 content gate.
package controlgrpc

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// leakScanSecret is a fixed 32-byte stand-in for an argon2id hash. Fixed,
// not random: the clean-journal case below must be deterministic.
var leakScanSecret = []byte{
	0xa3, 0x1f, 0x8c, 0x57, 0xe2, 0x09, 0xb4, 0x6d,
	0x71, 0xc8, 0x3e, 0x95, 0x0a, 0xf6, 0x42, 0xd9,
	0x88, 0x2b, 0x64, 0xcf, 0x13, 0x7a, 0xe5, 0x50,
	0x9e, 0x06, 0xbb, 0x41, 0xdc, 0x78, 0x2f, 0x93,
}

func TestFindSecretLeaksCatchesEachEncoding(t *testing.T) {
	cases := []struct {
		name    string
		journal string
	}{
		{"hex lower", "level=info msg=reload hash=" + hex.EncodeToString(leakScanSecret)},
		{"hex upper", "APPLIED HASH " + strings.ToUpper(hex.EncodeToString(leakScanSecret))},
		{"base64 std", "reload applied hash=" + base64.StdEncoding.EncodeToString(leakScanSecret)},
		{"base64 raw-std", "reload applied hash=" + base64.RawStdEncoding.EncodeToString(leakScanSecret)},
		{"base64 url", "reload applied hash=" + base64.URLEncoding.EncodeToString(leakScanSecret)},
		{"base64 raw-url", "reload applied hash=" + base64.RawURLEncoding.EncodeToString(leakScanSecret)},
		// fmt %v and slog TextHandler both render []byte as "[163 31 …]"
		// — the most likely accidental logging path in a Go DP.
		{"decimal slice (%v / slog)", fmt.Sprintf("time=x level=INFO msg=reload hash=%v", leakScanSecret)},
		{"decimal run (brackets stripped)", "hash bytes: " + strings.Trim(fmt.Sprint(leakScanSecret), "[]")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if leaks := findSecretLeaks(c.journal, leakScanSecret); len(leaks) == 0 {
				t.Errorf("scan missed a %s rendering — a DP logging the secret this way would pass the ReloadTokens no-logging clause undetected", c.name)
			}
		})
	}
}

func TestFindSecretLeaksCleanJournal(t *testing.T) {
	// A realistic secret-free journal (allowlisted line classes per
	// T025a: startup, ReloadTokens apply, snapshot-write events) must
	// produce zero findings — the scan gates on content, not chatter.
	journal := strings.Join([]string{
		"level=info msg=startup listener=127.0.0.1:8881",
		"level=info msg=\"tokens applied\" generation=2 count=1",
		"level=warn msg=\"snapshot write failed\" err=\"open /var/lib/stargate/.tmp: read-only file system\"",
	}, "\n")
	if leaks := findSecretLeaks(journal, leakScanSecret); len(leaks) != 0 {
		t.Errorf("false positives on a secret-free journal: %v", leaks)
	}
	// Empty and nil secrets are ignored, never treated as
	// matches-everything.
	if leaks := findSecretLeaks(journal, nil, []byte{}); len(leaks) != 0 {
		t.Errorf("empty secrets produced findings: %v", leaks)
	}
}
