// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the inter-plane transport invariants —
// specs/001-tor-route/contracts/control-grpc.md §"Transport invariants".
//
// Scope: the local-process-testable + static subset of the 10-row
// transport-invariants table. The compose-level rows (socket mode 0660,
// owner stargate-cp/stargate-dp, group stargate-ipc GID 5100, peer-plane
// UID connect, non-group UID EACCES, mutual ed25519) need the real
// compose stack with distinct UIDs and key material — deferred to a
// compose-level test (see ticket §Out-of-scope). Row 8 (schema-version
// handshake) is deferred to T045/T050 — the v2-marker wire shape is impl
// detail that cannot be test-pinned before it exists. Row 9 (plane-down
// survival) is covered by T020 (cold-start no-CP auth) and T021 row 3
// (reconnect after server-side stream close).
package controlgrpc

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestTransportInvariants(t *testing.T) {
	// Row 10: production CP MUST NOT invoke GetStatus — static regression
	// gate against the admin-UI feature wiring a production caller before
	// research.md §11's deferral is revisited. Runs NOW; no content gate.
	//
	// The grep checks BOTH "GetStatus(" (proto/Go PascalCase) and
	// "getStatus(" (Java gRPC lowerCamelCase) so the gate catches a real
	// production caller regardless of which stub convention the admin-UI
	// feature's codegen uses. The contract text names "GetStatus(" only,
	// but the intent is "no production caller" — the broader pattern is a
	// strict superset and does not weaken the gate.
	t.Run("ProductionCallerAbsent_GetStatus", func(t *testing.T) {
		repoRoot := findRepoRoot(t)
		cpRoot := filepath.Join(repoRoot, "control-plane")
		if _, err := os.Stat(cpRoot); err != nil {
			t.Skipf("control-plane/ absent — nothing to grep yet")
		}
		needles := []string{"GetStatus(", "getStatus("}
		var matches []string
		err := filepath.Walk(cpRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			// Exclude **/test/**, **/*Test.java, and **/target/**
			// (Maven build output incl. generated gRPC stubs) per the
			// contract's "production source tree" intent.
			slashPath := filepath.ToSlash(path)
			if strings.Contains(slashPath, "/test/") ||
				strings.Contains(slashPath, "/target/") ||
				strings.HasSuffix(path, "Test.java") {
				return nil
			}
			if !strings.HasSuffix(path, ".java") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			text := string(data)
			for _, needle := range needles {
				if strings.Contains(text, needle) {
					rel, _ := filepath.Rel(cpRoot, path)
					matches = append(matches, fmt.Sprintf("%s: contains %q", filepath.ToSlash(rel), needle))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", cpRoot, err)
		}
		if len(matches) > 0 {
			t.Errorf("production control-plane source has GetStatus/getStatus callers (%d) — "+
				"contracts/control-grpc.md §Transport invariants row 10 gates this until "+
				"research.md §11's deferral is revisited:\n  %s",
				len(matches), strings.Join(matches, "\n  "))
		}
	})

	// Row 2: the DP binds only dp.sock; control.sock does NOT exist in
	// the IPC dir after DP boot (role separation via bind(2)).
	t.Run("SocketTopology_DPBindsOnlyDpSock", func(t *testing.T) {
		h := startDP(t)
		dpSockPath := filepath.Join(h.ipcDir, "dp.sock")
		info, err := os.Stat(dpSockPath)
		if err != nil {
			t.Fatalf("stat %s: %v — dp.sock must exist after DP boot (T045 hosts ReloadTokens on it)", dpSockPath, err)
		}
		if info.Mode()&os.ModeSocket == 0 {
			t.Errorf("%s is not a socket (mode %s) — dp.sock must be a Unix domain socket", dpSockPath, info.Mode())
		}
		controlSockPath := filepath.Join(h.ipcDir, "control.sock")
		if _, err := os.Stat(controlSockPath); err == nil {
			t.Errorf("%s exists — the DP must NOT bind control.sock (role separation via bind(2); contracts/control-grpc.md §Socket topology)", controlSockPath)
		}
	})

	// Row 1: no TCP transport — the DP's only TCP LISTEN is the proxy
	// port 8881; the gRPC surface is UDS-only. Reads BOTH /proc/<pid>/net/
	// tcp (IPv4) and tcp6 (IPv6) so a future gRPC server switched to
	// [::]:port does not slip past.
	//
	// Process-scoping (T050 fixture lift): /proc/<pid>/net/tcp is
	// NETNS-wide, not process-wide. In the compose container the netns
	// holds only the DP (the live-stack R7 row keeps netns-wide
	// semantics legitimately), but the local-process tier shares the
	// host netns, so entries are filtered to inodes the DP actually
	// owns (readlink /proc/<pid>/fd/* → socket:[inode]). The assertion
	// itself is unchanged: the DP process may hold no TCP LISTEN other
	// than the proxy port.
	t.Run("NoTCPTransport_OnlyProxyListener", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skipf("/proc/<pid>/net/tcp is Linux-specific; skipping on %s", runtime.GOOS)
		}
		h := startDP(t)
		proxyPort := h.proxyPort()
		owned := dpSocketInodes(t, h.pid)
		tcp4, err := readProcNetTCPListenEntries(fmt.Sprintf("/proc/%d/net/tcp", h.pid))
		if err != nil {
			t.Fatalf("read /proc/%d/net/tcp: %v", h.pid, err)
		}
		tcp6, err := readProcNetTCPListenEntries(fmt.Sprintf("/proc/%d/net/tcp6", h.pid))
		if err != nil {
			t.Fatalf("read /proc/%d/net/tcp6: %v", h.pid, err)
		}
		var listenPorts []int
		for _, e := range append(tcp4, tcp6...) {
			if !owned[e.inode] {
				continue // another process's listener in the shared host netns
			}
			listenPorts = append(listenPorts, e.port)
		}
		// Sanity: the proxy listener MUST be visible — an empty table
		// would make the violation loop below vacuously pass.
		if len(listenPorts) == 0 {
			t.Fatalf("no TCP LISTEN entries found in /proc/%d/net/tcp{,6} — proxy listener on port %d should be visible; transient timing or wrong PID?", h.pid, proxyPort)
		}
		for _, port := range listenPorts {
			if port != proxyPort {
				t.Errorf("DP has a TCP LISTEN on port %d (proxy is %d) — contract requires no TCP transport for gRPC; only the proxy listener is permitted (contracts/control-grpc.md §Transport invariants row 1)", port, proxyPort)
			}
		}
		// Reinforce row 2: dp.sock is a UDS, not TCP.
		dpSockPath := filepath.Join(h.ipcDir, "dp.sock")
		info, err := os.Stat(dpSockPath)
		if err != nil {
			t.Fatalf("stat %s: %v", dpSockPath, err)
		}
		if info.Mode()&os.ModeSocket == 0 {
			t.Errorf("%s is not a socket — dp.sock must be a UDS, not a TCP listener", dpSockPath)
		}
	})
}

// --- harness accessors (T022 additions) -----------------------------------

// proxyPort returns the TCP port of the proxy listener (the last segment
// of proxyAddr "127.0.0.1:<port>").
func (h *dpHarness) proxyPort() int {
	_, portStr, ok := strings.Cut(h.proxyAddr, ":")
	if !ok {
		return -1
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return -1
	}
	return port
}

// --- /proc/<pid>/net/tcp{,6} parsing -------------------------------------

// tcpListenEntry is one LISTEN row of a /proc/net/tcp{,6} table: the
// local port plus the socket's kernel inode (the process-ownership key —
// see the row-1 comment on why netns-wide tables need inode filtering).
type tcpListenEntry struct {
	port  int
	inode string
}

// dpSocketInodes returns the set of socket inodes the process owns,
// read from /proc/<pid>/fd/* readlinks (socket:[<inode>]). Linux-only.
func dpSocketInodes(t *testing.T, pid int) map[string]bool {
	t.Helper()
	inodes := make(map[string]bool)
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		t.Fatalf("read %s: %v", fdDir, err)
	}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			continue // fd closed between readdir and readlink — not ours to judge
		}
		if rest, ok := strings.CutPrefix(link, "socket:["); ok {
			inodes[strings.TrimSuffix(rest, "]")] = true
		}
	}
	return inodes
}

// readProcNetTCPListenEntries reads a /proc/net/tcp or /proc/net/tcp6
// formatted file and returns every entry in LISTEN state (0x0A) with its
// local port and socket inode. The port hex is big-endian regardless of
// IPv4/IPv6. Linux-only.
func readProcNetTCPListenEntries(path string) ([]tcpListenEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []tcpListenEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: sl local_address rem_address st tx:rx tr:tm->tm retrns
		//   inode uid timeout ...
		// local_address is hex "0100007F:1F90" (IPv4) or
		// "00000000000000000000000000000000:1F90" (IPv6). Port is the
		// 4-hex-digit segment after the final colon; the socket inode is
		// the 10th column.
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] == "sl" {
			continue
		}
		if fields[3] != "0A" { // state 0x0A = LISTEN
			continue
		}
		localAddr := fields[1]
		colon := strings.LastIndexByte(localAddr, ':')
		if colon < 0 {
			continue
		}
		portHex := localAddr[colon+1:]
		portBytes, err := hex.DecodeString(portHex)
		if err != nil {
			continue
		}
		var port int
		for _, b := range portBytes {
			port = port<<8 | int(b)
		}
		entries = append(entries, tcpListenEntry{port: port, inode: fields[9]})
	}
	return entries, scanner.Err()
}
