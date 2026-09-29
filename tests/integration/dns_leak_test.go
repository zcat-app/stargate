//go:build linux

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// stargate:cadence privileged — T034/T183 need CAP_NET_RAW for
// gopacket/afpacket capture on lo + the default-route NIC. The file carries
// no cadence build tag on purpose (T183 acceptance 4): it compiles into every
// run of the mixed tests/integration package, so an unprivileged run (the
// hermetic PR gate) reports it as a counted SKIP with its reason instead of
// omitting it, and a run with CAP_NET_RAW (root, e.g. the named Docker job or
// a disposable root container) executes it. The `linux` constraint remains
// because AF_PACKET is Linux-only (and gopacket/afpacket needs cgo).

// T034 is the per-PR DNS-leak regression gate for FR-003 (proxyDNS:true /
// SOCKS5h) + FR-007 (the data plane forwards the hostname-form target and
// MUST NOT resolve it locally; Constitution III "DNS and route failure").
// The release-cadence SC-003 measurement against a real Mullvad Browser
// session is T034a; browser-side DNS is T157/T188.
//
// T183 rebuilt it on the current DP interface. The real DP binary boots
// through its production path only (no test-only DP surface):
//
//	STARGATE_LISTEN_ADDR     free loopback port (FR-010 bind check applies)
//	STARGATE_TOR_SOCKS_ADDR  unix://<path> — the fake Tor SocksPort
//	                         (fake_socks5_tor.go WithUnixSocket), the same
//	                         pathname transport as the deployed sidecar
//	STARGATE_KEYS_DIR        pepper.key only (per-run random 32 bytes); no
//	                         inter-plane keys, so the DP runs degraded (no
//	                         dp.sock, routing continues — Principle II)
//	STARGATE_STATE_DIR       dp-snapshot.json (schema 3) holding the
//	                         HMAC-SHA-256 verifier of a per-run random token —
//	                         the production cold-start restore path
//	                         (controlclient/snapshot.go). ReloadTokens would
//	                         need tests/contract/internal/dpharness, which Go's
//	                         internal rule makes unimportable from here.
//
// The confinement boundary (Landlock + seccomp) is applied by the binary
// itself before serving, exactly as deployed.
//
// What the verdict requires (t034Verdict) — a pass needs ALL of these, so a
// blind or idle run can never pass (Constitution VII: each privacy claim
// names its positive control and falsifier):
//
//  1. zero DNS packets naming a routed target (the .onion corpus, the
//     hostname targets, or any other .onion name) on either interface —
//     checked first, because a captured leak is positive evidence even when
//     the leaking DP also broke forwarding;
//  2. capture started on BOTH lo and the default-route NIC;
//  3. positive control: a synthetic DNS query sent by the unconfined test
//     process appears in the capture on EACH interface, once before the
//     session and once after it (so a capture that died mid-session fails);
//  4. forwarding exercised: every CONNECT round-tripped bytes through the DP
//     to the fake upstream, and the fake saw every distinct partition.
//
// Falsifier: TestDNSLeakDetectsSimulatedDPQuery runs the same harness and
// verdict while a resolver query for a routed hostname — what a DP that
// resolved locally would send to the system resolver — is injected
// mid-session, and requires the verdict to report that leak and to pass
// every other guard once the injected packets are set aside.
//
// Scope/residue: the capture sees this network namespace's lo and
// default-route NIC over UDP/53 (IPv4 and IPv6). It does not see the
// browser (T157/T188) or DNS over TCP/DoT/DoH; the DP's seccomp filter
// already denies it any non-Unix socket.
package integration

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/proxy"
)

// T034 constants.
//
// t034SessionWin is the SC-003 canonical window. Long enough that a buggy
// startup or per-name cache that resolves once is observed; sub-window
// leaks stay release-cadence residue (T034a). t034FalsifierWin only has to
// cover one injected query plus the guards.
//
// t034PollEvery paces CONNECTs so the corpus is exercised several times.
//
// t034CaptureBlockTimeout is both the afpacket TPACKET_V3 block-retirement
// timeout and its poll(2) timeout: gopacket's default poll timeout blocks
// forever, so without the latter a quiet interface parks NextPacket past
// cancellation (observed on lo in the T183 container run).
//
// t034EgressControlAddr is RFC 5737 TEST-NET-1: routed out the default NIC,
// but no real resolver ever receives the synthetic control name.
const (
	t034SessionWin          = 60 * time.Second
	t034FalsifierWin        = 6 * time.Second
	t034PollEvery           = 1 * time.Second
	t034ReqTimeout          = 10 * time.Second
	t034DPStartWait         = 20 * time.Second
	t034ControlWait         = 5 * time.Second
	t034CaptureBlockTimeout = 100 * time.Millisecond
	t034MaxRecords          = 4096
	t034LoControlAddr       = "127.0.0.1:53"
	t034EgressControlAddr   = "192.0.2.1:53"
	t034ProfileID           = "3434343434343434343434343434343434343434343434343434343434343434"
)

// t034Targets is the routed corpus: distinct .onion names plus hostname
// targets (Tor clearnet-via-exit shape). Each goes to the DP as a SOCKS5h
// DOMAIN target (ATYP=0x03). Hostnames matter for the falsifier: Go's own
// resolver refuses .onion (RFC 7686), so a regressed DP calling the stdlib
// resolver would emit queries for the hostnames only.
var t034Targets = []string{
	"aaaaaaaaaaaaaaaa.onion",
	"bbbbbbbbbbbbbbbb.onion",
	"cccccccccccccccc.onion",
	"dddddddddddddddd.onion",
	"eeeeeeeeeeeeeeee.onion",
	"ffffffffffffffff.onion",
	"1111111111111111.onion",
	"2222222222222222.onion",
	"3333333333333333.onion",
	"4444444444444444.onion",
	"5555555555555555.onion",
	"6666666666666666.onion",
	"7777777777777777.onion",
	"abcdefghijklmnop.onion",
	"qrstuvwxyz234567.onion",
	"t183-hostname-probe.example.net",
	"t183-hostname-probe.example.org",
}

var errT034Leak = errors.New("DNS LEAK DETECTED")

// TestDNSLeak is the T034 / SC-003 per-PR DNS-leak regression gate: a
// 60-second routed session through the real DP emits zero DNS for any
// routed target on lo or the default-route NIC, with the positive
// controls and forwarding guards holding.
func TestDNSLeak(t *testing.T) {
	res := t034RunSession(t, t034SessionWin, nil)
	if err := t034Verdict(res); err != nil {
		t.Fatalf("T034: %v", err)
	}
	t.Logf("OK: T034 PASS — %d CONNECTs (%d partitions) through the DP over %s; controls seen on %s; zero DNS naming a routed target",
		res.completed, res.upstreamPartitions, t034SessionWin, strings.Join(res.ifaces, " + "))
}

// TestDNSLeakDetectsSimulatedDPQuery is the verdict's falsifier: the same
// harness with a resolver query for a routed hostname injected mid-session
// (what a DP resolving locally would send) MUST fail the verdict with the
// leak, while every vacuity guard still holds.
func TestDNSLeakDetectsSimulatedDPQuery(t *testing.T) {
	injected := t034Targets[len(t034Targets)-1]
	res := t034RunSession(t, t034FalsifierWin, func() error {
		return t034SendQuery(t034SystemResolver(), injected)
	})
	err := t034Verdict(res)
	if !errors.Is(err, errT034Leak) {
		t.Fatalf("simulated DP-side query for %s was not reported as a leak; verdict = %v", injected, err)
	}
	if !strings.Contains(err.Error(), injected) {
		t.Fatalf("leak verdict does not name the simulated query %s: %v", injected, err)
	}
	// The leak must be the ONLY failure: without the injected packets every
	// vacuity guard (capture, controls, forwarding) passes on this run.
	clean := res
	clean.records = nil
	for _, r := range res.records {
		if r.Name != injected {
			clean.records = append(clean.records, r)
		}
	}
	if err := t034Verdict(clean); err != nil {
		t.Fatalf("falsifier run is not otherwise green, so it proves nothing about the leak check: %v", err)
	}
	t.Logf("OK: falsifier — verdict failed as required: %v", err)
}

// t034Record is one parsed DNS name observed on a captured interface.
type t034Record struct {
	Iface     string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Name      string // normalized: lowercase, no trailing dot
	QType     string
	Direction string // "query" or "response"
}

func (r t034Record) String() string {
	return fmt.Sprintf("[%s] %s %s:%d → %s:%d qname=%s qtype=%s",
		r.Iface, r.Direction, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, r.Name, r.QType)
}

// t034Result is everything t034Verdict judges.
type t034Result struct {
	ifaces             []string
	started            int32
	controls           map[string][]string // control name -> interface it must appear on
	records            []t034Record
	issued, completed  int
	connectErrs        []string
	wantPartitions     int
	upstreamPartitions int
}

// t034Verdict fails on any observed leak first (a captured query for a
// routed target is positive evidence whatever else went wrong — a DP that
// stalls on local resolution can also break forwarding), then applies the
// vacuity guards that stop a blind or idle run from passing.
func t034Verdict(res t034Result) error {
	routed := map[string]bool{}
	for _, name := range t034Targets {
		routed[name] = true
	}
	var leaks []string
	for _, r := range res.records {
		if _, control := res.controls[r.Name]; control {
			continue
		}
		if routed[r.Name] || strings.HasSuffix(r.Name, ".onion") {
			leaks = append(leaks, r.String())
		}
	}
	if len(leaks) > 0 {
		return fmt.Errorf("%w — FR-003/FR-007 regression (a routed target was resolved locally): %d packet(s):\n  %s",
			errT034Leak, len(leaks), strings.Join(leaks, "\n  "))
	}
	if int(res.started) != len(res.ifaces) {
		return fmt.Errorf("capture started on %d of %d interfaces (%v); zero-DNS would be vacuous",
			res.started, len(res.ifaces), res.ifaces)
	}
	seen := map[string]bool{}
	for _, r := range res.records {
		seen[r.Iface+"\x00"+r.Name] = true
	}
	var missing []string
	for name, ifaces := range res.controls {
		for _, iface := range ifaces {
			if !seen[iface+"\x00"+name] {
				missing = append(missing, iface+":"+name)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("positive control query not observed in the capture (%s); the capture cannot see DNS, so zero-DNS would be vacuous",
			strings.Join(missing, ", "))
	}
	if res.issued == 0 || res.completed != res.issued {
		return fmt.Errorf("forwarding not exercised: %d of %d CONNECTs round-tripped through the DP (%s)",
			res.completed, res.issued, strings.Join(res.connectErrs, "; "))
	}
	if res.upstreamPartitions != res.wantPartitions {
		return fmt.Errorf("fake upstream saw %d partitions, want %d", res.upstreamPartitions, res.wantPartitions)
	}
	return nil
}

// t034RunSession boots the real DP against the fake Unix upstream,
// captures DNS on lo + the default-route NIC, proves the capture can see
// DNS, drives a routed session of window length (calling inject once
// mid-session when non-nil), proves the capture is still live, and
// returns the observations. Skips — never passes — without CAP_NET_RAW.
func t034RunSession(t *testing.T, window time.Duration, inject func() error) t034Result {
	t.Helper()
	t034RequireCapture(t)
	egressNIC, err := t034DefaultEgressNIC()
	if err != nil {
		t.Fatalf("could not determine default egress NIC: %v", err)
	}
	ifaces := []string{"lo", egressNIC}

	// --- credentials: per-run random pepper and token, verifier in the
	// cold-start snapshot. Nothing fixed, nothing reused across runs.
	var pepper [32]byte
	var tokenRaw [16]byte
	if _, err := rand.Read(pepper[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(tokenRaw[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(tokenRaw[:]) // FR-017: 32 lowercase hex
	keysDir, stateDir, ipcDir := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(keysDir, "pepper.key"), pepper[:], 0o600); err != nil {
		t.Fatal(err)
	}
	t034WriteSnapshot(t, stateDir, pepper[:], token)

	// --- fake Tor SocksPort on a pathname Unix socket. MkdirTemp, not
	// t.TempDir: sun_path caps at ~108 bytes and t.TempDir embeds the name.
	sockDir, err := os.MkdirTemp("", "t034-tor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	fake := NewServer(AcceptAndRelay, WithUnixSocket(filepath.Join(sockDir, "tor.sock")))
	upstream, err := fake.Start()
	if err != nil {
		t.Fatalf("fake SOCKS5 start: %v", err)
	}
	t.Cleanup(func() { _ = fake.Close() })

	// --- the real DP binary on its production boot path.
	dpBin := t034BuildDP(t)
	dpAddr := t034FreeLoopbackAddr(t)
	dp := exec.Command(dpBin)
	dp.Env = append(os.Environ(),
		"STARGATE_LISTEN_ADDR="+dpAddr,
		"STARGATE_TOR_SOCKS_ADDR="+upstream,
		"STARGATE_KEYS_DIR="+keysDir,
		"STARGATE_STATE_DIR="+stateDir,
		"STARGATE_IPC_DIR="+ipcDir,
	)
	// main() redirects its own stdout/stderr to /dev/null before any work
	// (Constitution III), so the exit status is the only boot diagnostic.
	dp.Stdout, dp.Stderr = io.Discard, io.Discard
	if err := dp.Start(); err != nil {
		t.Fatalf("start data plane: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- dp.Wait() }()
	t.Cleanup(func() {
		_ = dp.Process.Kill()
		<-exited
	})
	t034WaitForListen(t, dpAddr, exited)

	// --- capture on both interfaces; every UDP/53 name is recorded.
	var (
		mu      sync.Mutex
		records []t034Record
		started atomic.Int32
		wg      sync.WaitGroup
	)
	captureCtx, captureCancel := context.WithCancel(context.Background())
	defer captureCancel()
	ready := make(chan struct{}, len(ifaces))
	for _, iface := range ifaces {
		wg.Add(1)
		go func(iface string) {
			defer wg.Done()
			t034Capture(captureCtx, iface, &started, ready, func(r t034Record) {
				mu.Lock()
				if len(records) < t034MaxRecords {
					records = append(records, r)
				}
				mu.Unlock()
			}, t.Logf)
		}(iface)
	}
	for range ifaces {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
		}
	}

	nonce := make([]byte, 6)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ctlPre := "t183-control-pre-" + hex.EncodeToString(nonce) + ".onion"
	ctlPost := "t183-control-post-" + hex.EncodeToString(nonce) + ".onion"
	controlAddrs := map[string]string{"lo": t034LoControlAddr, egressNIC: t034EgressControlAddr}
	sawControl := func(name string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, iface := range ifaces {
			found := false
			for _, r := range records {
				if r.Iface == iface && r.Name == name {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	sendControls := func(name string) {
		deadline := time.Now().Add(t034ControlWait)
		for !sawControl(name) && time.Now().Before(deadline) {
			for _, iface := range ifaces {
				if err := t034SendQuery(controlAddrs[iface], name); err != nil {
					t.Logf("control query %s via %s: %v", name, iface, err)
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if started.Load() == int32(len(ifaces)) {
		sendControls(ctlPre)
	}

	// --- the routed session.
	res := t034Result{ifaces: ifaces, controls: map[string][]string{ctlPre: ifaces, ctlPost: ifaces}}
	partitions := map[string]bool{}
	var connMu sync.Mutex
	var connWG sync.WaitGroup
	ticker := time.NewTicker(t034PollEvery)
	deadline := time.Now().Add(window)
	injectAt := time.Now().Add(window / 2)
	for i := 0; time.Now().Before(deadline); i++ {
		<-ticker.C
		if inject != nil && !time.Now().Before(injectAt) {
			if err := inject(); err != nil {
				t.Fatalf("inject simulated DP-side query: %v", err)
			}
			inject = nil
		}
		target := t034Targets[i%len(t034Targets)]
		user := t126PartitionUsername(token, t034ProfileID, target)
		partitions[user] = true
		res.issued++
		connWG.Add(1)
		go func() {
			defer connWG.Done()
			err := t034Connect(dpAddr, user, token, target)
			connMu.Lock()
			defer connMu.Unlock()
			if err != nil {
				res.connectErrs = append(res.connectErrs, target+": "+err.Error())
				return
			}
			res.completed++
		}()
	}
	ticker.Stop()
	connWG.Wait()

	// Post-session control: the capture was still observing at the end.
	if started.Load() == int32(len(ifaces)) {
		sendControls(ctlPost)
	}
	captureCancel()
	wg.Wait()

	select {
	case err := <-exited:
		exited <- err
		t.Fatalf("data plane exited during the session: %v", err)
	default:
	}

	res.started = started.Load()
	mu.Lock()
	res.records = append([]t034Record(nil), records...)
	mu.Unlock()
	res.wantPartitions = len(partitions)
	res.upstreamPartitions = len(fake.CircuitIDs())
	return res
}

// t034RequireCapture skips (never passes) when AF_PACKET capture is not
// permitted, and fails on any other capture error.
func t034RequireCapture(t *testing.T) {
	t.Helper()
	h, err := afpacket.NewTPacket(afpacket.OptInterface("lo"))
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("SKIP: DNS-leak gate needs CAP_NET_RAW for AF_PACKET capture (euid=%d); run as root, e.g. the named Docker job — this is not a pass", os.Geteuid())
	}
	if err != nil {
		t.Fatalf("AF_PACKET capture unavailable: %v", err)
	}
	h.Close()
}

// t034Capture records every DNS name in UDP/53 packets on iface until ctx
// ends. started is incremented only after the handle opened; ready is
// signalled either way so the caller never waits on a dead goroutine.
func t034Capture(ctx context.Context, iface string, started *atomic.Int32, ready chan<- struct{}, record func(t034Record), log func(string, ...any)) {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptBlockTimeout(t034CaptureBlockTimeout),
		afpacket.OptPollTimeout(t034CaptureBlockTimeout),
	)
	if err != nil {
		log("t034: afpacket.NewTPacket(%s): %v — capture NOT started", iface, err)
		ready <- struct{}{}
		return
	}
	defer handle.Close()
	started.Add(1)
	ready <- struct{}{}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	src.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		packet, err := src.NextPacket()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// ErrTimeout is the benign block retirement; anything else is
			// surfaced (a silently dead capture is caught by the post control).
			if !errors.Is(err, afpacket.ErrTimeout) {
				log("t034: NextPacket on %s: %v (continuing)", iface, err)
			}
			continue
		}
		for _, r := range t034ParseDNS(packet, iface) {
			record(r)
		}
	}
}

// t034ParseDNS returns every question and answer name of a UDP/53 DNS packet.
func t034ParseDNS(packet gopacket.Packet, iface string) []t034Record {
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok || (udp.SrcPort != 53 && udp.DstPort != 53) {
		return nil
	}
	dns, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if !ok {
		return nil
	}
	base := t034Record{Iface: iface, SrcPort: uint16(udp.SrcPort), DstPort: uint16(udp.DstPort)}
	if nl := packet.NetworkLayer(); nl != nil {
		src, dst := nl.NetworkFlow().Endpoints()
		base.SrcIP, base.DstIP = net.IP(src.Raw()), net.IP(dst.Raw())
	}
	var out []t034Record
	for _, q := range dns.Questions {
		r := base
		r.Name, r.QType, r.Direction = t034Normalize(string(q.Name)), q.Type.String(), "query"
		out = append(out, r)
	}
	for _, a := range dns.Answers {
		r := base
		r.Name, r.QType, r.Direction = t034Normalize(string(a.Name)), a.Type.String(), "response"
		out = append(out, r)
	}
	return out
}

func t034Normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// t034SendQuery sends one A query for name to addr over UDP from this
// (unconfined) process. The answer, if any, is irrelevant: the packet on
// the wire is what the capture must see.
func t034SendQuery(addr, name string) error {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	msg := &layers.DNS{
		ID: binary.BigEndian.Uint16(id[:]), RD: true, QDCount: 1,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	}
	buf := gopacket.NewSerializeBuffer()
	if err := msg.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		return err
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(buf.Bytes())
	return err
}

// t034SystemResolver is where a DP that resolved locally through the
// stdlib would send its query: the first resolv.conf nameserver, or the
// stdlib's own default when none is configured.
func t034SystemResolver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil {
				return net.JoinHostPort(f[1], "53")
			}
		}
	}
	return "127.0.0.1:53"
}

// t034Connect issues one authenticated SOCKS5h CONNECT through the DP and
// round-trips a probe through the fake upstream's echo. ATYP=DOMAIN: the
// client never resolves, so any query for the target is someone else's.
func t034Connect(dpAddr, user, token, target string) error {
	dialer, err := proxy.SOCKS5("tcp", dpAddr, &proxy.Auth{User: user, Password: token}, proxy.Direct)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), t034ReqTimeout)
	defer cancel()
	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", net.JoinHostPort(target, "443"))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(t034ReqTimeout))
	probe := []byte("t034-forwarding-probe")
	if _, err := conn.Write(probe); err != nil {
		return err
	}
	echo := make([]byte, len(probe))
	if _, err := io.ReadFull(conn, echo); err != nil {
		return err
	}
	if string(echo) != string(probe) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

// t034WriteSnapshot writes the schema-3 cold-start cache the DP restores at
// boot (controlclient/snapshot.go; data-model.md §1.4): one HMAC-SHA-256
// verifier under the pepper and the auth-set-v1 commitment over it.
func t034WriteSnapshot(t *testing.T, stateDir string, pepper []byte, token string) {
	t.Helper()
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(token))
	verifier := mac.Sum(nil)
	h := sha256.New()
	h.Write(append([]byte("stargate-auth-set-v1"), 0))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], 1)
	h.Write(count[:])
	h.Write(verifier)
	blob, err := json.Marshal(map[string]any{
		"schemaVersion":  3,
		"authSetVersion": 1,
		"generation":     1,
		"commitment":     base64.StdEncoding.EncodeToString(h.Sum(nil)),
		"loadedAt":       time.Now().UTC().Format(time.RFC3339),
		"verifiers":      []map[string]string{{"verifier": base64.StdEncoding.EncodeToString(verifier)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "dp-snapshot.json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

var t034Build struct {
	once sync.Once
	path string
	err  error
}

// t034BuildDP compiles the DP from this tree once per test binary, static
// like the shipped image, so the gate never runs a stale artifact.
func t034BuildDP(t *testing.T) string {
	t.Helper()
	t034Build.once.Do(func() {
		dir, err := os.MkdirTemp("", "t034-dp")
		if err != nil {
			t034Build.err = err
			return
		}
		t034Build.path = filepath.Join(dir, "stargate-proxy")
		cmd := exec.Command("go", "build", "-o", t034Build.path, "./cmd/stargate-proxy")
		cmd.Dir = filepath.Join(t034FindRepoRoot(t), "data-plane")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t034Build.err = fmt.Errorf("go build data-plane: %w\n%s", err, out)
		}
	})
	if t034Build.err != nil {
		t.Fatal(t034Build.err)
	}
	return t034Build.path
}

func t034FreeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// t034WaitForListen waits for the DP listener; an early exit fails at once.
func t034WaitForListen(t *testing.T, addr string, exited chan error) {
	t.Helper()
	deadline := time.Now().Add(t034DPStartWait)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("data plane exited before listening on %s: %v", addr, err)
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("data plane did not listen on %s within %s", addr, t034DPStartWait)
}

// t034DefaultEgressNIC resolves the default-route interface from
// /proc/net/route, falling back to `ip route` (minimal containers ship
// procfs but not iproute2).
func t034DefaultEgressNIC() (string, error) {
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		for i, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if i > 0 && len(fields) >= 8 && fields[1] == "00000000" {
				return fields[0], nil
			}
		}
	}
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("no IPv4 default route in /proc/net/route and `ip route` failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == "default" {
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "dev" {
					return f[i+1], nil
				}
			}
		}
	}
	return "", errors.New("no default route found")
}

// t034FindRepoRoot walks up from this source file to the directory holding
// go.work, independent of the working directory.
func t034FindRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	for dir := filepath.Dir(thisFile); ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		if filepath.Dir(dir) == dir {
			t.Fatal("repo root (go.work) not found above " + thisFile)
		}
	}
}
