//go:build docker && linux
// +build docker,linux

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// stargate:cadence docker — T034 needs CAP_NET_RAW for gopacket/afpacket
// capture on lo + the egress NIC. The named Docker PR job
// (STARGATE_TEST_TAGS=docker scripts/verify.sh) provides root in the
// container; the hermetic PR gate compile-checks via
// `go vet -tags 'docker live release'` (T076 §Acceptance #4/#5) and
// accounts this package SKIP[docker] in the hermetic run. The `linux`
// constraint is required because gopacket/afpacket uses AF_PACKET sockets
// (Linux-only); on a non-Linux dev host the file is excluded from the
// compile-check, so verify.sh stays green cross-platform.

// T034 is the per-PR DNS-leak regression gate for FR-003 (proxyDNS:true /
// SOCKS5h) + FR-007 (data plane forwards via SOCKS5h, MUST NOT resolve
// locally) — the per-PR implementation of SC-003's "zero DNS queries for
// any *.onion name" assertion via gopacket's DNS layer parse. The
// release-cadence SC-003 measurement against a real Mullvad Browser
// session is T034a (separate ticket, out of scope here).
//
// The session is Go-driven: a synthetic SOCKS5 backend
// (fake_socks5_tor.go AcceptAndRelay) stands in for the Tor sidecar so
// the test exercises the data plane's forwarding hot path without the
// real Tor network. A buggy data plane that resolves the .onion target
// locally before forwarding would emit a DNS query on lo (to the host
// resolver) and possibly on the egress NIC (to the upstream resolver);
// this test catches that regression by capturing both interfaces for the
// duration of a 60-second session and failing on the first DNS packet
// whose query name or response name matches *.onion.
//
// Test-first per Constitution Principle VII — self-skips until T047
// (data-plane/internal/forward/tor.go) and T050
// (data-plane/cmd/stargate-proxy/main.go) land. T050's task body
// explicitly lists T034 as one of its end-to-end verification targets,
// so the env-var contract this test assumes (STARGATE_TOR_SOCKS5 to
// redirect the upstream away from `tor:9050`;
// STARGATE_TEST_TOKEN_PLAINTEXT to load a one-token in-memory generation
// without the control plane — the same test-only surface T079a requires)
// is part of T050's interface contract, not an invention here.
package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/proxy"
)

// T034 constants.
//
// t034DPAddr is FR-005's fixed loopback data-plane port. The test does
// not override it; a regression that moves the listener off 8881 fails
// here, surfacing the FR-005 violation.
//
// t034SessionWin is the SC-003 canonical window (60 s per task body).
// PR-cadence choice: long enough that a buggy startup path that resolves
// the target once would be observed, short enough to keep the docker PR
// job fast. Sub-window-cadence leaks stay release-cadence residue (T034a).
//
// t034PollEvery paces the synthetic CONNECT driver. Faster than the
// session window means many distinct .onion targets are exercised per
// run, widening the regression catchment beyond a single lookup.
//
// t034ReqTimeout bounds a single CONNECT attempt. The fake SOCKS5
// (AcceptAndRelay) round-trips immediately, so this is a safety upper
// bound for a stalled attempt, not the expected latency.
//
// t034DPStartWait caps the wait for the data plane subprocess to open
// its listener on 8881. Generous for cold start (snapshot load + CP dial
// timeout under Principle II).
//
// t034CaptureBlockTimeout is the afpacket TPACKET_V3 block-retirement
// timeout. Bounds NextPacket's recvfrom: a quiet egress NIC sees
// ErrTimeout every ~100 ms, the loop re-checks captureCtx, and the
// goroutine exits within ~100 ms of captureCancel. Without this bound
// captureWG.Wait() could hang the named Docker PR job. (The afpacket
// default is 64 ms; this constant makes the bound concrete rather than
// implicit so a future afpacket release changing the default cannot
// silently regress the test.)
const (
	t034DPAddr              = "127.0.0.1:8881"
	t034SessionWin          = 60 * time.Second
	t034PollEvery           = 1 * time.Second
	t034ReqTimeout          = 10 * time.Second
	t034DPStartWait         = 15 * time.Second
	t034CaptureBlockTimeout = 100 * time.Millisecond
)

// t034OnionTargets is the synthetic corpus of distinct first-party
// .onion domains the session drives through the data plane. Each is a
// SOCKS5h DOMAIN target (ATYP=0x03) — the data plane must forward each
// to the fake SOCKS5 upstream WITHOUT resolving it locally. Distinct
// names widen the regression catchment: a per-name cache that leaks
// once would still be observed against the unmatched 19.
var t034OnionTargets = []string{
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
	"8888888888888888.onion",
	"9999999999999999.onion",
	"0000000000000000.onion",
	"abcdefghijklmnop.onion",
	"qrstuvwxyz012345.onion",
	"stargatetestxxxxx.onion",
}

// t034TestToken is the bearer token the data plane is told (via
// STARGATE_TEST_TOKEN_PLAINTEXT) to load into its in-memory generation.
// The same plaintext is then used as the SOCKS5 PASSWD by the session
// driver. Not a real credential — test fixture only, never deployed.
//
// Format: 32-character lowercase-hexadecimal per FR-017 ("Each plaintext
// token MUST be a 32-character lowercase-hexadecimal string, 128 bits of
// entropy"). T050's STARGATE_TEST_TOKEN_PLAINTEXT path is expected to
// honour the same format check as the production tokens.yaml loader; a
// non-conforming fixture here would be silently rejected, every CONNECT
// from t034IssueConnect would fail AUTH_REQUIRED at the DP, no SOCKS5h
// DOMAIN target would ever be forwarded, and T034 would pass vacuously.
const t034TestToken = "0123456789abcdef0123456789abcdef"

// TestDNSLeak is the T034 / SC-003 per-PR DNS-leak regression gate.
//
// During a 60-second Go-driven routed session of *.onion CONNECTs
// through the data plane, ZERO DNS packets matching *.onion may appear
// on lo OR on the egress NIC. Captures via gopacket/afpacket; fails
// fast on the first match.
//
// Self-skips until T047 (forward/tor.go) and T050 (DP main.go) land —
// the test-first pattern from T033. The test is the target the
// implementation lands against, not a downstream consumer.
func TestDNSLeak(t *testing.T) {
	// --- Content gates (T047 / T050) ------------------------------------
	// The test is authored BEFORE the implementation it verifies. Skip
	// (not fail) when the implementation hasn't landed yet — same pattern
	// T033 / T019b sub-test (c) / T094b's AppPlaneContainersHardened use.
	repoRoot := t034FindRepoRoot(t)
	dpMain := filepath.Join(repoRoot, "data-plane", "cmd", "stargate-proxy", "main.go")
	fwdTor := filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go")
	if _, err := os.Stat(dpMain); err != nil {
		t.Skipf("blocked: %s absent — T050 (DP main) not landed; T034 verifies it end-to-end (T050 task body)", dpMain)
	}
	if _, err := os.Stat(fwdTor); err != nil {
		t.Skipf("blocked: %s absent — T047 (forward/tor.go) not landed; T034 verifies it end-to-end", fwdTor)
	}

	// gopacket/afpacket opens a raw socket (AF_PACKET) which requires
	// CAP_NET_RAW or root. Under //go:build docker the named Docker PR
	// job runs as root; this check is defense-in-depth for a misconfigured
	// job or a local invocation that built with -tags docker but is not
	// privileged. A non-privileged run that proceeded would get a
	// permission-denied error from afpacket.NewTPacket with no DNS
	// packets observed — silently passing the assertion vacuously, which
	// is worse than skipping (a skip is honest about not having run).
	if os.Geteuid() != 0 {
		t.Skipf("blocked: not running as root (euid=%d) — gopacket/afpacket needs CAP_NET_RAW; run under the docker PR job (STARGATE_TEST_TAGS=docker scripts/verify.sh)", os.Geteuid())
	}

	// --- Locate the egress NIC BEFORE bringing anything up ----------------
	// The default-route interface is the only non-loopback path a leaked
	// DNS query could take to an upstream resolver. Resolving it before
	// the DP starts avoids racing with anything the DP might do to the
	// routing table (it should not, but Principle I's "no cover traffic"
	// + the fail-closed stance prefer not to assume).
	egressNIC, err := t034DefaultEgressNIC()
	if err != nil {
		t.Fatalf("could not determine default egress NIC: %v", err)
	}
	t.Logf("egress NIC for capture: %s", egressNIC)

	// --- Start synthetic SOCKS5 upstream (fake_socks5_tor.go) -------------
	// AcceptAndRelay completes the SOCKS5 handshake and round-trips bytes
	// in memory — no real upstream, no network egress. The data plane's
	// forwarding hot path is exercised against this fake; any DNS leak
	// would originate from the data plane resolving the .onion target
	// locally before forwarding, NOT from the fake.
	fakeSrv := NewServer(AcceptAndRelay)
	fakeAddr, err := fakeSrv.Start()
	if err != nil {
		t.Fatalf("fake SOCKS5 start: %v", err)
	}
	t.Cleanup(func() { _ = fakeSrv.Close() })
	t.Logf("fake SOCKS5 upstream listening on %s", fakeAddr)

	// --- Build the data plane binary from source -------------------------
	// Mirrors T019b's `go build` step: builds the binary into a temp dir
	// so the test exercises on-disk state, not a stale cached tag. The
	// build is bounded; a slow build machine does not blow past the
	// session window because the build runs BEFORE capture starts.
	tmpDir := t.TempDir()
	dpBin := filepath.Join(tmpDir, "stargate-proxy")
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer buildCancel()
	buildCmd := exec.CommandContext(buildCtx, "go", "build", "-o", dpBin, "./cmd/stargate-proxy")
	buildCmd.Dir = filepath.Join(repoRoot, "data-plane")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build data-plane: %v\n%s", err, out)
	}
	t.Logf("built data plane binary: %s", dpBin)

	// --- Start the data plane subprocess ---------------------------------
	// Env-var contract T050 must honour (T050 task body lists T034 as a
	// verification target; T079a's "one-token in-memory generation"
	// framing requires the same surface):
	//   STARGATE_TOR_SOCKS5=<addr>  — override the `tor:9050` upstream.
	//   STARGATE_TEST_TOKEN_PLAINTEXT=<token> — load a single in-memory
	//     token generation, bypassing the CP + snapshot files entirely.
	// No CP socket is created; the DP must come up healthy with just the
	// in-memory generation (Principle II — admission is not CP-gated).
	dpCtx, dpCancel := context.WithCancel(context.Background())
	defer dpCancel()
	dpCmd := exec.CommandContext(dpCtx, dpBin)
	dpCmd.Env = append(os.Environ(),
		"STARGATE_TOR_SOCKS5="+fakeAddr,
		"STARGATE_TEST_TOKEN_PLAINTEXT="+t034TestToken,
	)
	// Capture stderr for diagnostics: if the DP fails to start, the log
	// output is the fastest path to root cause. The output is NOT
	// inspected for the DNS-leak assertion (packet capture is) — only
	// surfaced on test failure via t.Logf.
	dpStderr := &safeBuffer{}
	dpCmd.Stderr = dpStderr
	dpCmd.Stdout = io.Discard
	if err := dpCmd.Start(); err != nil {
		t.Fatalf("start data plane subprocess: %v", err)
	}
	t.Cleanup(func() {
		// Kill (not Signal) so the subprocess cannot hang on a graceful
		// shutdown that waits on an in-flight request. t.Cleanup runs
		// after the test body returns; by then capture is already torn
		// down and the assertion has fired or passed.
		if dpCmd.Process != nil {
			_ = dpCmd.Process.Kill()
		}
		<-dpCtx.Done() // process released via CommandContext's internal goroutine
		if dpStderr.Len() > 0 {
			t.Logf("data plane stderr (cleanup):\n%s", dpStderr.String())
		}
	})

	// Wait for the DP to listen on 8881. A failed boot surfaces here with
	// the captured stderr in the diagnostic.
	if err := t034WaitForListen(t034DPAddr, t034DPStartWait); err != nil {
		t.Fatalf("data plane did not listen on %s within %s: %v\nstderr:\n%s",
			t034DPAddr, t034DPStartWait, err, dpStderr.String())
	}
	t.Logf("data plane listening on %s", t034DPAddr)

	// --- Start packet capture on lo + egress NIC -------------------------
	// Two goroutines, one per interface. Each reads packets via
	// afpacket, parses the DNS layer, and pushes any *.onion match to
	// leakCh. The first match wins; later goroutines see ctx cancelled.
	//
	// captureStarted is an atomic counter the goroutines increment ONLY
	// after their afpacket handle opened successfully. The test body
	// asserts captureStarted == 2 after the startup sleep — a capture
	// that silently died (e.g. AF_PACKET denied despite root, or a
	// typo'd interface name) is the worst silent-pass failure mode for
	// a privacy-critical regression gate, so we promote it to t.Fatalf
	// rather than leaving it to t.Logf visibility on PASS.
	leakCh := make(chan t034LeakFinding, 32)
	captureCtx, captureCancel := context.WithCancel(context.Background())
	defer captureCancel()

	var captureWG sync.WaitGroup
	var captureStarted atomic.Int32
	for _, iface := range []string{"lo", egressNIC} {
		captureWG.Add(1)
		go func(iface string) {
			defer captureWG.Done()
			t034CaptureDNSLeak(captureCtx, iface, leakCh, &captureStarted, t.Logf)
		}(iface)
	}
	// Ensure capture handles have opened BEFORE the session starts, so a
	// fast leak at session start is observed. 500 ms is enough for
	// afpacket.NewTPacket + OptBlockTimeout init on a warmed-up kernel.
	time.Sleep(500 * time.Millisecond)
	if started := captureStarted.Load(); started != 2 {
		// Capture is the test's only observation surface. If either
		// interface failed to start, the leak assertion below would
		// pass vacuously regardless of data-plane behaviour. Fail loud.
		dumpStderr := dpStderr.String()
		t.Fatalf("capture did not start on both interfaces (started=%d, want 2) — DNS-leak assertion would be vacuous; refusing to pass. lo + %s both required. DP stderr so far:\n%s",
			started, egressNIC, dumpStderr)
	}
	t.Logf("capture confirmed started on lo + %s", egressNIC)

	// --- Drive the 60-second session -------------------------------------
	// The session issues CONNECTs at t034PollEvery cadence to distinct
	// .onion targets. It exits early on the first leak (fail fast) or on
	// session window expiry (PASS).
	//
	// connectWG tracks every per-CONNECT goroutine so the failure
	// message's t.Logf calls cannot race ahead of test exit. Each
	// CONNECT is fire-and-forget at the session level (its result is
	// not asserted), but the WG is joined after captureCancel so the
	// test body never returns with in-flight t.Logf writers.
	sessionDeadline := time.Now().Add(t034SessionWin)
	var (
		requestsIssued atomic.Int32
		leakFinding    *t034LeakFinding
		leakOnce       sync.Once
		connectWG      sync.WaitGroup
	)

	sessionDone := make(chan struct{})
	go func() {
		defer close(sessionDone)
		ticker := time.NewTicker(t034PollEvery)
		defer ticker.Stop()
		// connectWG is joined outside the driver, after captureCancel.
		// The defer order below (ticker.Stop, then connectWG is NOT
		// deferred here) means the driver returns while CONNECTs may
		// still be in flight; the test body joins connectWG explicitly.
		idx := 0
		for {
			select {
			case <-captureCtx.Done():
				return
			case <-ticker.C:
				if time.Now().After(sessionDeadline) {
					return
				}
				target := t034OnionTargets[idx%len(t034OnionTargets)]
				idx++
				// Each CONNECT runs in its own goroutine so a stalled
				// attempt cannot block the ticker. The CONNECT result is
				// not asserted on — the test's property is "no DNS leak",
				// not "request succeeded". A failed CONNECT (route down,
				// timeout) is acceptable; a leaked DNS query is not.
				requestsIssued.Add(1)
				connectWG.Add(1)
				go func(target string) {
					defer connectWG.Done()
					t034IssueConnect(target, t.Logf)
				}(target)
			}
		}
	}()

	// Watch for the first leak or session window expiry.
	select {
	case leak := <-leakCh:
		leakOnce.Do(func() { leakFinding = &leak })
	case <-sessionDone:
	}

	// --- Stop capture, drain, assert -------------------------------------
	// captureCancel signals BOTH the capture goroutines AND the session
	// driver (which selects on captureCtx.Done). Wait for all three:
	// captureWG (capture goroutines), sessionDone (driver exited),
	// connectWG (in-flight CONNECTs finished). Only then is it safe to
	// read requestsIssued for the failure message without a race.
	captureCancel()
	captureWG.Wait()
	<-sessionDone
	connectWG.Wait()

	// Symmetric defensive check to captureStarted==2 above: the capture
	// plane is observed, but if the auth/forwarding plane never advanced
	// a single CONNECT to the fake SOCKS5 (env-var token contract
	// broken, T050 enforces FR-017 and rejected the fixture, DP came up
	// unhealthy, etc.), the leak assertion would pass vacuously exactly
	// the way a dead capture would. fake_socks5_tor.go records every
	// observed SOCKS5 USERNAME at sub-negotiation; if none were observed
	// after requestsIssued>0 CONNECTs were driven, refuse to pass.
	// Mirrors the captureStarted check's failure class on the forwarding
	// side (Principle VII: a test that demonstrates the property).
	if observed := len(fakeSrv.CircuitIDs()); observed == 0 {
		t.Fatalf("no CONNECT reached the fake SOCKS5 (CircuitIDs=%d, want >0; %d CONNECTs issued) — env-var token contract broken or DP rejected all requests; DNS-leak assertion would be vacuous; refusing to pass. DP stderr:\n%s",
			observed, requestsIssued.Load(), dpStderr.String())
	}
	t.Logf("OK: %d distinct SOCKS5 USERNAMEs observed at the fake upstream (forwarding path exercised)", len(fakeSrv.CircuitIDs()))

	// Drain any straggler findings the capture goroutines had in flight
	// when captureCancel fired.
	drained := 0
drainLoop:
	for {
		select {
		case leak := <-leakCh:
			drained++
			leakOnce.Do(func() { leakFinding = &leak })
		default:
			break drainLoop
		}
	}

	if leakFinding != nil {
		t.Fatalf("DNS LEAK DETECTED — FR-003/FR-007 regression (SOCKS5h not enforced; data plane resolved a *.onion target locally):\n"+
			"  %s\n"+
			"  session stats: %d CONNECTs issued over %s on lo + %s\n"+
			"  (capture observed %d additional finding(s) after the first)",
			leakFinding.String(), requestsIssued.Load(), t034SessionWin, egressNIC, drained)
	}

	t.Logf("OK: T034 PASS — %d *.onion CONNECTs through the data plane over %s; zero DNS packets matching *.onion observed on lo or %s",
		requestsIssued.Load(), t034SessionWin, egressNIC)
}

// t034LeakFinding describes a single DNS packet whose query name or
// response name matches *.onion — the regression signal T034 hunts.
type t034LeakFinding struct {
	Iface     string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Name      string // QNAME (question) or NAME (answer)
	QType     string // A, AAAA, MX, etc.
	Direction string // "query" or "response"
	Timestamp time.Time
}

// String formats a finding for the failure message.
func (f t034LeakFinding) String() string {
	return fmt.Sprintf("[%s] %s %s:%d → %s:%d  qname=%s  qtype=%s  at %s",
		f.Iface, f.Direction, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort,
		f.Name, f.QType, f.Timestamp.Format(time.RFC3339Nano))
}

// t034CaptureDNSLeak reads packets from the named interface, parses DNS
// queries and responses, and pushes the first *.onion match to leakCh.
// Returns when ctx is cancelled or the afpacket source errors terminally.
//
// *started is incremented ONLY after the afpacket handle + BPF setup
// succeeded. The caller asserts started == len(interfaces) before
// evaluating the leak assertion; a capture that died silently (AF_PACKET
// permission denied despite root, typo'd interface name, etc.) is the
// worst silent-pass failure mode for a privacy-critical regression gate
// and must surface as t.Fatalf, not t.Logf.
//
// The filter is applied in userspace (parse each packet, skip non-DNS),
// not via in-kernel BPF: gopacket v1.1.19's afpacket.TPacket exposes
// SetBPF([]bpf.RawInstruction) but not the string-filtered SetBPFFilter,
// and compiling BPF for "udp port 53" via golang.org/x/net/bpf would add
// a transitive dep for a low-traffic test. CPU cost is bounded by the
// 60s session window + the test's own synthetic traffic — no real
// browser is generating packet pressure.
//
// OptBlockTimeout(t034CaptureBlockTimeout) bounds NextPacket's recvfrom:
// afpacket TPACKET_V3 retires its ring-block at this interval and returns
// ErrTimeout, which the loop treats as a transient read error (log +
// continue + re-check ctx). Without this bound a quiet egress NIC could
// park NextPacket indefinitely, hanging captureWG.Wait() in the named
// Docker PR job. The 100 ms choice trades a small per-packet wakeup cost
// for a hard bound on cancel latency.
func t034CaptureDNSLeak(ctx context.Context, iface string, leakCh chan<- t034LeakFinding, started *atomic.Int32, log func(string, ...any)) {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptBlockTimeout(t034CaptureBlockTimeout),
	)
	if err != nil {
		log("t034: afpacket.NewTPacket(%s) failed: %v — capture NOT started on this interface (leak coverage reduced; test body will fail the started-count check)", iface, err)
		return
	}
	defer handle.Close()
	started.Add(1) // acknowledge BEFORE the read loop so the caller's assertion is race-free
	log("t034: capturing DNS on %s", iface)

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	src.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	for {
		// select-default + blocking read is the standard pattern, but
		// OptBlockTimeout bounds the read so the worst-case cancel
		// latency is ~t034CaptureBlockTimeout, not indefinite. The
		// TOCTOU window between the select and NextPacket is bounded
		// by the same interval: a cancel that arrives mid-read returns
		// on the next block retirement, then the loop's next iteration
		// sees ctx.Done and exits.
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
			// afpacket returns ErrTimeout on block retirement (every
			// ~100 ms by design) and io.EOF or a read error on a closed
			// source. ErrTimeout is the common, benign path — do not
			// log it (would flood). Other errors are surfaced so a
			// persistent capture failure is diagnosable: the test would
			// pass vacuously if capture silently died, which is the
			// failure mode this logging exists to surface.
			if !errors.Is(err, afpacket.ErrTimeout) {
				log("t034: NextPacket on %s: %v (continuing)", iface, err)
			}
			continue
		}
		// Fast-path skip: only DNS over UDP port 53 is in scope. Parse
		// transport first; if it's not UDP:53, skip the DNS layer parse
		// entirely. Cheaper than parsing DNS on every packet.
		if !t034IsUDP53(packet) {
			continue
		}
		finding, ok := t034ExtractOnionDNS(packet, iface)
		if !ok {
			continue
		}
		select {
		case leakCh <- finding:
		case <-ctx.Done():
			return
		}
		// First match wins: return after pushing so the session loop
		// fails fast rather than flooding leakCh with every subsequent
		// packet from the same leak.
		return
	}
}

// t034IsUDP53 reports whether the packet's transport layer is UDP with
// source or destination port 53 (DNS). Used as the fast-path filter
// before the (heavier) DNS layer parse.
func t034IsUDP53(packet gopacket.Packet) bool {
	tl := packet.TransportLayer()
	if tl == nil {
		return false
	}
	u, ok := tl.(*layers.UDP)
	if !ok {
		return false
	}
	return u.SrcPort == 53 || u.DstPort == 53
}

// t034ExtractOnionDNS returns the first *.onion-bearing DNS question or
// answer in the packet. ok is false if the packet has no DNS layer or
// the DNS layer carries no *.onion name.
func t034ExtractOnionDNS(packet gopacket.Packet, iface string) (t034LeakFinding, bool) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return t034LeakFinding{}, false
	}
	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return t034LeakFinding{}, false
	}
	ts := packet.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	// NetworkLayer (IPv4/IPv6) provides the IP pair. Absent on a
	// truncated capture; the finding still carries the QName + Iface.
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	if nl := packet.NetworkLayer(); nl != nil {
		srcEp, dstEp := nl.NetworkFlow().Endpoints()
		// Endpoint.Raw() for IPv4/IPv6 layers is the raw IP bytes —
		// net.IP is a []byte under the hood, so the conversion is free.
		srcIP = net.IP(srcEp.Raw())
		dstIP = net.IP(dstEp.Raw())
	}
	if tl := packet.TransportLayer(); tl != nil {
		if t, ok2 := tl.(*layers.UDP); ok2 {
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
		}
	}
	for _, q := range dns.Questions {
		name := string(q.Name)
		if strings.HasSuffix(name, ".onion") || strings.Contains(name, ".onion.") {
			return t034LeakFinding{
				Iface: iface, SrcIP: srcIP, DstIP: dstIP,
				SrcPort: srcPort, DstPort: dstPort,
				Name: name, QType: q.Type.String(),
				Direction: "query", Timestamp: ts,
			}, true
		}
	}
	for _, a := range dns.Answers {
		name := string(a.Name)
		if strings.HasSuffix(name, ".onion") || strings.Contains(name, ".onion.") {
			return t034LeakFinding{
				Iface: iface, SrcIP: srcIP, DstIP: dstIP,
				SrcPort: srcPort, DstPort: dstPort,
				Name: name, QType: a.Type.String(),
				Direction: "response", Timestamp: ts,
			}, true
		}
	}
	return t034LeakFinding{}, false
}

// t034IssueConnect issues a single SOCKS5h CONNECT to the .onion target
// through the data plane's loopback port. Uses proxy.SOCKS5 with a
// DOMAIN target so the SOCKS5 client itself issues NO local DNS
// resolution (ATYP=0x03 on the wire) — any DNS query for the target
// observed on lo therefore originated from the data plane, not the
// client. Errors are logged but not returned: the test's assertion is
// "no DNS leak", not "request succeeded".
func t034IssueConnect(target string, log func(string, ...any)) {
	dialer, err := proxy.SOCKS5("tcp", t034DPAddr, &proxy.Auth{
		User:     target,        // first-party domain — stream-isolation key (not a credential)
		Password: t034TestToken, // bearer token — the credential the DP validates
	}, proxy.Direct)
	if err != nil {
		log("t034: SOCKS5 dialer for %s: %v", target, err)
		return
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: t034ReqTimeout}
	reqCtx, cancel := context.WithTimeout(context.Background(), t034ReqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://"+target+"/", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		// Acceptable: the fake upstream round-trips bytes, not real HTTP;
		// a TLS handshake failure or a closed connection is expected. The
		// leak assertion is unaffected — what matters is the data plane
		// forwarded the DOMAIN framing onward without resolving locally.
		return
	}
	resp.Body.Close()
}

// t034WaitForListen blocks until something answers a TCP dial on addr
// or deadline elapses. Used to wait for the DP subprocess to open its
// listener before the session driver starts.
func t034WaitForListen(addr string, window time.Duration) error {
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("nothing listened on %s within %s", addr, window)
}

// t034DefaultEgressNIC resolves the default-route interface name via
// `ip route show default`. Falls back to parsing /proc/net/route if
// `ip` is absent (rare in a Docker image, but the fallback keeps the
// test portable across minimal containers).
func t034DefaultEgressNIC() (string, error) {
	if out, err := exec.Command("ip", "route", "show", "default").CombinedOutput(); err == nil {
		// "default via <gw> dev <iface> ..." OR "default dev <iface> ..."
		s := string(out)
		for _, line := range strings.Split(s, "\n") {
			if !strings.HasPrefix(line, "default") {
				continue
			}
			idx := strings.Index(line, " dev ")
			if idx < 0 {
				continue
			}
			rest := strings.TrimLeft(line[idx+5:], " ")
			end := strings.IndexByte(rest, ' ')
			if end < 0 {
				return strings.TrimSpace(rest), nil
			}
			return rest[:end], nil
		}
	}
	// /proc/net/route fallback. The first row with Destination == "00000000"
	// is the default route; the Interface column is its name.
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("neither `ip route` nor /proc/net/route available: %w", err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[1] != "00000000" {
			continue
		}
		return fields[0], nil
	}
	return "", fmt.Errorf("no default route found in `ip route` or /proc/net/route")
}

// t034FindRepoRoot walks up from this test file's source location to find
// the directory containing compose/docker-compose.local.yml. Mirrors
// T033 / T094b: does not rely on the working directory (go test may be
// invoked from any cwd in CI matrices or IDE runners).
func t034FindRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate test source path")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "compose", "docker-compose.local.yml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("repo root (containing compose/docker-compose.local.yml) not found by walking up from " + filepath.Dir(thisFile))
	return ""
}

// safeBuffer is a goroutine-safe bytes.Buffer for capturing subprocess
// stderr. sync.Mutex + []byte rather than bytes.Buffer (which is
// unsynchronized) because the DP subprocess writes via the *os.File
// backing the pipe while the test reads it after the process exits.
type safeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	return len(p), nil
}
func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.buf)
}
func (s *safeBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf)
}
