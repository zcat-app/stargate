// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// stream_isolation_test.go is T059: the US2 acceptance-scenario-1 gate.
// It brings up the full local-profile stack, issues two PARALLEL SOCKS5
// CONNECTs THROUGH the data plane's host-published loopback port 8881 (the
// T058/T058a contract suites dial tor:9050 directly; this test exists
// precisely to cover the DP hop they bypass), and asserts at the
// cookie-authenticated control port that the two streams attached to
// distinct, non-zero circuit IDs, each cross-checked BUILT in
// GETINFO circuit-status.
//
// Wire shape (contracts/socks5-auth.md, replicated exactly by x/net's
// proxy.SOCKS5): UNAME = the complete `sg1:` partition username the
// browser derives for a normal-mode, default-container top-level .onion
// navigation (contracts/foundation-boundaries.md; spec.md FR-002; T172/
// T173), via T126's reference-vector-pinned t126PartitionUsername — the
// two targets' tuples differ in `onion:<addr>`, so their partitions are
// distinct — PASSWD = the device bearer token. The DP validates
// the token, then forwards the UNAME verbatim as the upstream SOCKS5
// username (data-plane/internal/forward/tor.go dialUpstream, FR-007: "the
// US2 IsolateSOCKSAuth key"), never re-sending the PASSWD upstream.
// Distinct UNAMEs therefore reach tor as distinct credentials, which the
// image-baked `IsolateSOCKSAuth` torrc isolates — the same property T058
// pins at the torrc contract level, re-proven here end-to-end.
//
// Honest mechanism note (live capture, 2026-09-07): for two DIFFERENT
// onion destinations the distinct-circuit outcome is overdetermined — a
// rendezvous circuit is bound to a single onion service, so streams to
// different services cannot share one regardless of credentials (observed:
// same-credential holds to the two targets landed on circuits 13 and 24).
// This test therefore does NOT gate the DP's UNAME-forwarding axis: a DP
// that fused or dropped the upstream credentials would still pass here,
// because the destinations themselves force distinct rendezvous circuits.
// What it does pin end-to-end through port 8881 is the user-visible
// scenario 1 property plus a real authenticated route (CP-seeded token
// generation loaded and pushed via ReloadTokens, DP-side validation, DP→tor
// forwarding). The UNAME-isolation axis at tor level is pinned by T058
// (distinct usernames ⇒ distinct circuits) and T058a (no username ⇒
// shared), both dialing the sidecar directly; the same-target /
// distinct-inbound-usernames / THROUGH-THE-DP runtime gate is filed as
// T126 and pinned by no runtime test until it lands.
//
// Destinations (both must be real, reachable v3 onion services — a
// synthetic `.example.onion` never attaches a stream, so stream-level
// circuit attribution would be impossible; T058a live evidence):
//   - duckduckgogg42…zczad.onion:443 — spec-pinned reference target
//     (spec.md §"User Story 1"; port 443 proven through the DP by T033).
//   - shr6xwb55x7q4atmwjohlo4op6lxogpl5do26ptpoo2cf6hg3tsuqzad.onion:80 —
//     operator-supplied 2026-09-07 (T059 §Analysis), live-verified then
//     (raw SOCKS5 CONNECT through the sidecar returned REP=0) and
//     live-verified on every run by this test itself: a dead address
//     fails loudly at CONNECT, never as a false green. Per the spec's
//     DuckDuckGo note, an unreachable pinned target is fixed by updating
//     this harness and recording the change in SECURITY-DECISIONS.md
//     (NYT's onion was rejected: service shut down 2025-03; TPO's
//     self-published 2gzyxa5…wid.onion is the documented fallback).
//
// Bearer-token self-provisioning (the fixture T033's residue anticipated
// once T035/T038 landed): the test generates its own 32-hex token
// (crypto/rand), writes tokens.yaml (spec FR-017 shape) into the
// project-scoped stargate-control-config volume via a short-lived
// container from the already-built stargate/tor:local image (no external
// pull; stdin-fed so the token never appears in argv), restarts
// stargate-control, and lets the CONNECT retry window absorb the CP's
// argon2id load + ReloadTokens push to the DP. The token lives only in
// run-time memory/pipe and is torn down with the project's volumes.
//
// Control transport (FR-012; torrc contract invariant #3): tor exposes
// control only on the private ControlSocket
// /var/lib/tor/control/tor-control.sock (T162 removed TCP 9051). The
// cookie-authenticated probe rides `docker compose exec tor … nc -U` —
// T131's live-green shape, extended with GETINFO stream-status. Wire formats
// captured live 2026-09-07 (single-stream form `250-stream-status=<fields>`
// vs multi-stream block form `250+stream-status=` … `.`); the parser
// handles both, matching T058a's exact-count discipline: streams are
// matched by target string, never by StreamID ordering.
//
// stargate:cadence release — requires the real Tor network, two live
// onion services, and a Docker daemon; release-tag cadence like T033.
// The hermetic PR gate compiles and vets this file (go-workspace gate)
// while the body env-skips. Live invocation:
//
//	cd tests/integration && STARGATE_RUN_NETWORK_TESTS=1 \
//		go test -run TestStreamIsolationPerFirstPartyDomain -v -timeout 35m
//
// Skip guards mirror T033 (env opt-in / docker CLI / daemon / content
// gates for the not-yet-landed implementation).
//
// OPERATOR PREREQUISITES (current Local topology; T126/T131 runbook): run
// only on a disposable Linux Docker host or VM
// (tests/live-e2e/local-topology/README.md) with the `stargate-dp`
// AppArmor profile loaded in enforce mode and the DP owner rules
// installed, and with the init-equivalent key/pepper and volume-root
// provisioning (scripts/stargate init steps 2–3) done for THIS project's
// volumes — detailed at the token-seed step below. The harness automates
// only the tokens.yaml seed, the keys/ mountpoint and the two-phase
// bring-up.
package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// T059 constants.
//
// t059Project namespaces every compose invocation so the test never
// collides with operator-authored state, sibling suites, or the parallel
// T060/T061 sessions (the T033/T058a per-suite project convention).
//
// Deadlines: each compose-up phase derives its OWN 10-minute window from
// the suite context, and the bootstrap wait (5m) runs between them, so
// the stacked worst case is up 10m + boot 5m + up 10m + connect 3m +
// stream 1.5m ≈ 29.5m against a suite context of 30m and a go-test outer
// bound of 35m — a pathologically slow run surfaces as a loud deadline
// failure, not a hang, and no phase starves a later one of budget (the
// round-1 review catch: two ups sharing one window left the second up
// starved exactly on the slow path the two-phase bring-up exists to
// absorb). The connect window mirrors T058a's rationale: the first
// CONNECTs after PROGRESS=100 can fail transiently while tor warms its
// circuit builder / fetches descriptors (REP=1 within seconds of
// bootstrap was observed live on the T058a run).
const (
	t059Project = "stargate-t059-test"
	t059DPAddr  = "127.0.0.1:8881" // FR-005; the host-published DP loopback

	t059OnionA    = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	t059OnionAPrt = 443 // served (TLS); T033 proved this port through the DP
	t059OnionB    = "shr6xwb55x7q4atmwjohlo4op6lxogpl5do26ptpoo2cf6hg3tsuqzad.onion"
	t059OnionBPrt = 80 // served; live-verified REP=0 at T059 grounding (2026-09-07)

	t059UpDead      = 10 * time.Minute // per compose-up phase (T033's build+start)
	t059BootDead    = 5 * time.Minute  // tor bootstrap (T033)
	t059ConnectWait = 3 * time.Minute  // per-conn retry window (T058a's rationale)
	t059StreamWait  = 90 * time.Second // stream-attach wait (T033/T058a)
	t059PollEvery   = 5 * time.Second  // bootstrap poll cadence (T033)
	t059StreamPoll  = 2 * time.Second  // stream-status poll cadence (T058a)
	t059ExecDead    = 15 * time.Second // docker compose exec deadline (T033)
	t059OverallDead = 30 * time.Minute // whole-suite ctx; test -timeout 35m is outer

	// t059ControlSocket is tor's only control endpoint (torrc contract
	// invariant #3; T162).
	t059ControlSocket = "/var/lib/tor/control/tor-control.sock"
)

// t059ProfileID is the fixed browser-profile id of both partitions (the
// foundation-boundaries reference vector's); only the target varies.
var t059ProfileID = strings.Repeat("11", 32)

// t059OnionShape is the v3 onion-address shape (T063's corpus invariant):
// 56 base32 chars (a-z2-7) + ".onion". Both destination constants are
// validated against it at test start — a corrupted constant would
// otherwise surface as an opaque descriptor error minutes into the run.
var t059OnionShape = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

// t059TerminalStreamStates are the stream-status states a dead stream can
// carry; they never count toward the exactly-one match (T058a parity).
var t059TerminalStreamStates = map[string]bool{
	"CLOSED": true, "FAILED": true, "DETACHED": true,
}

// TestStreamIsolationPerFirstPartyDomain is T059 (spec US2 acceptance
// scenario 1): two parallel CONNECTs through port 8881 to two distinct
// .onion destinations, each with its own `sg1:` partition username,
// MUST attach to distinct circuits at the Tor control port.
func TestStreamIsolationPerFirstPartyDomain(t *testing.T) {
	// --- Self-skip guards (T033 pattern) ---------------------------------
	if os.Getenv("STARGATE_RUN_NETWORK_TESTS") != "1" {
		t.Skip("STARGATE_RUN_NETWORK_TESTS != 1 — release-tag test (needs real Tor network + two live onion services); set to opt in")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}
	for _, onion := range []string{t059OnionA, t059OnionB} {
		if !t059OnionShape.MatchString(onion) {
			t.Fatalf("destination constant fails v3 shape check: %q", onion)
		}
	}

	repoRoot := t059FindRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}

	// Content gates: the implementation this scenario rides (T033's
	// test-first pattern — skip, not fail, when the code isn't there).
	dpMain := filepath.Join(repoRoot, "data-plane", "cmd", "stargate-proxy", "main.go")
	if _, err := os.Stat(dpMain); err != nil {
		t.Skipf("blocked: %s absent — T050 (DP main) not landed", dpMain)
	}
	fwdTor := filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go")
	if _, err := os.Stat(fwdTor); err != nil {
		t.Skipf("blocked: %s absent — T047 (forward/tor.go) not landed", fwdTor)
	}
	if t059CountSuffix(filepath.Join(repoRoot, "control-plane"), ".java") == 0 {
		t.Skip("blocked: no .java sources under control-plane/ — CP not buildable (cannot load tokens / render the stack)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), t059OverallDead)
	defer cancel()

	// Cleanup BEFORE up (T019b's ordering rationale): a partially-successful
	// up must not orphan the project when the test aborts.
	t.Cleanup(func() {
		dCtx, dCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer dCancel()
		if out, err := t059Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// Signal-safe teardown (T033's redteam finding): an orphaned project
	// keeps the Tor sidecar's circuits alive — exposing the operator's IP
	// to their entry guards after the test ended. compose-down is
	// idempotent, so a double teardown (this + t.Cleanup) is harmless.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		dCtx, dCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dCancel()
		if out, err := t059Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "signal %v: compose down (best-effort): %v\n%s", sig, err, out)
		}
		os.Exit(1)
	}()

	// --- Bring up the stack: tor first, bootstrapped, then the rest ------
	// --build forces a rebuild against current Dockerfiles (T033): the test
	// exercises on-disk state, not a stale cached tag.
	//
	// Why tor in a separate phase (live-run finding 2026-09-07): the tor
	// HEALTHCHECK then demanded full bootstrap within ~150s and
	// stargate-control depended on it, so a slow cold bootstrap (minutes —
	// T032/T058a budget 5m) aborted the whole `up`. T162/T152 removed that
	// gate (the tor healthcheck is disabled and nothing depends on it);
	// the split remains so the CONNECT windows below start only after tor
	// has bootstrapped under this suite's OWN 5-minute deadline.
	t.Log("bringing up tor and waiting for bootstrap…")
	upCtx, upCancel := context.WithTimeout(ctx, t059UpDead)
	if out, err := t059Compose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		upCancel()
		t.Fatalf("docker compose up tor: %v\n%s", err, out)
	}
	upCancel()
	t059WaitBootstrapped(t, ctx, composeFile, envFile)

	// --- Seed the bearer token BEFORE the CP's first start ---------------
	// (FR-017 shape; T035 loads at CP boot → pushes to the DP.) The seed
	// must precede the full `up`: the CP container cannot even START until
	// the config volume carries the pre-created keys/ mountpoint (T123),
	// and starting before the token exists would only add an empty
	// generation that a restart would then have to fix.
	//
	// OPERATOR PREREQUISITE (not harness-automated — T033's approved
	// "provisioning is the operator's job at release-tag time" residue,
	// sharpened by the round-1 review): the release-run operator must have
	// run the init-equivalent key provisioning for THIS project's volumes
	// before invoking the live command — the ed25519 keypairs + 32-byte
	// pepper into <project>_stargate-keys (cp.priv/dp.priv 0600 owned
	// 5101:5100 resp. 5102:5100, pubs 0644, pepper 0640 cp:ipc) AND the
	// volume-root ownership initialisation for stargate-keys (5101:5100
	// 0750), stargate-ipc (5102:5100 0770), stargate-control-state /
	// stargate-dp-state / stargate-tor-config (5101/5102:5100 0750) —
	// scripts/stargate init steps 2–3 (scripts/subcommands/init), scoped
	// to this project's volume names. Without it the DP fail-fasts on the
	// missing pepper (main.go auth.LoadPepper → exit 1) and the CP on its
	// own pepper read — the harness only automates the tokens.yaml +
	// keys/-mountpoint + cp-restart half. A shared init-equivalent
	// provisioning helper for the full-stack suites is the T123/T126-era
	// follow-up this file deliberately does not re-implement per-suite.
	token, err := t059NewToken()
	if err != nil {
		t.Fatalf("generate bearer token: %v", err)
	}
	if err := t059SeedToken(ctx, token); err != nil {
		t.Fatalf("seed token into %s_stargate-control-config: %v", t059Project, err)
	}
	t.Log("token seeded (CP first boot will load it and push the generation to the DP)")

	t.Log("bringing up data plane + control plane…")
	// Fresh per-phase deadline (round-1 review Finding 3): the second up
	// gets its own t059UpDead window instead of sharing the first up's.
	up2Ctx, up2Cancel := context.WithTimeout(ctx, t059UpDead)
	defer up2Cancel()
	// Scoped to the two planes, WITH --build kept for freshness (T033):
	// a list-less `up -d --build` would also rebuild the tor image, see
	// its hash move, RECREATE the healthy tor container, and re-race the
	// healthcheck's bootstrap window from zero (live-run finding #3,
	// run #6). Naming the services leaves the running tor untouched; its
	// already-healthy state satisfies stargate-control's depends_on.
	if out, err := t059Compose(up2Ctx, composeFile, envFile, "up", "-d", "--build", "stargate-dp", "stargate-control"); err != nil {
		t.Fatalf("docker compose up (data + control planes): %v\n%s", err, out)
	}

	// --- Two PARALLEL CONNECTs through port 8881 --------------------------
	// Barrier start (sync.WaitGroup as starting gun): both dials are in
	// flight concurrently, per scenario 1's "in parallel". Each connection
	// retries independently until its window — post-bootstrap transient
	// failures must not turn into order-dependent flakes. The winner's
	// conn is held OPEN (stream stays attached) until both assertions run.
	t.Logf("issuing parallel CONNECTs through %s to two distinct .onion targets…", t059DPAddr)
	connA, connB := t059ParallelConnect(t, ctx, composeFile, envFile, token)
	t.Cleanup(func() { _ = connA.Close(); _ = connB.Close() })

	// --- Assert distinct circuit IDs at the control port ------------------
	circA := t059WaitStreamCircuit(t, ctx, composeFile, envFile, t059Target(t059OnionA, t059OnionAPrt))
	circB := t059WaitStreamCircuit(t, ctx, composeFile, envFile, t059Target(t059OnionB, t059OnionBPrt))

	if circA == "0" || circB == "0" {
		t.Fatalf("stream(s) reported unattached (CircID 0): %s → %s, %s → %s",
			t059OnionA, circA, t059OnionB, circB)
	}
	if circA == circB {
		t.Fatalf("DISTINCT first-party usernames (via the DP) shared circuit %s — "+
			"FR-002 per-first-party isolation broken end-to-end: either the DP fused "+
			"the upstream credentials (T047 regression) or tor stopped isolating "+
			"credential-bearing streams (T058's torrc contract would fail too)", circA)
	}
	t059AssertCircuitBuilt(t, ctx, composeFile, envFile, circA)
	t059AssertCircuitBuilt(t, ctx, composeFile, envFile, circB)
	t.Logf("OK: streams attached to distinct circuits (%s → %s, %s → %s), both BUILT",
		t059OnionA, circA, t059OnionB, circB)
}

// t059Target renders the stream-status target string for an onion:port —
// the DP forwards DST.ADDR=DST.PORT verbatim upstream (dumb router), and
// tor renders the stream target as "<addr>:<port>" (live-captured format).
func t059Target(onion string, port int) string {
	return fmt.Sprintf("%s:%d", onion, port)
}

// t059NewToken generates a bearer token in the FR-017 plaintext shape:
// 32 lowercase hex chars (16 crypto/rand bytes). The token is the SOCKS5
// PASSWD the DP validates; it never appears in source, argv, or logs.
func t059NewToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// t059SeedToken provisions the project's stargate-control-config volume
// BEFORE the CP's first start: it creates the volume under compose's
// labels (compose adopts same-name volumes; the labels keep
// `compose down --volumes` cleanup working), pre-creates the keys/
// mountpoint, and writes tokens.yaml (T035's TokenLoader reads it at CP
// boot and pushes the generation to the DP via ReloadTokens — the
// quickstart's operator flow, automated). The file is fed on stdin to a
// short-lived container from the already-built tor image — no external
// pull, and the token never lands in argv.
func t059SeedToken(ctx context.Context, token string) error {
	vol := t059Project + "_stargate-control-config"
	// Tolerance for "already exists" keeps re-runs against a surviving
	// project idempotent; the labels mirror what compose itself sets, so
	// the cleanup `down --volumes` still finds and removes the volume.
	create := exec.CommandContext(ctx, "docker", "volume", "create",
		"--label", "com.docker.compose.project="+t059Project,
		"--label", "com.docker.compose.volume=stargate-control-config",
		vol)
	if out, err := create.CombinedOutput(); err != nil {
		return fmt.Errorf("create config volume: %v: %s", err, out)
	}
	// FR-017 plaintext = 32 lowercase hex; shape asserted by construction
	// (t059NewToken) and re-checked here so a future generator change
	// fails at the seed step, not as an opaque CP validation warning.
	if matched, _ := regexp.MatchString(`^[0-9a-f]{32}$`, token); !matched {
		return fmt.Errorf("token does not match the FR-017 plaintext shape")
	}
	tokensYAML := fmt.Sprintf("tokens:\n  - label: t059-test\n    token: %s\n", token)
	// mkdir -p keys: on a fresh volume the CP cannot start without it —
	// its rw stargate-keys child mount at /etc/stargate/keys needs a
	// mountpoint inside the :ro-mounted /etc/stargate volume, and runc
	// cannot mkdir there (EROFS; docker 29.1.3, observed 2026-09-07 —
	// live-verified that a pre-created dir lets the keys volume mount rw
	// at the contract path). Operator-equivalent provisioning riding the
	// same seed step; the product-side gap is T123. --entrypoint sh
	// overrides the image's `tor` entrypoint (docker exec bypasses it —
	// which is why the control-port probes don't need this; docker run
	// does).
	write := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--user", "0:0",
		"--entrypoint", "sh",
		"-v", vol+":/tgt", "stargate/tor:local",
		"-c", "mkdir -p /tgt/keys && cat > /tgt/tokens.yaml")
	write.Stdin = strings.NewReader(tokensYAML)
	if out, err := write.CombinedOutput(); err != nil {
		return fmt.Errorf("write tokens.yaml into volume: %v: %s", err, out)
	}
	return nil
}

// t059WaitBootstrapped polls GETINFO status/bootstrap-phase until
// PROGRESS=100 (T032/T033's shape): SOCKS CONNECTs before full bootstrap
// fail transiently in ways that would masquerade as the assertion failing.
func t059WaitBootstrapped(t *testing.T, ctx context.Context, composeFile, envFile string) {
	t.Helper()
	deadline := time.Now().Add(t059BootDead)
	for {
		out, err := t059ControlProbe(ctx, composeFile, envFile, "GETINFO status/bootstrap-phase")
		if err == nil && strings.Contains(out, "PROGRESS=100") {
			t.Logf("OK: tor bootstrapped")
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tor did not reach PROGRESS=100 within %s (last probe: %q, err: %v)",
				t059BootDead, strings.TrimSpace(out), err)
		}
		time.Sleep(t059PollEvery)
	}
}

// t059ControlProbe runs one cookie-authenticated control command over
// tor's private ControlSocket inside the tor container and returns the
// raw reply text. The probe mirrors T131's t131WaitBootstrapped: locate
// the cookie with `find` (T087's DataDirectory note), hex-encode it,
// AUTHENTICATE, send the command, QUIT; `nc -q 1` closes after the reply.
func t059ControlProbe(ctx context.Context, composeFile, envFile string, command string) (string, error) {
	shell := `COOKIE=$(find /var/lib/tor -name control_auth_cookie 2>/dev/null | head -1)` +
		` && [ -n "$COOKIE" ]` +
		` && HEX=$(od -An -tx1 "$COOKIE" | tr -d ' \n')` +
		` && { printf 'AUTHENTICATE %s\r\n' "$HEX"` +
		`      ; printf '` + command + `\r\n'` +
		`      ; printf 'QUIT\r\n'` +
		`      ; } | nc -q 1 -U ` + t059ControlSocket
	eCtx, cancel := context.WithTimeout(ctx, t059ExecDead)
	defer cancel()
	out, err := t059Compose(eCtx, composeFile, envFile, "exec", "-T", "tor", "sh", "-c", shell)
	return string(out), err
}

// t059ParallelConnect dials both targets through the DP concurrently and
// returns the two held-open conns. Barrier semantics: close(start) is the
// starting gun — both dials are in flight simultaneously, per scenario 1's
// "in parallel". Each worker retries independently until the per-conn
// window; if either is still failing at the deadline the test dies with
// BOTH outcomes (a one-sided failure is diagnostic — auth vs route — and
// the tor log tail is the forensics channel), so a single bad target
// cannot pass as a flake, and any established conn is released.
func t059ParallelConnect(t *testing.T, ctx context.Context, composeFile, envFile, token string) (net.Conn, net.Conn) {
	t.Helper()
	targets := [2]struct {
		onion string
		port  int
	}{
		{t059OnionA, t059OnionAPrt},
		{t059OnionB, t059OnionBPrt},
	}
	start := make(chan struct{})
	results := make(chan t059DialResult, 2)
	for i := 0; i < 2; i++ {
		go t059DialWorker(ctx, start, i, targets[i].onion, targets[i].port, token, results)
	}
	close(start)

	conns := make([]net.Conn, 2)
	errs := make([]error, 2)
	for done := 0; done < 2; done++ {
		r := <-results
		if r.err != nil {
			errs[r.idx] = r.err
		} else {
			conns[r.idx] = r.conn
		}
	}
	if errs[0] != nil || errs[1] != nil {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
		// Forensics (acceptance item 1's diagnostics clause): name the
		// broken link per target, then attach bounded service logs —
		// SafeLogging 1 makes the tor tail safe to print (torrc contract
		// invariants #8–#9; the same channel T058a attaches).
		t.Fatalf("parallel CONNECT through %s did not establish both streams within %s\n  %s: %s\n  %s: %s\n%s\n%s",
			t059DPAddr, t059ConnectWait,
			t059Target(targets[0].onion, targets[0].port), t059ClassifyDialErr(errs[0]),
			t059Target(targets[1].onion, targets[1].port), t059ClassifyDialErr(errs[1]),
			t059ServiceLogTail(t, ctx, composeFile, envFile, "stargate-dp", 12),
			t059ServiceLogTail(t, ctx, composeFile, envFile, "tor", 15))
	}
	return conns[0], conns[1]
}

// t059ClassifyDialErr names the broken link the way the acceptance labels
// it (auth / route / isolation), keyed on the observed error surfaces:
// x/net's SOCKS5 auth rejection string, the RFC 1928 upstream-refusal
// wrapper ("unknown error <rep>", the same surface forward/tor.go
// classify keys on), dial-refused on the published port, and deadline
// exhaustion (tor rendezvous/descriptor latency). Classification is
// diagnostic only — the assertion above does not depend on it.
func t059ClassifyDialErr(err error) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "username/password authentication failed"):
		return "AUTH: SOCKS5 auth rejected — token generation not loaded/pushed? (seed step, CP restart, ReloadTokens push)"
	case strings.Contains(msg, "connection refused"):
		return "ROUTE: DP listener unreachable on the published port — is stargate-dp running? (see T125 for the compose-publish conflict)"
	case strings.Contains(msg, "unknown error "):
		return "ROUTE: upstream (tor sidecar) refused the CONNECT — see the tor log tail below"
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "Client.Timeout"):
		return "ROUTE: tor rendezvous/descriptor latency exceeded the window — see the tor log tail below"
	default:
		return "UNCLASSIFIED: " + msg
	}
}

// t059ServiceLogTail returns the last n log lines of a compose service
// for failure forensics. Best-effort: a logs failure is reported inside
// the returned string, never fatal — the primary Fatalf above is the
// signal, this is the forensics channel (T058a's ulTorLogTail shape).
func t059ServiceLogTail(t *testing.T, ctx context.Context, composeFile, envFile, service string, n int) string {
	t.Helper()
	eCtx, cancel := context.WithTimeout(ctx, t059ExecDead)
	defer cancel()
	out, err := t059Compose(eCtx, composeFile, envFile, "logs", "--tail", fmt.Sprint(n), service)
	if err != nil {
		return fmt.Sprintf("— %s logs unavailable: %v", service, err)
	}
	return fmt.Sprintf("— %s log tail:\n%s", service, strings.TrimSpace(string(out)))
}

// t059DialResult is one worker's outcome; idx routes it back to the right
// slot without order assumptions on channel delivery.
type t059DialResult struct {
	idx  int
	conn net.Conn
	err  error
}

// t059DialWorker drives one target's retry loop until the per-conn window
// closes, delivering the first successful conn (held open by the caller)
// or the last error. Retries absorb the post-bootstrap transience T033
// observed (REP=1 while descriptors/warmup settle) and the token-push
// latency of the seeded CP generation (auth-fail replies retry too).
func t059DialWorker(ctx context.Context, start <-chan struct{}, idx int, onion string, port int, token string, results chan<- t059DialResult) {
	<-start
	deadline := time.Now().Add(t059ConnectWait)
	var lastErr error
	for {
		if ctx.Err() != nil {
			results <- t059DialResult{idx: idx, err: fmt.Errorf("suite context expired: %w (last error: %v)", ctx.Err(), lastErr)}
			return
		}
		conn, err := t059ConnectThroughDP(ctx, onion, port, token)
		if err == nil {
			results <- t059DialResult{idx: idx, conn: conn}
			return
		}
		lastErr = err
		if time.Now().After(deadline) {
			results <- t059DialResult{idx: idx, err: lastErr}
			return
		}
		time.Sleep(t059StreamPoll)
	}
}

// t059ConnectThroughDP issues one SOCKS5 CONNECT through the DP's loopback
// port 8881: UNAME = the target's complete `sg1:` partition
// (foundation-boundaries.md; FR-002), PASSWD = the bearer token
// (contracts/socks5-auth.md). x/net's dialer sends ATYP=0x03 DOMAIN for a
// non-IP host — SOCKS5h, no local resolution (FR-007) — and the returned
// conn is the established tunnel: no HTTP/TLS is spoken (page load is
// T033's assertion; this test only needs the stream attached and held).
func t059ConnectThroughDP(ctx context.Context, onion string, port int, token string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", t059DPAddr, &proxy.Auth{
		// Partition — the isolation credential the DP forwards upstream.
		User:     t126PartitionUsername(token, t059ProfileID, onion),
		Password: token, // bearer token — what the DP validates; never re-sent upstream
	}, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dialer: %w", err)
	}
	dCtx, cancel := context.WithTimeout(ctx, t059ConnectWait)
	defer cancel()
	return dialer.(proxy.ContextDialer).DialContext(dCtx, "tcp", t059Target(onion, port))
}

// t059WaitStreamCircuit polls the control port until exactly one live
// (non-terminal) stream matches target and returns its circuit ID. It
// fails at the deadline rather than skipping: a count that never lands is
// either a broken assertion environment or the property failing, and both
// must be loud (T058a's ulWaitStreams discipline).
func t059WaitStreamCircuit(t *testing.T, ctx context.Context, composeFile, envFile, target string) string {
	t.Helper()
	deadline := time.Now().Add(t059StreamWait)
	var last string
	for {
		raw, err := t059ControlProbe(ctx, composeFile, envFile, "GETINFO stream-status")
		if err != nil {
			t.Fatalf("stream-status probe for %s: %v (last reply: %q)", target, err, strings.TrimSpace(raw))
		}
		circIDs, states := t059ParseStreams(raw, target)
		if len(circIDs) == 1 {
			return circIDs[0]
		}
		last = fmt.Sprintf("%d live stream(s), states=%v", len(circIDs), states)
		if time.Now().After(deadline) {
			t.Fatalf("expected exactly 1 live stream for %s within %s; saw %s (raw: %q)",
				target, t059StreamWait, last, strings.TrimSpace(raw))
		}
		time.Sleep(t059StreamPoll)
	}
}

// t059ParseStreams extracts the circuit IDs (and states, for diagnostics)
// of live streams whose target matches, from the raw control-port reply.
// Tor renders GETINFO stream-status in two live-captured shapes:
//
//	250-stream-status=59 SUCCEEDED 13 <addr>:80        (single stream)
//	250+stream-status=\n59 SUCCEEDED 13 <addr>:80\n60 …\n.\n250 OK
//	                                                   (multi-stream block)
//
// so every line is prefix-stripped and field-checked rather than
// position-indexed: the 4-field shape <StreamID> <Status> <CircID>
// <Target> is matched by target string and terminal-state, never by
// StreamID ordering (T058a parity).
func t059ParseStreams(raw, target string) (circIDs, states []string) {
	inBlock := false
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.HasPrefix(ln, "250+stream-status=") {
			inBlock = true
			ln = strings.TrimPrefix(ln, "250+stream-status=")
		} else if strings.HasPrefix(ln, "250-stream-status=") {
			ln = strings.TrimPrefix(ln, "250-stream-status=")
		} else if inBlock {
			if ln == "." {
				inBlock = false
			}
			if ln == "." || ln == "" || strings.HasPrefix(ln, "250 ") {
				continue
			}
		} else if ln == "" || strings.HasPrefix(ln, "250 ") {
			continue
		}
		fields := strings.Fields(ln)
		if len(fields) < 4 || fields[3] != target || t059TerminalStreamStates[fields[1]] {
			continue
		}
		circIDs = append(circIDs, fields[2])
		states = append(states, fields[1])
	}
	return circIDs, states
}

// t059AssertCircuitBuilt cross-checks that a stream's circuit exists with
// status BUILT in GETINFO circuit-status — tor's circuit-level surface
// must agree with its stream-level one (T058a's ulCircuitBuilt parity;
// guards against misparsing stream-status or a dangling circuit).
func t059AssertCircuitBuilt(t *testing.T, ctx context.Context, composeFile, envFile, circID string) {
	t.Helper()
	raw, err := t059ControlProbe(ctx, composeFile, envFile, "GETINFO circuit-status")
	if err != nil {
		t.Fatalf("circuit-status probe: %v", err)
	}
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.HasPrefix(ln, circID+" ") && strings.Contains(ln, " BUILT ") {
			return
		}
	}
	t.Errorf("circuit %s not found BUILT in GETINFO circuit-status — "+
		"stream-status and circuit-status disagree (parsing bug or tor surface change)", circID)
}

// t059Compose runs a docker compose subcommand under the test's project
// name and returns combined output (T033's runner shape with this suite's
// project baked in — each suite owns its project const so its exec
// transports and up/down never split across projects, the split T058a
// found live; a future hoist is T121).
func t059Compose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{
		"compose", "-p", t059Project,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	return exec.CommandContext(ctx, "docker", full...).CombinedOutput()
}

// t059FindRepoRoot walks up from this test file's source location to find
// the directory containing compose/docker-compose.local.yml. Does NOT rely
// on the working directory — `go test` may be invoked from any cwd
// (T033's rationale; mirrored so this file stays self-contained for the
// parallel T060/T061 sibling sessions).
func t059FindRepoRoot(t *testing.T) string {
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

// t059CountSuffix counts files with the given suffix under root
// (depth-unlimited) — the content-gate helper (T033's shape).
func t059CountSuffix(root, suffix string) int {
	count := 0
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, suffix) {
			count++
		}
		return nil
	})
	return count
}
