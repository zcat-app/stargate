// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// Hermetic tests of TestOnionLoad's gate logic (T208 acceptance 7). The
// live test needs the Tor network; what it decides with the answers does
// not. These tests drive t033Gate with scripted effects and a fake clock:
//
//   - the timed retry window opens only when token delivery reads
//     ACKNOWLEDGED (`scripts/stargate status` exit 0), so control-plane
//     start-up no longer consumes the window meant for Tor;
//   - expiry of the delivery allowance, and every status exit that is not a
//     "not yet" state, fail loudly and name token delivery;
//   - the control onion's result is logged and never changes the verdict:
//     the pass condition stays the reference onion (spec.md User Story 1).
//
// No Docker, network or sleep is involved; the status runner test uses a
// stub `docker` on PATH.

// t033GateDeliveryWait is the delivery allowance these tests script
// against; the gate takes it as a parameter.
const t033GateDeliveryWait = 5 * time.Minute

var errT033HostUnreachable = errors.New("socks connect tcp 127.0.0.1:8881->reference:443: unknown error host unreachable")

// t033Script is a scripted gate: a fake clock, an event log, and the three
// effects. Every effect advances the clock by its scripted duration, so
// the gate's time arithmetic is exercised without waiting.
type t033Script struct {
	clock  time.Time
	events []string
	logs   []string

	statusExits []int           // one per call; the last repeats
	statusLeft  []time.Duration // per call: real time left on the call's context; -1 when unbounded
	statusErr   error
	statusTook  time.Duration

	loadErrs []error // one per call; the last repeats
	loadTook []time.Duration

	controlErr error
}

func (s *t033Script) gate() t033Gate {
	return t033Gate{
		deliveryStatus: func(ctx context.Context) (int, string, error) {
			left := time.Duration(-1)
			if dl, ok := ctx.Deadline(); ok {
				left = time.Until(dl)
			}
			s.statusLeft = append(s.statusLeft, left)
			n := s.count("status")
			s.events = append(s.events, "status")
			s.clock = s.clock.Add(s.statusTook)
			if s.statusErr != nil {
				return 0, "", s.statusErr
			}
			exit := s.statusExits[min(n, len(s.statusExits)-1)]
			return exit, fmt.Sprintf("scripted exit %d", exit), nil
		},
		loadReference: func(context.Context) ([]byte, error) {
			n := s.count("load")
			s.events = append(s.events, "load")
			s.clock = s.clock.Add(s.loadTook[min(n, len(s.loadTook)-1)])
			if err := s.loadErrs[min(n, len(s.loadErrs)-1)]; err != nil {
				return nil, err
			}
			return []byte("page"), nil
		},
		loadControl: func(context.Context) error {
			s.events = append(s.events, "control")
			return s.controlErr
		},
		now:          func() time.Time { return s.clock },
		sleep:        func(d time.Duration) { s.clock = s.clock.Add(d) },
		logf:         func(format string, args ...any) { s.logs = append(s.logs, fmt.Sprintf(format, args...)) },
		deliveryWait: t033GateDeliveryWait,
		window:       t033ReqWait,
		poll:         t033PollEvery,
	}
}

func (s *t033Script) count(event string) int {
	n := 0
	for _, e := range s.events {
		if e == event {
			n++
		}
	}
	return n
}

func t033NewScript() *t033Script {
	return &t033Script{
		clock:       time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
		statusExits: []int{0},
		statusTook:  2 * time.Second,
		loadErrs:    []error{nil},
		loadTook:    []time.Duration{3 * time.Second},
	}
}

// The window does not open before ACKNOWLEDGED, and it is measured from
// the acknowledgement: 150 s of delivery wait (longer than the whole
// pre-T208 window) followed by three attempts that Tor fails at 120 s each
// still leaves room for a fourth attempt, which succeeds.
func TestT033GateWindowOpensOnlyAfterAcknowledged(t *testing.T) {
	s := t033NewScript()
	s.statusExits = []int{50, 30, 20, 70, 30, 30, 0} // UNKNOWN, PENDING, unavailable, timeout: not yet
	s.statusTook = 20 * time.Second
	s.loadErrs = []error{errT033HostUnreachable, errT033HostUnreachable, errT033HostUnreachable, nil}
	s.loadTook = []time.Duration{120 * time.Second}

	body, err := s.gate().run(context.Background())

	firstLoad := -1
	for i, e := range s.events {
		if e == "load" {
			firstLoad = i
			break
		}
	}
	if got := s.count("status"); got != len(s.statusExits) {
		t.Errorf("status consulted %d times, want %d (until exit 0)", got, len(s.statusExits))
	}
	if firstLoad != len(s.statusExits) {
		t.Errorf("first reference load is event %d of %v; want it only after all %d status calls (the last one ACKNOWLEDGED)",
			firstLoad, s.events, len(s.statusExits))
	}
	if err != nil || string(body) != "page" {
		t.Fatalf("run = (%q, %v); want the page from the fourth attempt: the 390 s window must start at ACKNOWLEDGED, "+
			"not at bootstrap, and fit three attempts Tor fails at 120 s", body, err)
	}
	if got := s.count("load"); got != 4 {
		t.Errorf("reference attempts = %d, want 4", got)
	}
}

// Expiry of the delivery allowance fails loudly, names token delivery and
// never starts the reference load or the control.
func TestT033GateDeliveryAllowanceExpiryFails(t *testing.T) {
	s := t033NewScript()
	s.statusExits = []int{30} // PENDING forever
	start := s.clock

	body, err := s.gate().run(context.Background())

	if err == nil || body != nil {
		t.Fatalf("run = (%q, %v); want an error when delivery never reads ACKNOWLEDGED", body, err)
	}
	if !strings.Contains(err.Error(), "token delivery") {
		t.Errorf("error %q does not name token delivery", err)
	}
	if n := s.count("load") + s.count("control"); n != 0 {
		t.Errorf("%d loads ran although delivery was never acknowledged: %v", n, s.events)
	}
	waited := s.clock.Sub(start)
	if waited < t033GateDeliveryWait || waited > t033GateDeliveryWait+s.statusTook+t033PollEvery {
		t.Errorf("gave up after %s; want the %s allowance (bounded, at most one poll over)", waited, t033GateDeliveryWait)
	}
}

// An acknowledgement that arrives after the allowance has expired does not
// open the window (review round 1): seven not-yet answers and then exit 0,
// each status call taking 37 s, put the acknowledgement at 331 s against the
// 300 s allowance. The positive control is
// TestT033GateWindowOpensOnlyAfterAcknowledged, where it arrives in time.
func TestT033GateRejectsLateAcknowledgement(t *testing.T) {
	s := t033NewScript()
	s.statusExits = []int{30, 30, 30, 30, 30, 30, 30, 0}
	s.statusTook = 37 * time.Second

	body, err := s.gate().run(context.Background())

	if err == nil || body != nil {
		t.Fatalf("run = (%q, %v); an acknowledgement observed after the %s allowance must fail the gate", body, err, t033GateDeliveryWait)
	}
	if !strings.Contains(err.Error(), "token delivery") {
		t.Errorf("error %q does not name token delivery", err)
	}
	if n := s.count("load") + s.count("control"); n != 0 {
		t.Errorf("%d loads ran after a late acknowledgement: %v", n, s.events)
	}
}

// Each status call is bounded by what is left of the allowance, so a call
// that hangs cannot carry the wait past it, and no call starts once the
// allowance is spent.
func TestT033GateStatusCallsAreBoundedByTheRemainingAllowance(t *testing.T) {
	s := t033NewScript()
	s.statusExits = []int{30}
	s.statusTook = 55 * time.Second
	start := s.clock

	if _, err := s.gate().run(context.Background()); err == nil {
		t.Fatal("run passed although delivery never read ACKNOWLEDGED")
	}
	if waited := s.clock.Sub(start); waited != t033GateDeliveryWait {
		t.Errorf("gave up after %s, want exactly the %s allowance: the last pause is cut to what is left and no call starts after it", waited, t033GateDeliveryWait)
	}
	for i, left := range s.statusLeft {
		// Call i starts after i calls and i pauses on the fake clock.
		remaining := t033GateDeliveryWait - time.Duration(i)*(s.statusTook+t033PollEvery)
		if left < 0 || left > remaining {
			t.Errorf("status call %d: context bound %s, want a bound of at most the remaining allowance %s", i+1, left, remaining)
		}
	}
}

// Every status exit other than 0 (ACKNOWLEDGED) and the four not-yet exits
// fails at once and names token delivery: 10 preflight, 40 STALE_CONFLICT,
// 60 unrecognised, 2 usage, and anything unexpected. So does a status
// command that could not run.
func TestT033GateFailingStatusExitsFailLoudly(t *testing.T) {
	for _, exit := range []int{10, 40, 60, 2, 1, 124, 137, -1} {
		t.Run(fmt.Sprintf("exit_%d", exit), func(t *testing.T) {
			s := t033NewScript()
			s.statusExits = []int{30, exit, 0}
			body, err := s.gate().run(context.Background())
			if err == nil || body != nil {
				t.Fatalf("run = (%q, %v); want a failure on status exit %d", body, err, exit)
			}
			if !strings.Contains(err.Error(), "token delivery") {
				t.Errorf("error %q does not name token delivery", err)
			}
			if got := s.count("status"); got != 2 {
				t.Errorf("status consulted %d times, want 2 (stop at the failing exit)", got)
			}
			if n := s.count("load") + s.count("control"); n != 0 {
				t.Errorf("%d loads ran after failing status exit %d: %v", n, exit, s.events)
			}
		})
	}
	t.Run("status_cannot_run", func(t *testing.T) {
		s := t033NewScript()
		s.statusErr = errors.New("exec: bash: not found")
		body, err := s.gate().run(context.Background())
		if err == nil || body != nil || !strings.Contains(err.Error(), "token delivery") {
			t.Fatalf("run = (%q, %v); want a failure naming token delivery", body, err)
		}
		if n := s.count("load") + s.count("control"); n != 0 {
			t.Errorf("%d loads ran although status could not run: %v", n, s.events)
		}
	})
}

// The control onion is loaded exactly once, after the reference verdict is
// known, and its result never changes that verdict in either direction.
func TestT033GateControlNeverChangesTheVerdict(t *testing.T) {
	t.Run("reference_fails_control_succeeds", func(t *testing.T) {
		s := t033NewScript()
		s.loadErrs = []error{errT033HostUnreachable}
		s.loadTook = []time.Duration{120 * time.Second}
		s.controlErr = nil

		body, err := s.gate().run(context.Background())

		if err == nil || body != nil {
			t.Fatalf("run = (%q, %v); a reachable control must not turn a reference-onion failure into a pass", body, err)
		}
		if got := s.count("control"); got != 1 {
			t.Fatalf("control loaded %d times, want exactly 1: %v", got, s.events)
		}
		if last := s.events[len(s.events)-1]; last != "control" {
			t.Errorf("control ran before the reference verdict was known: %v", s.events)
		}
	})
	t.Run("reference_succeeds_control_fails", func(t *testing.T) {
		s := t033NewScript()
		s.controlErr = errT033HostUnreachable

		body, err := s.gate().run(context.Background())

		if err != nil || string(body) != "page" {
			t.Fatalf("run = (%q, %v); the pass condition is the reference onion alone", body, err)
		}
		if got := s.count("control"); got != 1 || s.events[len(s.events)-1] != "control" {
			t.Errorf("control must run exactly once, after the verdict: %v", s.events)
		}
	})
}

// Characterization (unchanged by T208): an attempt already running when
// the window closes is allowed to finish and can pass the test; no attempt
// starts after the window has closed.
func TestT033GateAttemptRunningAtWindowCloseFinishes(t *testing.T) {
	s := t033NewScript()
	s.loadErrs = []error{errT033HostUnreachable, nil, nil}
	s.loadTook = []time.Duration{t033ReqWait - 10*time.Second, 300 * time.Second}
	if body, err := s.gate().run(context.Background()); err != nil || string(body) != "page" {
		t.Fatalf("run = (%q, %v); the attempt started 5 s before the window closed must be allowed to finish", body, err)
	}

	s = t033NewScript()
	s.loadErrs = []error{errT033HostUnreachable}
	s.loadTook = []time.Duration{t033ReqWait}
	if _, err := s.gate().run(context.Background()); err == nil {
		t.Fatal("run passed although its only attempt failed")
	}
	if got := s.count("load"); got != 1 {
		t.Errorf("%d attempts; none may start once the window has closed", got)
	}
}

// The time budget the live gate runs with (T208 acceptance 6b). The
// contract value is mirrored here as a literal because tests/integration
// cannot import the data plane's internal constant; the data plane's own
// TestProductionDialDeadlineIsContractValue pins that side.
func TestT033TimeBudgetMatchesTheContractDeadline(t *testing.T) {
	const contractDeadline = 250 * time.Second // contracts/socks5-auth.md §Deadlines row 1
	const socksTimeout = 120 * time.Second     // Tor's default; torrc.md invariant 14 keeps it unset
	if t033ReqDead <= contractDeadline {
		t.Errorf("per-attempt client timeout %s does not exceed the data plane's %s deadline: an attempt would end "+
			"with the client's timeout instead of the data plane's reply class", t033ReqDead, contractDeadline)
	}
	if t033ReqWait != 390*time.Second {
		t.Errorf("retry window = %s, want 390s", t033ReqWait)
	}
	if need := 3*socksTimeout + 2*t033PollEvery; t033ReqWait <= need {
		t.Errorf("retry window %s does not fit three attempts Tor fails at %s (needs more than %s)", t033ReqWait, socksTimeout, need)
	}
}

// t033ReplyClass labels an attempt's outcome from the error the real
// SOCKS5 client returns, so the live record can tell Tor's failure reply
// (0x04) from the data plane's own deadline (0x06) and from an
// unreachable sidecar (0x03). Driven with real client bytes against a
// scripted SOCKS5 server, so a dependency change in the error text fails
// here and not in a live run's classification.
func TestT033ReplyClassFromRealClientErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		authFail bool
		rep      byte
		want     string
	}{
		{"auth_denied", true, 0x00, "auth-denied"},
		{"rep_03", false, 0x03, "0x03"},
		{"rep_04", false, 0x04, "0x04"},
		{"rep_06", false, 0x06, "0x06"},
		{"rep_01", false, 0x01, "socks-reply-other"},
		{"rep_05", false, 0x05, "socks-reply-other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := t033ScriptedSOCKS5(t, tc.authFail, tc.rep)
			dialer, err := proxy.SOCKS5("tcp", addr, &proxy.Auth{User: "partition", Password: "bearer"}, proxy.Direct)
			if err != nil {
				t.Fatalf("SOCKS5 dialer: %v", err)
			}
			_, err = dialer.Dial("tcp", "unresolvable.invalid:443")
			if err == nil {
				t.Fatal("dial succeeded against a failing scripted server")
			}
			if got := t033ReplyClass(fmt.Errorf("GET: %w", err)); got != tc.want {
				t.Errorf("t033ReplyClass(%q) = %q, want %q", err, got, tc.want)
			}
		})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closed := ln.Addr().String()
	ln.Close()
	dialer, _ := proxy.SOCKS5("tcp", closed, nil, proxy.Direct)
	_, err = dialer.Dial("tcp", "unresolvable.invalid:443")
	if got := t033ReplyClass(err); got != "listener-unreachable" {
		t.Errorf("t033ReplyClass(%q) = %q, want listener-unreachable", err, got)
	}
	for err, want := range map[error]string{
		nil:                                 "ok",
		context.DeadlineExceeded:            "client-timeout",
		errors.New("tls: bad record"):       "other",
		errors.New("status 503 (want 200)"): "other",
	} {
		if got := t033ReplyClass(err); got != want {
			t.Errorf("t033ReplyClass(%v) = %q, want %q", err, got, want)
		}
	}
}

// t033ScriptedSOCKS5 serves one SOCKS5 username/password session that
// either rejects the credentials or answers the request with rep.
func t033ScriptedSOCKS5(t *testing.T, authFail bool, rep byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
			return
		}
		_, _ = c.Write([]byte{0x05, 0x02})
		if _, err := io.ReadFull(c, hdr); err != nil { // VER, ULEN
			return
		}
		unamePlen := make([]byte, int(hdr[1])+1) // UNAME, PLEN
		if _, err := io.ReadFull(c, unamePlen); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, unamePlen[len(unamePlen)-1])); err != nil { // PASSWD
			return
		}
		if authFail {
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		_, _ = c.Write([]byte{0x01, 0x00})
		req := make([]byte, 5)
		if _, err := io.ReadFull(c, req); err != nil { // VER CMD RSV ATYP LEN
			return
		}
		if _, err := io.ReadFull(c, make([]byte, int(req[4])+2)); err != nil {
			return
		}
		_, _ = c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()
	return ln.Addr().String()
}

// t033DeliveryStatus runs the real `scripts/stargate status` addressed to
// the test's own project and returns its exit code. Driven here against a
// stub `docker` so the exit codes, the project addressing and the
// "nothing is created in the checkout" property are checked without a
// daemon.
func TestT033DeliveryStatusRunsStargateStatusForItsOwnProject(t *testing.T) {
	repoRoot := t033FindRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	defaultEnv := filepath.Join(repoRoot, "compose", "env", "local.env")
	_, statErr := os.Stat(defaultEnv)
	defaultEnvExisted := statErr == nil

	stubDir := t.TempDir()
	logPath := filepath.Join(stubDir, "docker.log")
	statePath := filepath.Join(stubDir, "state")
	stub := `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$T033_STUB_LOG"
case "$*" in
  "compose version"|"info") exit 0 ;;
  *" ps -q --status running stargate-control") echo container-id; exit 0 ;;
  *" exec -T stargate-control "*) cat "$T033_STUB_STATE"; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(filepath.Join(stubDir, "docker"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write docker stub: %v", err)
	}
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("T033_STUB_LOG", logPath)
	t.Setenv("T033_STUB_STATE", statePath)
	// An operator's shell may carry these; the runner must override them.
	t.Setenv("STARGATE_PROJECT", "some-other-project")
	t.Setenv("STARGATE_ENV_FILE", filepath.Join(stubDir, "must-not-be-used.env"))

	for _, tc := range []struct {
		content  string
		wantExit int
		wantText string
	}{
		{"ACKNOWLEDGED(7)\n", 0, "ACKNOWLEDGED(7)"},
		{"PENDING\n", 30, "PENDING"},
		{"ABSENT\n", 50, "UNKNOWN"},
		{"STALE_CONFLICT\n", 40, "STALE_CONFLICT"},
		{"garbage\n", 60, "unrecognised"},
	} {
		if err := os.WriteFile(statePath, []byte(tc.content), 0o600); err != nil {
			t.Fatalf("write state: %v", err)
		}
		exit, state, err := t033DeliveryStatus(context.Background(), repoRoot, composeFile, envFile)
		if err != nil {
			t.Fatalf("t033DeliveryStatus(%q): %v", tc.content, err)
		}
		if exit != tc.wantExit || !strings.Contains(state, tc.wantText) {
			t.Errorf("state file %q: exit %d, state %q; want exit %d and state containing %q",
				tc.content, exit, state, tc.wantExit, tc.wantText)
		}
	}

	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read docker stub log: %v", err)
	}
	addressed := "compose -p " + t033Project + " -f " + composeFile + " --env-file " + envFile + " "
	for _, line := range strings.Split(strings.TrimSpace(string(logged)), "\n") {
		if line == "compose version" || line == "info" {
			continue
		}
		if !strings.HasPrefix(line, addressed) {
			t.Errorf("docker call %q is not addressed to the test's own project (%q)", line, addressed)
		}
	}
	if !strings.Contains(string(logged), addressed+"exec -T stargate-control ") {
		t.Errorf("no status read reached the stub; calls:\n%s", logged)
	}
	if _, err := os.Stat(defaultEnv); err == nil && !defaultEnvExisted {
		t.Errorf("the status call created %s in the checkout", defaultEnv)
	}
	if _, err := os.Stat(filepath.Join(stubDir, "must-not-be-used.env")); err == nil {
		t.Error("the status call used the inherited STARGATE_ENV_FILE instead of the test's env file")
	}
}
