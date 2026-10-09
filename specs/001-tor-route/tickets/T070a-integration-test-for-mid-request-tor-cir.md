---
id: T070a
title: 'Prove Tor circuit drop closes an in-flight SOCKS tunnel'
status: done
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T070a
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156"]
parallel: true
files_budget: 6
files_scope:
  - data-plane/internal/forward/tor_test.go
  - tests/integration/circuit_drop_midstream_test.go
  - tests/contract/tor/control_port.go
  - tests/contract/tor/control_port_test.go
  - specs/001-tor-route/tickets/T070a-integration-test-for-mid-request-tor-cir.md
  - specs/001-tor-route/STATUS.md
out_of_scope:
  - data-plane/** production sources
  - 'tests/contract/** except tests/contract/tor/control_port.go and tests/contract/tor/control_port_test.go'
  - compose/**
  - control-plane/**
  - SECURITY-DECISIONS.md
privacy_critical: true
tests_first: [] # same-ticket red-first regression: tests/contract/tor/control_port_test.go::TestControlPortPostFlushHook
constitution_refs:
  - "I: Dumb Router"
  - "III: Privacy-Preserving by Construction"
  - "VII: Tests-first for privacy-critical paths"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md §"Edge Cases" — Tor circuit failure mid-request'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"Deadlines"'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"'
decision_refs: []
reviews: { round: 7, date: 2026-10-09, verdict: APPROVE, findings: "Astra and Luna approved the exact staged candidate; no findings." }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T070a: Prove Tor circuit drop closes an in-flight SOCKS tunnel

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Integration test for mid-request Tor circuit drop (Principle I no-retry + Principle III no-upstream-derived-leak; spec §"Edge Cases" — *Tor circuit failure mid-request*) — bring up the local-profile stack; using the cookie-authenticated control-port helper from T062, open an authenticated CONNECT through port 8881 to a known-reachable `.onion`, begin a slow read so the stream stays in-flight, then issue `CLOSECIRCUIT <id>` on the control port to kill *that specific circuit* (not the whole sidecar); capture every byte written to the browser side until the browser-side socket finishes closing; assert (a) after the data plane observes EOF (or RST) on the upstream SOCKS5 stream, zero new bytes are written to the browser side — the data plane MUST NOT synthesise an error template, status line, or reason text at this layer (in-flight bytes Tor delivered before the close are passed through verbatim and are tested only against the leak-corpus scan in assertion (d)); (b) the browser-side socket is closed by the data plane (TCP close, not a rendered HTTP response — the post-CONNECT byte pipe has no framing context for one); (c) the data plane issues no retry to the Tor sidecar (verified by control-port `circuit-status` showing no new circuit for the same SOCKS5 username within a bounded watch window); (d) leak-corpus scan over the captured bytes returns zero matches; (e) the T025a shared log allowlist applies to the data plane's output during the run — in `tests/integration/circuit_drop_midstream_test.go`. Run before each release tag, not on every PR (real-Tor reachability + control-port timing make this unsuitable as a per-PR gate; same cadence as T034a).

## Analysis

- **Must hold:** after SOCKS5 admission and the zeroed success reply, forwarding remains an
  opaque byte pipe. An upstream EOF/RST ends the client tunnel without a SOCKS failure reply,
  error template, replay, or automatic circuit retry. The complete partition username reaches
  Tor, and the test kills only the circuit carrying the exact stream. Stargate DP diagnostics
  remain empty under the Local profile's disabled Docker log driver.
- **Gated:** the deterministic test drives production `listener.HandleConn` and `forward.Tor`
  against a local SOCKS server that returns one fixed opaque payload then closes. Exact
  post-success byte equality proves no appended failure bytes; accepted-connection count pins
  the one upstream attempt. The live test uses T070's bounded authenticated SOCKS positive
  control to confirm token delivery after cold start, then uses a distinct full-profile username
  for the attributed stream; it pins attribution and closure through the deployed stack. Focused
  Go commands are recorded in the handoff; this task intentionally does not run
  the repository-wide verify gate under its approved execution scope.
- **Residue:** Tor control status can establish that the exact complete username was attached
  to a BUILT circuit. After raw EOF/RST, the selected stream may be absent from the current
  stream-status view; if present it must be CLOSED/FAILED, not DETACHED or reassigned to another
  nonzero circuit. Circuit polling can show that no replacement circuit ID appeared in sampled
  circuit-status snapshots over 10 seconds; it cannot rule out a short-lived circuit between
  polls or retries outside Tor's published circuit surface.
  TLS ciphertext cannot prove absence of synthesized application text, so that byte property is
  proven in the deterministic lane. Empty attached logs plus `LogConfig.Type=none` establish
  observed-output and retention evidence, not the absence of invisible channels. Neither lane
  proves exact internal ordering between upstream EOF and a client write; the acceptance claim
  stays at observable byte and close behavior.

## Acceptance

1. `TestT070aCircuitDropMidstream` in `tests/integration/circuit_drop_midstream_test.go` is
   Docker/Linux tagged and requires `STARGATE_RUN_NETWORK_TESTS=1`. Against the fresh Local
   stack and the spec-pinned onion, it first confirms token delivery with the bounded T070
   authenticated SOCKS positive control, then opens TLS over an authenticated SOCKS5 CONNECT with one
   full `sg1:` username; sends incomplete HTTP request headers; and fails calibration if any
   plaintext response or prior close occurs. Before killing anything, it maps exactly one
   nonterminal target stream to its circuit, verifies that circuit is BUILT and carries the
   exact username, and confirms the TLS read is still pending. The read has no deadline while
   attribution and pre-close setup run. Immediately before `CLOSECIRCUIT`, it takes a fresh
   exact-username circuit-status snapshot, requires the selected circuit to remain BUILT, and
   checks again that the read is pending. The control helper records a timestamp immediately
   after successfully flushing CLOSECIRCUIT to the local Docker-exec stdin pipe; this proves
   local pipe flush, not receipt by Tor or causation. At that hook it starts the bounded read
   deadline; a read completed before the timestamp fails. Only EOF, unexpected EOF, connection
   reset, or connection aborted count as a client close; any timeout fails. Every Tor control
   command in attribution, close, post-close status, and the replacement
   watch is bounded by its phase deadline; a command result at or after the deadline fails even
   if cancellation cleanup later completes. The helper waits for synchronous ControlPort
   cancellation cleanup before returning, which can add its existing 5.25-second teardown bound
   to test return time without extending the observation window. The authenticated control session
   prepared for the immediate pre-close snapshot remains the single owner through CLOSECIRCUIT,
   post-close stream status, and the complete 10-second circuit observation; it is closed and
   checked afterward. Its lifecycle deadline covers the sequential phase caps, while each command
   retains its shorter phase deadline.
2. The live test requires the TLS read to unblock and then independently drains the underlying
   client TCP socket to EOF/RST before cleanup. The selected stream must be absent from current
   stream-status or be CLOSED/FAILED, and must not be DETACHED or reassigned to another nonzero
   circuit. Across 10 seconds, no replacement circuit ID appeared in sampled circuit-status
   snapshots beyond the immediately pre-close username-tagged baseline. It requires Docker
   `LogConfig.Type=none`, a successful reader attach that stays alive, bounded empty captured
   output, and the shared `loginvariants.AssertOnlyAllowedLines` check. Any TLS ciphertext is
   treated as opaque; the live lane makes no ciphertext leak-corpus claim.
3. `TestCircuitDropMidstreamClosesWithoutSynthesizedBytes` in
   `data-plane/internal/forward/tor_test.go` drives production `listener.HandleConn` plus
   `forward.Tor` against one controllable local SOCKS server. It requires the exact SOCKS
   success reply, the server's fixed opaque payload and no more bytes through client EOF/RST,
   and exactly one upstream TCP accept.
4. Run the focused Go checks only: from `data-plane/`,
   `go test -race ./internal/forward -run '^TestCircuitDropMidstreamClosesWithoutSynthesizedBytes$'`;
   from `tests/`, `go test ./contract/tor` exercises the post-flush hook contract;
   from `tests/integration/`,
   `go test -tags docker -run '^TestT070aDeadlineAndCloseEvidence$' .` covers read/flush
   correlation, timeout rejection, and late control results, and
   `go test -tags docker -run '^TestT070aCircuitDropMidstream$' .`
   compiles the live selector (which skips unless opted in). One live acceptance invocation uses
   the reviewed host runner. This is release-tag cadence, not a PR gate. No Java or full-suite
   run is in scope.

## Out-of-scope

This ticket adds only the deterministic forwarding regression and the live release-cadence
test, then stages its executable evidence. It does not change forwarding code, Tor policy,
HTTP refusal, other routes, generic retry behavior, TLS contents, CI cadence, or the host's
network boundary. The live result is specific to this Local topology, onion, Tor's exposed
control status, and the bounded observation window; it does not prove global retry absence or
hidden logging channels.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

Candidate evidence (2026-10-09): the focused forward race test passed and the exact Docker/Linux
integration selector compiled and skipped because the network-test opt-in was unset; focused
helper tests cover read/flush correlation, timeout rejection, and late control-result rejection.
The first
host-root run failed at the Local init loopback verification because the helper container did not
share host networking; its runner restored baseline. A host-network run then reached the test
but exposed the CP token-delivery cold-start race before the custom SOCKS CONNECT; its runner
also restored baseline. A third run passed those setup checks and the client EOF/RST assertion,
then failed because its post-drain stream-status poll did not find an explicit terminal row; its
runner also restored baseline. Each run removed only its own project and returned IPv4/IPv6
OUTPUT and AppArmor to baseline. T070a now treats absence from current stream-status after the
pre-close stream proof and raw EOF/RST as termination; if a row remains, only CLOSED/FAILED with
no reassignment passes. Its circuit claim is limited to sampled circuit-status snapshots. The
corrected host-network invocation passed: stream 65 was attributed to its BUILT partition
circuit, the TLS read and raw socket reached close, no replacement circuit ID appeared in the
sampled circuit-status snapshots over 10 seconds, and attached DP output was empty. The runner
removed only project `stargate-t070-live-1791579193-7` and verified IPv4/IPv6 OUTPUT plus
AppArmor returned to baseline. The TLS capture contained 7,887 opaque bytes; it was not scanned
as application plaintext.

Round-3 independent reviews identified that recording a timestamp before the blocking control
write/flush allowed a TLS read timeout to be misattributed to CLOSECIRCUIT. The accepted correction
adds an after-flush hook to the control helper. Its timestamp establishes only that the command
bytes were flushed to the local Docker-exec stdin pipe; it cannot establish Tor receipt or
causation. Test-first red evidence: `go test ./contract/tor -run
'^TestControlPortPostFlushHook$' -count=1` exited 1 with
`ControlPort does not implement CommandContextAfterFlush`; the test compiled and failed at its
runtime interface assertion, as intended. After the additive hook and focused cases landed,
`go test ./contract/tor -count=1`, the forward race selector, the T070a deadline/evidence helper,
and the exact Docker/Linux T070a selector all passed; the live selector skipped because its opt-in
was unset. The helper hook is synchronous and non-reentrant; its evidence boundary is only the
successful flush into the local Docker-exec stdin pipe.
Deadline operations run synchronously in their owner: the observation fails when work returns
at or after its phase deadline, after ControlPort's existing bounded cancellation cleanup has
finished. The pre-opened close session uses a bounded lifecycle context spanning setup, the
pre-close snapshot, close, client drain, post-close stream status, and the circuit observation; if
Connect returns after its preparation deadline, the session is closed synchronously before
failure. No deferred Close overlaps a command operation.

The reviewed final candidate's first correctly wrapped live attempt passed Local init, the
authenticated positive control, exact stream/circuit attribution, CLOSECIRCUIT, client TLS
unblock, raw TCP EOF/RST, and post-close stream status. It then failed during the 10-second
circuit-status observation when one snapshot command did not complete within the observation
deadline. The test intentionally reports a fixed category, so the evidence does not distinguish a
slow Tor reply from repeated cookie-read, Docker-exec, authentication, and session-teardown setup
costs; repeated per-snapshot setup is the likely cause, not an established diagnosis. The runner
removed only project `stargate-t070-live-1791582567-7` and confirmed IPv4/IPv6 OUTPUT and AppArmor
returned to baseline. The correction keeps one authenticated ControlPort session for the immediate
pre-close snapshot through the final observation sample, preserves the same absolute 10-second
window and all per-command deadlines, and adds focused coverage for repeated samples, late results,
query errors, and new circuit IDs.

After that correction, the exact reviewed candidate passed the one live selector through the same
host runner. It observed stream 69 on its BUILT partition circuit, the TLS read and raw socket
closed, no new exact-username circuit ID appeared in the sampled 10-second window, the attached DP
output was empty, and the TLS capture remained opaque (7,887 bytes). Cleanup removed only project
`stargate-t070-live-1791583334-6` and verified the IPv4/IPv6 OUTPUT and AppArmor baseline restored.

## T172 selected acceptance refinement

T172 selects an authenticated SOCKS5 CONNECT carrying the complete partition username, closure
of the identified Tor circuit, and no automatic retry. T070a provides evidence at two observable
boundaries: the deterministic test proves exact byte equality after the SOCKS success reply
through client EOF/RST; the live test establishes stream attribution before the kill, a pending
TLS read, the resulting client close, absence or a CLOSED/FAILED stream-status row after raw
EOF/RST, and no replacement circuit ID in sampled circuit-status snapshots over 10 seconds. The
live lane does not attribute exact EOF/write ordering
inside the data plane or prove absence of retry outside Tor's circuit-status surface/window.

Leak-corpus scans apply only to cleartext and diagnostic data where meaningful; the live TLS
ciphertext is opaque and is not scanned as if it were application plaintext. The empty attached
DP output and `LogConfig.Type=none` prove observed-output and retention facts for this run, not
the absence of an invisible logging channel. Historical `CONNECT` mentions in the derived task
mean the SOCKS command.
