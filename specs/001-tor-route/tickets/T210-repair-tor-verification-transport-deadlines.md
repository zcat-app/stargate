---
id: T210
title: "Repair Tor verification transport and I/O deadlines"
status: pending
created: 2026-10-06
last_updated: 2026-10-06
source: "T202 guest15 verification stop; reviewed repair plan final SHA256 cd5fc2e88e255bab31bfe34d34cc5e01f8200244d29d91810f588d0d190b637c; maintainer authorized prerequisite implementation"
phase: "Foundation verification remediation"
story: "-"
blocked_by: []
parallel: false
files_budget: 15
files_scope:
  - tests/contract/tor/control_port.go
  - tests/contract/tor/control_port_test.go
  - tests/contract/tor/control_port_live_test.go
  - tests/contract/tor/username_less_isolation_test.go
  - tests/contract/torrc/isolate_socks_auth_effect_test.go
  - tests/contract/torrc/live_sidecar_test.go
  - tests/integration/circuit_isolation_corpus_test.go
  - tests/integration/same_origin_shared_circuit_test.go
  - specs/001-tor-route/tickets/T210-repair-tor-verification-transport-deadlines.md
  - specs/001-tor-route/STATUS.md
  - specs/001-tor-route/evidence/T210-tests-first.json
  - specs/001-tor-route/evidence/T210-live-results.json
  - docs/process/reviewer-scorecard.md
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "V: Honest Threat Model"
  - "VI: Open and Auditable"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - "specs/001-tor-route/spec.md §FR-016"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
  - "docs/process/workflow.md §Evidence and atomic tests-first work (T156)"
decision_refs:
  - "Final repair plan §5 R1; final-document hash above is distinct from the two v3 READY advisory reports"
  - 'Maintainer: "ok so if you have a plan you can be again orchestrator of the implementation"; defer/prerequisite route authorized'
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T210: Repair Tor verification transport and I/O deadlines
## Context

T202's guest15 cadence failed after individual F1/F2 and cleanup-rehearsal passes. Its
aggregate remains FAILED. Ordinary Tor verification helpers still use stale TCP SOCKS
endpoints, unsynchronized subprocess diagnostics and phase windows that do not bound real I/O.
Repair this verification interface against FR-011/FR-016, the private socket in
`contracts/torrc.md`, and SC-002's unchanged threshold before renewed T202 qualification.
This ticket is an atomic regression-and-fix unit; there is no done red-only prerequisite.

## Analysis

- **Must hold:** the helper uses the shipped Unix transport, records race-free diagnostics,
  enforces existing operation windows and retains successful sessions needed by later stream
  observations. Tests retain framing, authentication, secret-redaction and isolation controls.
- **Gated:** untagged parser/helper tests, tagged build/vet and the ordinary canonical gate.
  Spec-derived real-child controls must falsify the repaired diagnostic and blocked-I/O paths.
- **Residue:** successful sidecar negotiation, live isolation and actual teardown require the
  six named isolated live suites and source-bound evidence; ordinary PASS does not establish them.
- **Constitution Check:** I/II production routing and lifecycles are unchanged; III preserves
  the Tor-private transport and existing isolation/statistical controls. IV/VI preserve pins
  and authentic inputs. V reports partial evidence accurately. VII requires meaningful atomic
  RED/GREEN; VIII requires the native GLM/Astra implementation gate on the exact candidate.

## Acceptance

1. Before implementation, stage spec-derived regressions and capture a meaningful RED through
   `scripts/test-first-evidence.py red T210 -- <probe command>`. The probe must exercise each
   of the four real-subprocess diagnostic paths (ControlPort, username-less, torrc isolation,
   same-origin), using successful dialogue followed by EOF/active synthetic stderr, plus
   blocked-read, blocked-write, cancellation and teardown controls. Missing tooling/files,
   disconnected buffer tests and an assumed final stderr string at first EOF are insufficient.
   Stage the implementation and rerun the identical command through `green`; explicitly stage
   `specs/001-tor-route/evidence/T210-tests-first.json` with the true START baseline.
   House a reusable real-subprocess diagnostic regression in untagged `control_port_test.go`
   so ordinary PR coverage executes it. The three tagged SOCKS-helper regressions may use their
   existing named files and substituted external child tools, but must exercise the actual
   helper bodies under the recorded hermetic race-enabled probe, without real Docker effects.
   Ordinary reusable coverage does not substitute for those four actual-helper controls.

2. Use one shared mutex-guarded diagnostic buffer in the Tor helper: a private `bytes.Buffer`
   with synchronized Write and snapshot, without anonymous embedding/promoted ReaderFrom.
   Use it on all four confirmed concurrent diagnostic read/write paths. Until Wait completes,
   EOF diagnostics are a best-effort snapshot. Preserve sequential request semantics and existing
   secret/error discipline. The real-child positive dialogue and race controls pass unchanged.

3. Export `SocksSocketPath = "/run/tor-fabric/private/tor-socks.sock"` beside ControlSocketPath.
   Repair corpus and same-origin child argv to `nc -U` with this exact Tor-side path; the
   hermetic argv control matches `nc -U /run/tor-fabric/private/tor-socks.sock` and proves successful
   pipe negotiation. Retain the production Unix-only contract and all existing assertions.
   Distinguish SOCKS negotiation failure from a low distinct-circuit count. Preserve the
   >=95/100 identity-tagged circuit statistic and every same-origin share/diverge control.
   Circuit entries do not establish completed destination CONNECTs or browser/DP coverage.

4. Carry the existing capture30s, connect3m, bootstrap5m and stream90s windows to actual
   blocking control/handshake read, write and cancellation edges. Keep session lifetime distinct
   from per-operation context: successful phase completion retains reusable sessions; failed
   operations discard/close their owned session and terminate/reap within its teardown bound.
   No deferred operation cancel may kill a successfully returned session. Arm the current5s
   Close bound before QUIT/Flush so pipe writes cannot block ahead of it. Exercise successful
   reuse, cancellation, early errors before session return, blocked reads/writes and zero owned
   child residue. Preserve all framing/auth/secret/deadline tests and the existing constants.

5. Ground and inventory every background I/O/command in `live_sidecar_test.go`. Propagate
   existing up5m/bootstrap5m contexts through Docker API and GETCONF operations and enforce
   the documented manual15m whole-test allowance, with90s cleanup accounted separately.
   Bound remaining API/GETCONF work within that outer window; do not inflate bootstrap.
   The ticket's accepted finite budget is at most15m test work plus existing90s cleanup,
   with each shorter phase enforced at its actual operation, before R2b derives package caps.
   The old manual go-test15m process alarm collides with15m foreground plus90s cleanup.
   Before the selected GETCONF run, declare a package allowance covering both (at least16m30s
   plus measured scheduling overhead), while retaining the15m work and90s cleanup limits.
   Declare it in the documented manual command in `live_sidecar_test.go` and record the
   selected allowance in the tracked `T210-live-results.json` evidence output.
   This selected invocation allowance is not a bootstrap/deadline inflation or full-gate repair.

6. Audit all changed-helper callers and preserve existing exported Connect/Authenticate/Command
   signatures with additive context-aware operations if needed. Include control_port_live_test.go
   in the declared scope. Explicitly verify the existing fresh-session operation contexts in
   `tests/contract/compose/network_hardening_test.go` and
   `tests/integration/stream_isolation_dp_uname_test.go`; unchanged signatures alone do not prove
   their operations/Close are finite. Run their existing caller/deadline controls against the new
   helper. If actual caller edits, helper extraction or further regression source paths are
   necessary, report and declare the exact revised union before implementation; remain <=15
   or split with explicit dependencies. Never broaden scope through an unexplored signature change.

7. Run complete canonical ordinary `scripts/verify.sh` on the exact candidate as an ordinary
   user with actual pinned tools, authentic Git history and no coverage opt-outs. Before live
   work, use the independent owned external bootstrap/control path, with no imports from
   undeployed T202 runner/provisioner. Check existing host emulation first as the maintainer
   requested: unchanged timing controls must pass before admitting it; otherwise report refusal
   without widening assertion windows or automatically retrying a VM. Admit machine identity,
   ordinary user/HOME/cache/groups/sudo, daemon locality, kernel/capabilities, exact source/tool
   manifest, process ownership, tested stop interface, retention and both storage projections.
   An adapter requiring maintained source changes is its own reviewed prerequisite before live
   execution. No concurrent ticket/runtime gate/live/build; six-hour hard cap, disk-floor polling,
   bounded owned TERM/KILL/reap, artifact collection and independent stop/cleanup apply.

8. In that admitted disposable boundary, execute sequentially, preserving existing documented
   manual outer allowances and all positive/negative controls: TestControlPortLive,
   TestUsernameLessIsolation, TestIsolateSOCKSAuthDistinctCircuits,
   TestLiveSidecarGETCONFSocksPort, TestCircuitIsolationCorpus and
   TestSameOriginSharedCircuit, plus changed-helper caller controls. Required SKIPs, deadline
   overrun, race, incomplete result or owned residue block completion. R1 selected execution
   does not claim the still-unrepaired full Docker cadence is GREEN.

9. Stage sanitized `specs/001-tor-route/evidence/T210-live-results.json`, binding measured
   candidate/input manifest, exact commands, user/capabilities/tools/environment, every named
   executed test and exit, expected versus actual coverage, raw artifact hashes and independent
   cleanup. Declare this exact generated output and any exact lifecycle normalization before
   admission; never exclude executable/policy/acceptance source. Record full measurement and
   final review snapshots, prove differences are only those declared outputs/lifecycle fields,
   otherwise renew evidence. The record cannot hash itself. After staging it, rerun identical
   tests-first GREEN, ordinary verification and required native implementation review. No
   candidate10/guest15 result is relabelled as this candidate's acceptance.

## Out-of-scope

Production DP/CP/extension, Compose/security policy, pins, T202 implementation/restoration,
other pending tickets, aggregate gate/CI repairs and retained-asset deletion. Existing named
verification tests may change only to restore private transport, synchronized diagnostics,
real I/O bounds, precise failure claims and their spec-derived regression controls. Preserve
all isolation thresholds, positive/negative controls, mandatory coverage and per-operation
assertions. Do not add TCP listeners, hide tests behind new opt-ins or weaken a SKIP rule.

## Implementation inventory

The YAML declares13 known tracked paths including both exact evidence outputs and the done
scorecard, ceiling15. It adds control_port_live_test.go to the final plan's seven named source
paths. The scorecard belongs only to the normal done follow-up commit, outside the implementation
review candidate and its negative-space check; the declared inventory count is unchanged.
Existing untagged control_port_test.go hosts the reusable regression. No extra source
path is implicitly authorized; re-ground and refine/split before any additional path is needed.
