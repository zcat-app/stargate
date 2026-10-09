---
id: T212
title: "Close Docker verification budgets, history and CI inputs"
status: pending
created: 2026-10-06
last_updated: 2026-10-09
source: "T202 guest15 verification stop; reviewed repair plan final SHA256 cd5fc2e88e255bab31bfe34d34cc5e01f8200244d29d91810f588d0d190b637c; maintainer authorized prerequisite implementation"
phase: "Foundation verification remediation"
story: "-"
blocked_by: [T211, T213]
parallel: false
files_budget: 10
files_scope:
  - scripts/go-workspace-gate.py
  - tests/contract/workflow/verify_discovery_test.sh
  - .github/workflows/verify.yml
  - .github/workflows/docker-cadence.yml
  - tests/contract/workflow/ci_inputs_test.sh
  - specs/001-tor-route/tickets/T212-close-docker-verification-budgets-history-ci.md
  - specs/001-tor-route/STATUS.md
  - specs/001-tor-route/evidence/T212-tests-first.json
  - specs/001-tor-route/evidence/T212-live-results.json
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
  - "Final repair plan §5 R2b; final-document hash above is distinct from the two v3 READY advisory reports"
  - 'Maintainer: "ok so if you have a plan you can be again orchestrator of the implementation"; defer/prerequisite route authorized'
  - "Maintainer authorization 2026-10-09: T213 plan v2 SHA256 5a04c840e8a213274e1cba09085b7337e2608cf21527a3fe3281dbe612761d31 and frozen ticket SHA256 774ab8da6e0f479584c27bcf62f3ee79acf1cb72051dc0946198504f3226b0a3"
  - "Approved lifecycle clarification: after T213 delivery, metadata-only reopen commit precedes a fresh driver-owned T212 START; this supersedes the earlier original-START transfer for the reopened attempt only. Preserve old evidence as history; restore original tests-first JSON before new RED."
reviews: {}
overrides: []
aborted_attempts: []
reopens: [{ date: 2026-10-09, blocker: T213, resolved_by: 4c462d2, prior_deferral_commit: e285488, prior_deferral_reason: blocked-on-new-ticket }]
redteam_findings: []
clarity_check: {}
---

# T212: Close Docker verification budgets, history and CI inputs
## Context

After Tor helper and fixture repairs, close the aggregate verification envelope, genuine
historical evidence context and dependency-driven Docker CI coverage under FR-016. Existing
Go10m defaults cannot bound the long serial Tor suites; shallow exports/checkouts omit the
tracker's required authentic historical commit. This ticket derives finite source-based caps,
retains package concurrency and proves complete ordinary/Docker coverage plus the mandatory
same-candidate disposable DNS complement before T202 can be reopened.

## Analysis

- **Must hold:** every workspace module/suite remains discovered, race/vet/scanners and all-SKIP
  refusal stay intact, exact source-derived operation bounds fit the admitted aggregate envelope,
  and only authentic reachable commit context satisfies evidence checks.
- **Gated:** discovery/classification, CI-input contract, tracker commit-positive/missing/bogus/
  blob-negative controls, the ordinary gate and complete named Docker entrypoint.
- **Residue:** finite long-suite/resource scheduling, remote post-squash object reachability,
  actual dependency-trigger coverage and privileged DNS execution require explicit falsifiers.
- **Constitution Check:** III retains the disposable capture and actor matrix; IV/VI preserve
  immutable tools/pins and authentic history. V distinguishes ordinary CI DNS SKIPs from real
  qualification. VII requires atomic RED/GREEN and all mandatory coverage; VIII retains review.

## Acceptance

1. Re-ground on delivered T210/T211, especially T211's shared discovery fixture, before edits.
   Stage spec-derived budget/history/CI regressions and capture a meaningful RED with
   `scripts/test-first-evidence.py red T212 -- <exact probe command>` at the actual START baseline,
   then identical-command GREEN after implementation. Each RED must demonstrate its intended
   missing property, not tooling absence. Explicitly stage T212-tests-first.json. Use existing
   declared fixtures for budget regressions; an additional source path cannot silently exceed
   the exact10-path union. This is atomic regression/fix work, not a done red-only test dependency.

2. Inventory every discovered workspace module and every test's build/opt-in/capability guard,
   source line, serial/parallel status, enforced operation/whole-test bound, cleanup and measured
   compile/vet/scanner cost before choosing caps. The planning12-package/71-test inventory covers
   only two test modules and includes helpers/optional cases; it is not all-live coverage or the
   whole workspace. Store sanitized inventory, cold/hot timing and the adopted equations in the
   declared T212 live-results record; ignored raw diagnostics alone are insufficient acceptance.

3. Preserve one `go test -json -count=1 -race ... ./...` per module, existing default package
   concurrency/-p, workspace discovery, classification, tagged vet/scanners and all-SKIP refusal.
   Keep hermetic10m. In named Docker mode use a module-level explicit per-binary timeout equal
   to its largest grounded package envelope. Derive contract/tor from44m contexts+5m cleanup;
   torrc from T210's finite33m contexts+3m cleanup; integration from106m primary contexts plus
   diagnostic/down6m and connection/session cleanup; each needs measured short-test/build margin.
   Independently inventory compose and other packages; no automatic other10m assumption. Retain
  10m where verified adequate. Real shorter-operation contexts and forced-stall falsifiers remain
   enforced; a larger package alarm does not replace them. No new opt-in hides required suites.

4. Compute upper jobs from pre-gate/setup plus sequential-module build/vet/scanner work and
   concurrently scheduled package envelopes adjusted for -p/resource contention, then extension,
   Maven, shell contracts (including T162 Docker tier), artifact and cleanup margin. Inspect
   global firewall/confinement effects before co-running suites; explicitly serialize unsafe
   coexistence and recompute the sum. Disposable executor adds its narrow DNS tier. P3 and
   renewed O2 each require one complete canonical Docker verify invocation, not split standalones.
   Adopt no125m/300m cap without finite source bounds/full inventory/measured admission.
   Verify the then-current official CI runner limit while implementing, keep the admitted guest
   invocation <=six hours and preserve ordinary30m/agent60m unless an explicit separately reviewed
   change is required. Mismatch refuses admission; no blind timeout growth or VM retry.

5. Change both CI verification checkouts to fetch-depth0, retain persist-credentialsfalse and
   correct the shallow-history comment. Exercise authentic commit/tree positive, shallow/missing
   object, fabricated40hex and blob-not-commit negatives. For external execution, transfer a
   self-contained authentic required-commit bundle/full ancestry with no unmet prerequisites,
   fetch to a non-HEAD context ref and verify commit type/tree identity without moving candidate
   HEAD/index/source manifest. Bootstrap uses an owned external verifier/control-root, standard
   transfer/execution and no imports from undeployed T202 runner/provisioner.

6. Exercise a local main-only-after-milestone-squash negative and retained/published-feature-ref
   positive: full-depth checkout supplies only objects reachable from refs actually served by
   origin. Before milestone close, check the actual published refs and pinned evidence commit
   reachability with an authentic fresh clone. If unavailable, stop for separately authorized
   feature-ref publication or the tracker's reviewed repin to verified main-reachable evidence.
   Do not push automatically, fabricate commits, lower tracker assertions or silently repin.
   Local origin/001-tor-route history is not proof of current remote availability.

7. Close Docker CI push/PR path filters against actual dependency inputs of verify and shared
   setup. Retain existing patterns and workflow_dispatch; include data-plane/**, control-plane/**,
   extension/**, tests/contract/**, tests/integration/**, scripts/**, setup-toolchain action,
   go.work/go.work.sum, all module/lock/POM/npm manifests, .mvn/** and source-resolved lock/config
   inputs, plus parent workflow where it affects shared contracts. Prove representative DP, CP,
   installer, gate, lockfile and setup-action changes trigger for both push and PR; unrelated prose
   does not falsely claim a Docker run. Pins/actions/scanners remain unchanged.

8. Run complete ordinary canonical verify as an ordinary user with actual pinned tools, correct
   HOME/cache ownership and authentic history, no opt-outs. Before full live cadence, respect
   the maintainer's emulation-first preference: calibrate unchanged race compile/vet, s13/s14
   readiness15s/10s, existing500ms probes and TestBootstrapDeadlineEnforcement in the owned
   disposable boundary. Failed calibration refuses that tier without widening controls. Confirm
   identity/capabilities, ordinary user/groups/sudo, daemon locality/kernel, source/tool manifest,
   invocation roots, owned process control/stop, no concurrent ticket/live/gate/build, retained
   disk rules, storage projections and disk floor. Maintain the independent external supervisor's
   six-hour cap, bounded owned TERM/KILL/reap, per-command exits/logs/artifacts, manifest recheck
   and independent machine stop/cleanup. Any necessary maintained adapter is a separately declared
   reviewed prerequisite; no hidden T202 files or fabricated target admission.

9. Run one complete `STARGATE_TEST_TAGS=docker bash scripts/verify.sh` in that admitted disposable
   boundary as the ordinary user. Record every discovered package and actual executed top-level
   tests, exits and every capability/opt-in/build SKIP. All mandatory suites and controls execute;
   package PASS alone is insufficient. Ordinary-user CI truthfully names TestDNSLeak and
   TestDNSLeakDetectsSimulatedDPQuery as SKIP, never DNS PASS/complete privileged coverage.
   On the identical candidate, narrowly invoke both DNS tests with required capture privilege
   inside the disposable boundary, using the existing isolated namespace/documentation resolver
  192.0.2.1 procedure. Record capture availability/interfaces, actual proxy forwarding and the
   injected-leak falsifier. Both must execute without SKIP. No shared-host packet capture,
   privileged CI identity change or whole-cadence root invocation is authorized.

10. Stage sanitized `specs/001-tor-route/evidence/T212-live-results.json`, binding the complete
    cadence and DNS complement to measured candidate/input manifest, exact commands/identities,
    tool/environment data, expected/executed tests/SKIPs/exits, budget/dependency inventory,
    raw evidence hashes and independent cleanup. Before admission declare this exact generated
    output and exact lifecycle normalization, retain all executable/policy/acceptance inputs,
    and bind external verifier/control bytes separately. Record full measurement and final review
    snapshots; prove differences are only declared generated/lifecycle outputs or renew evidence.
    Results cannot hash themselves. Stage the results and rerun identical tests-first GREEN,
    canonical verification and exact native GLM/Astra implementation review before completion.
    No required SKIP, unowned residue, failed cleanup, unexplained source change or partial cadence
    becomes PASS. T202 remains deferred until all three prerequisites are delivered.

## Out-of-scope

Production/runtime routing, policy, pins, retained-asset deletion, T202 source restoration,
new privileged CI process/step, tracker assertion relaxation/automatic repin, automatic publication
and unrelated pending tickets. Named discovery/CI tests may change only for explicit named-mode
budgets, dependency-trigger/history regressions and authentic coverage. Preserve operation windows,
real controls, race/vet/scanners, discovery, all-SKIP refusal and mandatory suite inclusion.

## Implementation inventory

All10 tracked paths, including exact T212 tests-first/live-results JSON, ticket/STATUS and done
scorecard, are declared in YAML; ceiling10. No additional tracked diagnostics/document/test path
is implicitly authorized. The scorecard belongs only to the normal done follow-up commit,
outside the implementation review candidate and its negative-space check; the declared inventory
count is unchanged. Stop and refine/split if the actual union cannot fit.
