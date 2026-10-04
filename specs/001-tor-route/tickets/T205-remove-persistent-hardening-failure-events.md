---
id: T205
title: 'Remove persistent hardening failure events and reconcile the schema'
status: in-review
created: 2026-10-03
last_updated: 2026-10-04
source: 'T155 resumed cumulative CP/browser falsification CPB-M1; full next repair scope approved 2026-10-03'
phase: 'Foundation audit remediation'
story: ''
blocked_by: ["T034b", "T055", "T091", "T151", "T156", "T157", "T188", "T195"]
parallel: false
files_budget: 21
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - 'III: Privacy-Preserving by Construction — persistent operational records and fail-closed routing'
  - 'V: Honest Threat Model'
  - 'VII: Tests-First for Privacy-Critical and Contract Code'
  - 'VIII: Adversarial Review at Milestones'
complexity: high
risk: high
round_cap: 3
spec_refs:
  - 'specs/000-architecture/spec.md §14.4 storage.local layout and §14.5 runtime gate/failure UX'
  - 'specs/001-tor-route/spec.md FR-004 and FR-004a'
  - 'specs/001-tor-route/contracts/foundation-boundaries.md browser protected-decision contract'
  - 'THREAT-MODEL.md §5.3 WebRTC and relevant client-storage limits'
  - 'tests/live-e2e/mullvad-browser-hardening/README.md'
decision_refs:
  - '2026-10-03 maintainer approved full next scope after T203: conforming HardeningRecord repair, absorb T117 and redirect named consumers; reserved exact wording remains separately evaluated and approved'
remediates: T055
replaces: T117
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T205: Remove persistent hardening failure events and reconcile the schema

## Context

The resumed T155 CP/browser falsification, CPB-M1, confirmed that
`extension/background/hardening.js` persists a last failure under `storage.local.hardening`:
`lastAuditedAt` stores the event hour and `lastAuditResult` stores a surface, preference name
and arbitrary `readError`. A subsequent successful audit returns before touching that record,
so the previous failure survives. Current Constitution III expressly prohibits persistent
operational events, including events with hour-bucketed timestamps. Finite current readiness
is permitted; a stale last-failure record is not current state. No actual destination or secret
leak was demonstrated, and none is needed to establish this policy contradiction.

Architecture §14.4 still illustrates invented DoH/HTTP-3 results; §14.5 requires a persistent
failure record for a future signed export. T117 would replace the example with the shipped
event/hour/error schema while forbidding correction of §14.5. The approved repair absorbs its
complete consistency scope instead. T034b/T055/T091 and other completed tickets retain their
historical text; this remediation defines the current contract. No constitutional amendment
or new persistent aggregate mechanism is needed or authorized.

The orchestrator's preceding filing batch records T117 as deferred/replaced by T205 and
redirects the approved consumer edges. The independent T205 developer runs after T204 has
completed, with fresh grounding on that actual baseline; orchestration order is not a T155
prerequisite edge. All listed prerequisites were done at filing.

## Analysis

- **Must hold:** new hardening checks never create persistent operational event/hour/error
  state; supported startup/upgrade removes the obsolete API-visible hardening record without
  touching credentials or routing configuration. Only finite current volatile status crosses
  the UI boundary. Unknown/failed current hardening cannot authorize a protected request.
  Explanatory notifications and their failures cannot become raw-error logging or history.
- **Gated:** spec-derived Node tests exercise real shipped hardening source, API edge failures,
  state transitions and preservation of unrelated storage; router/popup units retain protected
  cancellation and scope. Existing package and extension gates run through `scripts/verify.sh`.
- **Residue:** Node mocks do not prove actual browser storage migration, background restart,
  displayed notification or network behavior. The dedicated pinned-browser scenario below
  closes those properties against the packaged candidate. Browser/OS forensic erasure, durable
  external backups, untested browser versions and unrelated existing release obligations remain
  outside that result. A SKIP cannot close a required scenario.

## Acceptance

1. Before implementation, add named spec-derived regressions in
   `extension/background/hardening.test.js` and `hardening.edges.test.js` covering WebRTC
   disabled, enabled, unknown/unset and rejected/unavailable API reads. Use synthetic event-hour
   and error markers to demonstrate the current persistent write. Include failure followed by
   success and successful browser/background restart with an existing legacy `hardening`
   record. Retain a behavioral RED from the starting writer and identical-command GREEN via
   `scripts/test-first-evidence.py`; missing dependencies or new-symbol errors alone are not
   the required RED.
2. Remove the persistent last-failure event, timestamp/hour and arbitrary error text. At the
   supported startup/upgrade boundary, remove legacy `storage.local.hardening` state, including
   records written before T205, without clearing or rewriting unrelated device credentials,
   profile isolation identity, route preferences or other valid client configuration. Test
   idempotence, absent/malformed legacy values and unavailable/rejecting storage APIs. Do not
   claim migration success when removal fails; errors must be contained and must not create a
   new event record, raw-error log or unhandled startup rejection. The live migration acceptance
   requires actual successful removal, not merely an attempted API call.
3. Keep hardening state volatile and current: startup begins unknown/closed; only the supported
   API's measured disabled value opens the runtime hardening gate. Enabled, unset and read-error
   results close it. Test failure/success transitions and restart initialization, including a
   held initial read so previously persisted failure or success cannot serve as authority.
   Preserve the existing protected-request cancellation/no-fallback contract and intentional
   Direct behavior. This ticket does not select or implement T190's per-request re-audit policy.
4. Show finite current status and actionable explanatory UX without recreating a stored failure
   report or event stream. Preserve the distinction between measured enabled and unknown,
   WebRTC's runtime API boundary, transient supported Gecko notifications, and the popup's
   main-navigation/mixed-request/unverified-connection scope. Test notification rejection and
   status failure/success/restart behavior; do not let notification delivery determine routing
   authorization. Only the minimal current-status presentation needed by this repair is in
   scope; no history, dashboard/export, new route feature or broad popup redesign is authorized.
   Any changed user-facing text must pass the exact-wording approval gate in acceptance 8.
5. Inspect and test explicit logging/output sinks within the changed hardening/migration path.
   Synthetic raw read, notification and storage errors must not reach persistent state or
   diagnostics as arbitrary detail text. A static finite current error indication may explain
   failure without becoming history. Record the inspected browser logging setup and observable
   results; API key removal is not forensic disk erasure and does not establish absence from
   browser/OS backups, storage journals or other retention outside the measured API boundary.
6. Extend the real-browser harness with a focused scenario using the actual reproducibly
   packaged extension and a disposable profile. Seed a synthetic legacy hardening record through
   the extension's real storage API, together with synthetic unrelated credential/configuration
   sentinels; exercise enabled/failure, hardened/success and restart initialization. Inspect
   complete API-visible persistent extension storage before and after, proving the event, hour
   and raw-error markers are absent after cleanup and remain absent after later success/restart,
   while unrelated state survives unchanged. Distinguish a real browser process restart from
   an extension reload; exercise the former for persistence/restart closure. Fault-injected
   unknown/read-error variants may supplement the unmodified-package checks but must be
   separately labelled and bound to their source. Never call a modified test package the
   unchanged shipped artifact.
7. In the same focused pinned-browser evidence, retain calibrated routing positive/negative
   controls: a valid protected request reaches the intended SOCKS catcher, explicit Direct
   remains distinct, and failed/unknown/pending hardening reaches no unintended destination,
   ordinary proxy, SOCKS forwarding endpoint or resolver. Verify actual finite status and
   failure notification behavior. Record browser/archive/driver identities, package and source
   hashes, profile settings, commands, outcomes, reruns and limitations. Use the saved supported
   Mullvad Browser 153.3.0esr development pin after rechecking its artifact identity; do not
   substitute the incompatible system browser or claim stable-channel/release certification.
   Existing effective-profile deficiencies owned by T200 remain explicit; do not repair them
   here or count injected harness preferences as shipped configuration.
8. Reconcile architecture §14.4's example and §14.5's failure UX/export requirement in this
   same reviewed repair so neither prescribes a persistent event or invented runtime surface.
   Reconcile current source comments, tests, browser-harness storage observations and its
   README reset/inventory-read instructions where removal makes them stale. Record T117's
   absorbed scope and replacement lineage without deleting its historical acceptance or
   modifying completed T034b/T055 tickets. Update the relevant THREAT-MODEL boundary in this
   change; draft exact THREAT-MODEL/quickstart/other changed product-facing words separately
   for independent evaluation and maintainer approval before applying them. Approval of this
   ticket is not approval of those exact words. No constitution or SECURITY-DECISIONS edit is
   authorized. Internal architecture/schema reconciliation follows this approved acceptance.
9. Preserve named consumer ownership. T190's re-audit decision and other items, T197's broader
   inventory/profile/indicator claims and T200's shipped profile/release-verification repair
   remain pending. Explain any narrowly absorbed stale hardening comment/storage instruction
   in their filing/history notes so later work cannot restore the removed persistence contract;
   do not implement their independent acceptance. T155/T078 depend on T205; T078/T079 replace
   T117 with T205; T190/T197/T200 wait on T205. No T205 dependency on T155 or a pending consumer
   is allowed. Verify the already approved filing graph is acyclic and report drift to the
   orchestrator rather than silently editing unapproved dependency edges.
10. Retain focused source-bound tests-first and live results under the feature evidence
    directory, with raw test artifacts under `target/runs/T205`. Record what evidence is
    refreshed for T155 and what remains historical. The driver green gate and ordinary fresh
    independent review pair must pass on the final candidate. Record Constitution VIII impact
    assessment and every actual reviewer/round in the usual completion follow-up. T205 closure
    does not close T155, T200, milestone reviews or external human release review.

## Grounded files budget: 21 paths (initial budget 20)

This is an upper bound, not a requirement to touch each path. The final fresh-context outline
must choose the smallest adequate implementation. Consumer bookkeeping is handled by the orchestrator in the preceding approved filing batch
and is part of the implementation baseline; do not repeat it in this ticket. No unrelated
consumer implementation is included. All changed paths, including overhead and new tests, count.

1. `specs/001-tor-route/tickets/T205-remove-persistent-hardening-failure-events.md`.
2. `specs/001-tor-route/STATUS.md`.
3. `specs/001-tor-route/evidence/T205-tests-first.json`.
4. `specs/001-tor-route/evidence/T205-live-results.json`.
5–7. `extension/background/{hardening.js,hardening.test.js,hardening.edges.test.js}`.
8–9. `extension/background/{router.js,router.test.js}` — only necessary finite current-state
     delivery and direct fail-closed regression/orphan work; no re-audit policy change.
10–12. `extension/popup/{popup.js,popup.test.js,popup.html}` — only if necessary for the minimal
       current-status presentation and its tests; retain existing route-indicator scope.
13–14. `extension/lib/{storage.js,storage.test.js}` — own-change comments that currently claim
       hardening owns a persistent storage key; no unrelated storage-wrapper behavior change.
15. `specs/000-architecture/spec.md` — §14.4/§14.5 reconciliation.
16. `THREAT-MODEL.md` — exact approved boundary/migration limitations.
17–19. `tests/live-e2e/mullvad-browser-hardening/{probe.py,README.md,test_probe.py}` — focused
       browser closure, direct storage-oracle orphan and discriminating harness tests if needed;
       `test_probe.py` is a proposed new file, not existing evidence.
20. `specs/001-tor-route/spec.md` — FR-004's persistent-write mandate is a direct
    schema orphan in spec_refs; pre-granted accepted reconciliation substitutes for
    the unused optional quickstart path.
21. `tests/live-e2e/mullvad-browser-hardening/run.sh` — pre-granted (rule 2026-10-01)
    direct own-change orphan: its source comment still directs reading the removed
    persistent hardening key. Replace only that comment; preserve executable lines.

The initial budget was 20 paths. Round-1 review identified the additional
`run.sh` storage-reader comment orphan. The existing own-orphan pre-grant permits
this required correction and records the driver budget as 21; no new subsystem,
acceptance change or fresh scope permission is inferred.

No new runtime dependency or extension permission is anticipated. Extra direct acceptance or
own-change orphan paths use the existing budget pre-grant with precise reasons; unrelated
scope or unresolved policy remains a stop condition.

## Out-of-scope

- A replacement persistent aggregate, enum journal, event export or admin dashboard. Choosing
  aggregates later requires a separately grounded maintainer decision, completed immutable
  hour-bucket publication, allowlisted categories and retention before implementation.
- T190's mid-session/per-request WebRTC re-audit policy, unused management permission, token
  validation and CP work; T197's route-indicator behavior or broader inventory/prose repair;
  T200's DoH/HTTP-3 template or release-precondition changes; T201 auth recovery.
- T204 listener work; T203 observer work; T155 TLS-probe/GetStatus/full-stack closure; T206
  capture-integrity implementation; T202 host-direct infrastructure.
- New routes, broader routing policy/UI features, new permission grants, credential export,
  browser-forensics tooling or guaranteed physical erasure.
- Changing the constitution, accepting the violation in SECURITY-DECISIONS, reopening completed
  lineage tickets, deleting old evidence, publication, push or milestone merge.

Existing tests that positively require `storage.local.hardening.lastAuditResult` and side-effect
record writes are explicitly authorized to change to the opposite approved contract. Preserve
all still-valid WebRTC boundary, notification schema, fail-closed and shared-background-scope
checks. Update a pinned internal surface only if the minimal current-state design requires it,
with corresponding discriminating tests and honest contract reconciliation; no opportunistic
refactor is included.
