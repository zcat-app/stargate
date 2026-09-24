---
id: "T157"
title: "Block protected-route failure without Direct fallback"
status: done
created: "2026-09-12"
last_updated: 2026-09-24
source: "specs/001-tor-route/contracts/foundation-boundaries.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T156", "T139", "T136"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/contracts/foundation-boundaries.md"]
decision_refs: []
remediates: "T055"
tests_first: []
reviews: { round: 2, date: 2026-09-24, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T157: Block protected-route failure without Direct fallback

## Context

The audit observed Direct descriptors on failed hardening/token/context paths but did not prove
actual browser egress. Constitution III now defines the network outcome explicitly.

## Analysis

- Must hold: protected requests cannot dispatch through a forbidden path while credentials,
  hardening, context or routing authority are unavailable. Both browser listeners share and
  revalidate the request decision; only intentional Direct requests may use the ordinary route.
- Gated: units exercise descriptor, generation, identity and UI decisions. Live tests require
  calibrated catchers, observed initialization ordering, an identical admitted sidecar request,
  completion markers and actual mutation failures. Prior reports alone cannot establish those
  newly explicit causal checks.
- Residue: controlled extension-initialization evidence does not establish browser-process launch
  or session restore before listener registration. T155 retains those stable-target tests and
  integrated packet/circuit evidence; neither an Alpha result nor a unit pass closes that gate.

## Acceptance

1. Ground the real browser APIs and specify request cancellation/blocking behavior before code.
   Test missing/invalid credentials, failed/unknown hardening, absent initiating context, startup
   races, sidecar failure, redirects, retries and subresources. Preserve intentional Direct use.
2. Record failing descriptor and browser-network probes before the fix; prove no protected
   request goes to Direct, system proxy or an unintended route. Include positive capture controls.
3. Give truthful failure UI without claiming a notification cancels the request. Update extension
   contracts/threat-model evidence, run relevant tests and scripts/verify.sh with required reviews.
4. Real-browser evidence is required for completion; unavailable execution remains pending. If
   decomposition is needed, keep its browser evidence child blocking T155.
5. Establish startup overlap with a controlled pending initialization operation in the real
   browser, valid stored credentials, and otherwise valid prerequisites. Record the request
   beginning before initialization is released, observe all forbidden paths while it is pending,
   and require safe terminal behavior after release. A completed installation followed by a page
   load, a persistent-background flag, or a sleep alone is not startup evidence. Any instrumented
   package must identify its exact changes and hash; distinguish that evidence from unmodified
   candidate coverage and retain the browser-launch/session-restore release obligation under T155.
6. Calibrate unavailable-sidecar coverage with the identical initiating page and protected
   request first reaching the available SOCKS server with the expected hostname and credential.
   Repeat that admitted path with the server unavailable/refusing; require terminal failure with
   no ordinary-proxy or destination fallback. Exercise removal of terminal-null protection and
   require its descriptor regression to fail. If the independent blocking listener still prevents
   network fallback, record that actual callback sequence and additionally disable that listener
   in a labelled combined mutant which must fail on captured fallback. Context cancellation before
   SOCKS admission cannot satisfy the available/unavailable pair.
7. Preserve inspectable per-scenario reports for baseline, candidate and falsifying mutations,
   with package hashes, exact commands, effective prerequisite states, startup ordering,
   reconnect ordering, and all three capture surfaces. Prove the oracle rejects an admitted
   opaque-context request, missing fixture generation, and delayed fallback. Reviewer candidate
   copies must contain the report observations, not solely hashes of unavailable local files.

## Out-of-scope

Constitution weakening, unrelated feature work, and claiming unavailable tests passed.

## Notes

Privacy regressions are authored first within this ticket; empty tests_first is not an exemption.
If decomposed, create concrete children and add them to T155 and affected consumers before closure.

The persistent-background requirement supersedes T051's historical non-persistent direction.
The completed ticket and generated `tasks.md` wording remain an audit record; architecture §14.1,
FR-004a and the foundation boundary now own the active persistent-background requirement.

On 2026-09-24 the maintainer selected `refine` after the first attempt reached round 3.
Acceptance 5–7 make its two unresolved Major evidence findings independently falsifiable;
no finding is overridden and no privacy requirement is relaxed. The previous candidate, reports
and reviewer set are preserved under `target/runs/T157-attempt-1/` before resetting the loop.
