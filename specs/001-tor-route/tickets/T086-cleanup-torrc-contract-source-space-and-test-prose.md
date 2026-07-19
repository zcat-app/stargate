---
id: T086
title: 'Clean up torrc contract: Source-space typo + test prose drift'
status: done
created: 2026-07-08
last_updated: 2026-07-08
source: followup:T029   # cleanup of two findings surfaced in T029's /start grounding
phase: Polish
story: '-'
blocked_by: [T029]
parallel: true
files_budget: 4
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs: ['contracts/torrc.md', 'research.md#5']
decision_refs: []
constitution_refs: ['VI: Open and Auditable']
reviews: { round: 1, date: 2026-07-08, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T086: Clean up torrc contract: Source-space typo + test prose drift

## Context

Followup to T029 (done). T029's `/start` grounding surfaced two
`specs/001-tor-route/contracts/torrc.md` defects that were out-of-scope
for T029's surgical byte-match test. Both were verified by falsification
before this ticket was opened (see §Notes):

1. **Stray space (line 23).** The rendered torrc's `Source:` comment
   reads `# Source: specs/001-tor-route/ contracts/torrc.md` (a space
   before `contracts`). The canonical no-space form
   `specs/001-tor-route/contracts/torrc.md` appears in 5 other places
   (`analysis/2026-05-18-findings.md`, ticket T014, and the contract's
   own self-references); the space form exists only on line 23 and its
   downstream copies (T029's golden + comments). Confirmed typo. Tor
   ignores comment lines so it is functionally harmless, but the
   rendered torrc is an auditable artefact (Constitution Principle VI —
   Open and Auditable), so the operator-facing path reference should be
   correct.
2. **Prose drift (§`render_byte_match_test.go`).** The contract says
   the Go test "Calls the control plane's `TorrcRenderer.render()`".
   `research.md` §5 forbids a JVM in the Go contract-test path, and no
   Go→Java mechanism exists (FFM/`jextract` are Java→native; JNI
   Invocation embeds `libjvm` — the rejected case; GraalVM
   `native-image` is heavy), so this can never become true. T029
   implemented the Go-golden + contract-doc cross-check split; T037
   carries the Java `render()==golden` JUnit. The prose now contradicts
   the implemented test and misleads readers about where the
   `render()` assertion lives.

Fixing line 23 requires a lock-step update to T029's Go golden
(`wantTorrc`) — the contract's own §"When this contract changes" rule
mandates this, and T029's byte-match test enforces it fail-closed.

## Analysis

*(Omitted — `privacy_critical: false` and `complexity: low`; quick pass
per `docs/process/analysis.md`. The directive SET is unchanged; only a
comment and prose are touched. T029's byte-match test machine-enforces
that no directive drifts. See §Notes for the privacy-criticality
justification.)*

## Acceptance

1. `contracts/torrc.md` line 23 reads
   `# Source: specs/001-tor-route/contracts/torrc.md` (no stray space).
2. `contracts/torrc.md` §`render_byte_match_test.go` prose reworded to
   describe the actual mechanism: the Go test pins the v1 template as a
   golden constant and cross-checks `contracts/torrc.md` byte-for-byte;
   the renderer↔golden equality is asserted by T037's JUnit (Java), per
   `research.md` §5's Go-harness decision. No claim that the Go test
   "calls" `TorrcRenderer.render()`.
3. `tests/contract/torrc/render_byte_match_test.go`: the `wantTorrc`
   golden updated to drop the stray space (lock-step with item 1); the
   doc comment that justified pinning the space "as-written"
   (T029 §Analysis residue) removed/updated since the space is gone.
4. `cd tests/contract && go test ./torrc/` PASSES (golden == contract
   fence, byte-for-byte). `scripts/verify.sh` GREEN.

## Out-of-scope

- **No change to any torrc directive** (`SocksPort`, `IsolateSOCKSAuth`,
  `SafeLogging`, etc.) — only the `Source:` comment and the
  §`render_byte_match` prose. The directive set is byte-pinned by
  T029's test; any accidental directive change fails-closed there.
- T029's own ticket §Analysis residue (which records the stray-space
  finding as of T029's landing) is a historical record and is NOT
  edited — T086 is the resolution.
- The other torrc test descriptions in `contracts/torrc.md`
  (`invariants_test.go`, `no_bridges_test.go`, `live_sidecar_test.go`,
  `isolate_socks_auth_effect_test.go`) are NOT reworded — their
  "rendered output" framing is T030/T031/T032/T058's `/start` concern,
  not this cleanup's.
- Wiring `tests/contract` into verify.sh / CI — T076's scope.

## Notes

**Falsification record (why these are real, not confirmation bias).**
- *Space:* grep shows the no-space form is canonical (5 sites); the
  space form exists only at the defect and its downstream copies.
  Falsifier "the space is intentional" refuted.
- *Prose:* `research.md` §5 + the Go→Java mechanism survey (FFM
  direction, JNI rejection, GraalVM weight) show the prose can never
  become true. Falsifier "a future mechanism will make it true"
  refuted.

**`privacy_critical: false` justification.** The change alters a
comment and prose, not a privacy directive. The byte-match test (T029,
landed) gates any accidental directive drift fail-closed, so the
privacy boundary is machine-enforced regardless. Constitution Principle
VII's tests-first attaches to the directive path, which T029 already
covers; this ticket's changes sit downstream of that gate.

**`files_budget: 4`.** Counted files exclude `specs/`
(`contracts/torrc.md`) and the ticket file itself; only the Go test
file counts (1), with headroom for the lock-step golden + comment edit.
