---
id: T029
title: 'Contract test asserting the rendered `torrc` matches the v1 template b'
status: done
created: 2026-07-04
last_updated: 2026-07-08
source: tasks.md#T029
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: ['spec.md#FR-011', 'contracts/torrc.md', 'research.md#5', 'plan.md#VII']   # derived at /start
decision_refs: []
reviews: { round: 1, date: 2026-07-08, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T029: Contract test asserting the rendered `torrc` matches the v1 template b

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test asserting the rendered `torrc` matches the v1 template byte-for-byte in `tests/contract/torrc/render_byte_match_test.go` — per `contracts/torrc.md` §"render_byte_match_test.go".

## Analysis

**Design decision (cross-plane split).** The contract prose
(`contracts/torrc.md` §`render_byte_match_test.go`) says the Go test
"Calls the control plane's `TorrcRenderer.render()`". That is not
achievable from Go: `TorrcRenderer` is Java (T037), and `research.md` §5
explicitly rejects pulling a JVM into the Go contract-test path (FFM /
`jextract` are Java→native, not Go→Java; JNI Invocation embeds `libjvm`
and is the rejected case; GraalVM `native-image --shared` is heavy and
out of scope for a low-complexity ticket). Reconciliation chosen with the
user: **the Go test pins the v1 template as a golden constant and
cross-checks the contract doc against it; T037 ships the Java
`TorrcRenderer` + a JUnit test asserting `render()` equals the same
golden.** The chain is contract doc == Go golden == Java `render()`
output. T029 owns the first link; T037 owns the second (and is "verified
by T029" per tasks.md).

- **Must hold:**
  - The Go golden constant `wantTorrc` equals the bytes of the
    `contracts/torrc.md` §"Rendered file" code fence, byte-for-byte
    (invariants 1–13 collectively; this test is the whole-file gate,
    T030 owns the per-invariant breakdown).
  - The golden ends with exactly one trailing `\n` and contains no `\r`
    anywhere (invariant #13 — determinism / byte reproducibility).
  - The golden carries every privacy-load-bearing directive (Principle
    III boundary): `IsolateSOCKSAuth` (inv. 1), `ClientUseIPv6 0` (5),
    `AvoidDiskWrites 1` (6), `UseBridges 0` + no `Bridge` lines (7),
    `SafeLogging 1` (8) — covered transitively by the byte-match, called
    out here because these are the rows the contract flags for
    `SECURITY-DECISIONS.md` review on change.
  - The Go test parses the contract doc's rendered-file code fence at
    run time and `bytes.Equal`s it against `wantTorrc`, so contract-doc
    drift fails the test (without this the Go side would be a no-op
    constant).
- **Gated:**
  - `gofmt` + `go vet` on the new file (once T076 wires `tests/contract`
    into CI — see residue).
  - The byte-equality assertion gates contract-doc ↔ Go-golden drift.
  - T037's JUnit test (under verify.sh gate 3 `mvnw-verify`) gates
    renderer ↔ golden — the link that actually exercises `render()`,
    in the renderer's own toolchain.
  - License-header check (verify.sh gate 1) on the new Go file.
- **Residue:**
  - **No verify.sh gate runs `tests/contract/` Go tests today.** Gate 2
    is `cd data-plane && go test ./...` (data-plane module only); gate 4
    runs only `.sh`/`.bats`; verify.yml mirrors verify.sh. This test is
    authored here but dormant until T076 wires `tests/contract/*/` into
    CI. Inherited gap — identical status to the already-merged
    T023–T028 Go contract tests.
  - **The Java renderer's output is gated in T037, not here.** If T037
    lands without the JUnit `render()==golden` assertion, the chain
    breaks silently. Mitigation: §Acceptance names T037's JUnit as the
    required sibling gate; T037's frontmatter already says "Verified by
    T029".
  - **Contract-prose drift (finding, out of T029's surgical scope to
    amend):** `contracts/torrc.md` §`render_byte_match_test.go` should
    be reworded to describe the Go-golden + Java-JUnit split rather than
    "Calls ... `TorrcRenderer.render()`". Surface to reviewer /
    spec-author for a lock-step contract edit.
  - **Stray space in contract line 23 (finding):** the `Source:`
    comment reads `specs/001-tor-route/ contracts/torrc.md` (space
    before `contracts`). T029 pins the template **as-written** (space
    included) to stay surgical; flagged as a likely contract-doc typo
    for a lock-step amend. Tor ignores comment lines so it is
    functionally harmless, but byte-fidelity-wise it is a defect.

## Acceptance

**Named test.** `TestRenderedTorrcByteMatch` in
`tests/contract/torrc/render_byte_match_test.go` (`package torrc`),
mirroring the content-gate + byte-match style of the sibling Go contract
tests (T019b `tests/contract/tor/port_exposure_test.go`,
T027 `tests/contract/error-template/auth_required_test.go`).

**Behavioral assertions (Principle VII — privacy-critical path):**
1. `wantTorrc` is a Go `const` (string) holding the exact bytes of the
   `contracts/torrc.md` §"Rendered file" code fence, **as that fence
   reads on disk today** (including the line-23 stray space noted in
   §Analysis residue).
2. At run time the test reads `contracts/torrc.md` (located via
   repo-root walk like `findRepoRoot` in `tests/contract/tor/`), extracts
   the rendered-file code fence (the fenced block under
   `## Rendered file`), and asserts `bytes.Equal(fenceBytes,
   []byte(wantTorrc))`. Failure message names the contract section and
   the first diverging byte index; does not dump the secret-free torrc.
3. Structural checks on `wantTorrc` (invariant #13): ends with exactly
   one `\n`; contains zero `\r`. Cheap, deterministic, independent of
   the markdown parse.
4. No self-skip / content-gate on `TorrcRenderer.java` — under the
   split, the Go test does not call the renderer and is useful
   immediately (it pins the contract). (If the reviewer prefers parity
   with the sibling tests' skip-until-implemented style, the gate would
   be a no-op since T037 is Java and the Go test doesn't depend on it.)

**Runnable command (dormant until T076):**
`cd tests/contract && go test ./torrc/` — compiles standalone today;
verify.sh does not invoke it (see §Analysis residue).

**Sibling gate (T037's scope, recorded here so the chain is explicit):**
`control-plane/core/src/test/java/.../TorrcRendererTest.java` asserts
`TorrcRenderer.render(v1Config)` equals `wantTorrc`'s bytes. T029 does
not author that file; it relies on T037 to land it.

## Out-of-scope

- The Java `TorrcRenderer` itself and its JUnit `render()==golden` test
  — T037's scope (T037 frontmatter: "Verified by T029"). T029 lands the
  Go golden + the contract-doc ↔ golden cross-check; T037 lands the
  renderer ↔ golden link.
- The per-invariant breakdown (rows 1–13) — T030
  (`tests/contract/torrc/invariants_test.go`).
- The no-bridges substring sweep — T031 (`no_bridges_test.go`).
- The live-sidecar `GETCONF` assertion — T032
  (`live_sidecar_test.go`).
- Wiring `tests/contract/*/` into verify.sh / CI — T076's scope.
- Amending the contract prose (`contracts/torrc.md`
  §`render_byte_match_test.go`) to describe the Go-golden + Java-JUnit
  split, and fixing the line-23 stray space — surfaced as findings in
  §Analysis residue; left for a lock-step contract edit, out of T029's
  surgical scope.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
