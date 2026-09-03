---
id: T115
title: 'Fix the wire gate's comment-sensitive impl-detection probe'
status: in-review
created: 2026-09-03
last_updated: 2026-09-03
source: hand-authored   # Raised during T044's implementation (2026-09-03):
                        # the gate's content probe matched a code COMMENT and
                        # flipped verify.sh RED while T045/T050 are pending.
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []          # The gate script exists (T095); T045/T050 need not
                        # land first — this fixes detection accuracy, which
                        # is exactly what gates their self-lift.
parallel: true          # Single test-harness file; no other open ticket
                        # touches it.
files_budget: 4
files_scope:
  - tests/contract/compose/inter_plane_wire_test.sh
  - tests/contract/compose/inter_plane_wire_gate_test.sh
                          # + §Acceptance 1: the gate's fixture/substrate test
                          # (comment-only no-detect; server/client symbol
                          # detection; bare-probe pin).
  - data-plane/internal/auth/token.go
                          # + §Acceptance 4 only: restore the workaround
                          # comments to name the RPCs verbatim — no code
                          # change (the out_of_scope note authorizes this).
out_of_scope:
  - data-plane/**        # T044's comments were reworded as the in-round
                         # workaround ("token-reload handler"); this ticket
                         # owns the real fix and may restore precise wording.
  - proto/**, contracts/**   # The wire contract itself is T095's, done.
  - scripts/verify.sh    # The gate is already discovered and invoked.

# --- Stargate-specific flags ---
privacy_critical: false  # Test-harness detection accuracy; no runtime
                         # behaviour. The gate it fixes guards a
                         # privacy-critical surface, but the diff is
                         # shell-test-only. Redteam N/A.
constitution_refs:
  - "V: Falsify-before-publishing — a GREEN verify.sh must mean the gates
     that should have run did, and a gate that fires must fire for the
     reason it names (this one fired on a comment)"
  - "VII: fail-closed gates (the fix must keep the gate's FAIL-forcing
     self-lift property, not soften it)"
complexity: low
risk: low                # Contract-test harness only; ship behaviour
                         # unchanged.
round_cap: 2

spec_refs:
  - "specs/001-tor-route/tickets/T095-test-inter-plane-wire-contract.md
     §Notes (the gate-lift/LIFT-MARKER forcing function this ticket must
     preserve)"
  - "specs/001-tor-route/tickets/T044-implement-data-planeinternalauthtokengo.md
     (the session that tripped the probe; its §Analysis finding 1 records
     the workaround)"
decision_refs:
  - "specs/001-tor-route/tickets/T114-wire-staticcheck-gosec-into-go-workspace-gate.md
     (structural precedent: hand-authored gate-accuracy ticket raised by
     another ticket's round)"

reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T115: Fix the inter-plane wire gate's comment-sensitive impl-detection probe

## Context

`tests/contract/compose/inter_plane_wire_test.sh` decides whether its
RUNTIME tier must be lifted (R1–R9 assertion authoring, FAIL-forcing) using
two probes: (a) file existence of the four impl paths (T038/T045/T050), and
(b) a content probe — `grep -rqE 'ReloadTokens|WatchEvents' data-plane/internal/`.
Probe (b)'s stated intent is to catch "a DP gRPC server necessarily imports
ReloadTokens + WatchEvents" even if the impl moves paths (redteam Minor:
path-rename bypass).

The probe is satisfied by COMMENT TEXT. On 2026-09-03, T044's
`data-plane/internal/auth/token.go` doc comments named "T045's ReloadTokens
handler" while describing the token store's consumers — no gRPC code
exists. verify.sh flipped RED (`RUNTIME tier GATE-LIFT REQUIRED … 0/9
LIFT-MARKER rows`) on a tree where the gate's own primary condition (all
four impl files) is false, and the failure message blamed a missing
assertion authoring pass that this ticket's landing state cannot produce
until T045/T050 land. T044 worked around it by rewording the comments to
"token-reload" — i.e. source text is currently constrained by a detector's
false-positive class, which is backwards.

## Analysis

Quick pass (`privacy_critical: false`):

- **Must hold:**
  - The content probe fires only on gRPC server/client CONSTRUCTION
    symbols, not prose — e.g. the generated stubs' registration/client
    entry points (`grpcpb.Register…Server(`, `NewControlClient(`) or an
    AST/comment-aware match; the chosen mechanism is documented here.
  - The gate's FAIL-forcing self-lift is preserved: when the impl truly
    lands, the R1–R9 LIFT-MARKER forcing function still triggers (falsify
    by landing a stub with a registration call and no markers → gate must
    still FAIL).
  - Probe (a) (file existence) is unchanged.
  - The gate still SKIPs (never PASSes) while neither probe condition
    holds, with the same SKIP line.
  - T044's workaround comments may be restored to naming the RPC verbatim
    — the fix must make that safe again (grep the restored wording → gate
    stays SKIP).
- **Gated:** `bash scripts/verify.sh` — the inter-plane gate returns to
  SKIP on today's tree (impl absent, no false content hit) and the rest of
  the suite stays green; the contract-test harness change is exercised by
  `tests/contract/run_task_test.sh`-style shell discipline
  (`tests/contract/shell_quality_test.sh` re-runs clean).
- **Residue:** no static shell probe can be perfectly semantic — a comment
  quoting the new detection pattern verbatim could still trip it; accepted
  (named here), the construction-symbol pattern is far narrower than bare
  RPC names and the S-tier structural rows are unaffected.

## Acceptance

1. On the current tree (T045/T050 impl absent), the gate's detection phase
   reports impl-absent and the RUNTIME tier SKIPs — even with a file under
   `data-plane/internal/` whose comments contain `ReloadTokens` /
   `WatchEvents`.
   — runnable: `bash scripts/verify.sh` → inter_plane_wire gate SKIP,
   RESULT GREEN; plus the gate script's own fixture/substrate test if the
   author adds one (preferred: a case with a comment-only match asserting
   no detection).
2. With a synthetic file containing a real registration/client symbol
   (`grpcpb.Register…Server(` / `NewControlClient(`), detection fires and
   the gate FAILs on missing LIFT-MARKERs exactly as today (the forcing
   function is intact — NOT softened into always-skip).
   — runnable: the gate's fixture case for detection-positive.
3. `grep -rqE 'ReloadTokens|WatchEvents' data-plane/internal/` is no longer
   the detection mechanism (or is comment-aware); the chosen replacement is
   recorded in the gate script's header comment.
   — runnable: `grep -n "runtime_content_detected" tests/contract/compose/inter_plane_wire_test.sh`.
4. T044's `token.go` comments are restored to name the RPC verbatim
   ("T045's ReloadTokens handler") and verify.sh stays GREEN.
   — runnable: `bash scripts/verify.sh` after the restore.

## Out-of-scope

- Authoring the R1–R9 runtime assertions — T095's own landing state, only
  possible once T038/T045/T050 exist.
- Any change to the wire contract, proto, or DP/CP implementations.
- The T025a/T093 test files and their wording.

## Notes

Provenance: surfaced 2026-09-03 during T044 round-1 verify (RED
`RUNTIME tier GATE-LIFT REQUIRED` on an impl-absent tree; root cause
isolated to the bare-word content probe; in-round workaround = comment
rewording, recorded in T044 §Analysis finding 1). Hand-authored per
docs/process/ticket-template.md; T114 is the structural precedent for
gate-accuracy follow-ups.
