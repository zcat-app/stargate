---
id: T187
title: 'Report pending or stale revocation; count only after DP ack'
status: done
created: 2026-09-29
last_updated: 2026-09-30
source: "reviews/redteam-20260929-694dbd8.md (area 2 M3, survived falsification, narrowed to observability)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 14   # TokenLoader.java + TokenLoaderContract.java + GrpcReloadChannel.java + StargateControlPlane.java + TokenLoaderTest.java + StargateControlPlaneTest.java + scripts/subcommands/status + scripts/stargate + quickstart.md + data-model.md + THREAT-MODEL.md + this ticket + STATUS.md regen + evidence/T187-tests-first.json (7 -> 14 maintainer-authorised 2026-09-30; anything beyond 14 is a stop)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "II: Plane Separation"   # report pending delivery, not success
  - "III: Privacy-Preserving by Construction"   # finite current status, no event history
complexity: high
risk: medium
round_cap: 3
spec_refs:
  - specs/001-tor-route/data-model.md
  - THREAT-MODEL.md
decision_refs:
  - "data-model §1.8 / T159: keeping DP state on a stale reply is required and stays"
  - "T178: this silence already hid a real initial token-load failure"
remediates: "T159"
reviews: { round: 2, date: 2026-09-30, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: ["20260929-005-revocation-status-invisible"]
clarity_check: {}
---

# T187: Report pending or stale revocation; count only after DP acknowledgement

## Context

`TokenLoader` writes the `revoked`/`enrolled` aggregates inside the store
transaction, before `ReloadTokens` is delivered. With CP logging off, stdout and
stderr sent to /dev/null and no status surface (`scripts/stargate` has only
`init`), an operator cannot see that a revocation is pending (DP unreachable) or
was refused as stale (e.g. after CP state loss while the DP holds a newer
generation). The only persisted trace counts the revocation as done. The
constitution's failure table says "Report pending delivery, not success"; the
threat model §5.15 says the operator must not be told it succeeded before the DP
acknowledges. The stale-reply mechanism itself is specified (data-model §1.8)
and is not changed here.

## Analysis

- Must hold: the operator can read a finite, current delivery state
  (e.g. PENDING, ACKNOWLEDGED(generation), STALE_CONFLICT) with no history,
  timestamps or labels; `revoked`/`enrolled` aggregates count only acknowledged
  application.
- Gated: CP tests for unreachable, stale and acknowledged DP replies.
- Residue: the stale-conflict recovery remains an explicit operator procedure.

## Acceptance

1. Add a finite current-state status readable through local administration
   (e.g. `scripts/stargate status` over an authenticated local channel, or a
   static exit/refusal), within Constitution III's lifecycle-enum allowance.
2. Move aggregate counting after exact DP acknowledgement.
3. Tests first: unreachable DP → PENDING and revoked stays 0; stale reply →
   STALE_CONFLICT and revoked stays 0; acknowledgement → ACKNOWLEDGED(gen) and
   revoked counts after the hour closes. Record red before green.
4. Document the stale-conflict recovery in the quickstart/operator procedure and
   reconcile data-model/threat-model text.

## Out-of-scope

Changing stale-generation handling; terminating established pipes on revocation.

## Notes

Maintainer decisions (2026-09-30, maintainer-authorised, relayed by the orchestrator):

1. `files_budget` raised 7 -> 14 to cover the fourteen paths in the frontmatter comment
   (option B of the developer's budget stop). Anything beyond 14 is a stop.
2. The operator surface is a new `scripts/stargate status` subcommand following the `init`
   conventions (PATH independence, exit codes, T016). It reads the CP's volatile tmpfs
   status file via `docker compose exec`: a current-state enum PENDING /
   ACKNOWLEDGED(gen) / STALE_CONFLICT, no history, no timestamps, outside the shared IPC
   volume, within Constitution III's current-lifecycle-enum allowance.

## Evidence

- Tests first: `specs/001-tor-route/evidence/T187-tests-first.json` (red: TokenLoaderTest counted
  pending/stale diffs inside the store transaction; StargateControlPlaneTest found no status).
- Live (saved QEMU guest, real DP + CP images, project `stargate-t187`; gitignored
  `target/runs/T187-vm/live.sh`, log `live-run3.log`): `scripts/stargate status` reported
  ACKNOWLEDGED(1) → PENDING/30 with the DP stopped after revoking a label → ACKNOWLEDGED(2)
  when the DP returned without a CP restart → STALE_CONFLICT/40 after restoring an older CP
  database with different content → ACKNOWLEDGED(2) after the quickstart recovery option 2 →
  20 with the CP stopped → NONE/50 without `tokens.yaml` (round-1 wording; round 2 renamed
  the absent-file state UNKNOWN/50 and made an unreadable file exit 20). The status file was
  `/tmp/stargate-control/auth-delivery` (0600, directory 0700, uid 5101, tmpfs); the DP
  mounts no CP `/tmp` path. The first live attempt showed the CP's `/run` tmpfs is root-owned
  0755, so the file moved to the CP-private `/tmp` tmpfs (Compose mode 1777).
- Round 2 (review r1 astra Majors, GLM Minors): PENDING is published before the initial RPC
  (`pendingIsPublishedWhileInitialDeliveryIsOutstanding`, DP reply held); a failed status write
  withdraws the old value and is retried (`failedStatusWriteNeverLeavesObsoleteState`); the
  command distinguishes an absent file (UNKNOWN/50) from an unreadable one (unavailable/20) and
  its vocabulary/exit codes run against a stubbed `docker`
  (`statusCommandPrintsValidatedStatesAndRefusesUnreadableState`). The three failed before the
  fix (`target/runs/T187-vm/r2-red.log`); the recorded tests-first JSON keeps the round-1 red and
  its green reruns the same probe over the round-2 snapshot. The quickstart recovery resolves the
  DP volume by Compose label. Live rerun `live-run4.log`: all seven steps pass (UNKNOWN/50 at
  step 7; recovery used the label-resolved volume).
- Residue: the hour-closure half of acceptance 3 relies on AuditLogService's existing
  standalone-count rule (AuditLogServiceTest); the new tests assert the count is written only
  after exact acknowledgement. `scripts/subcommands/status` is not in verify.sh's shell-quality
  list (verify.sh is outside the budget); `shellcheck -x` was run by hand (only the SC1091 info
  that `init` also reports). Its behaviour is exercised by the stubbed-docker JUnit case above.
