---
id: T178
title: 'Diagnose and repair live initial token-load failure'
status: done
created: 2026-09-27
last_updated: 2026-09-27
source: T132 live VM execution on 2026-09-27
phase: 'Foundational'
story: 'US2'
blocked_by: ["T159", "T173", "T177"]
parallel: false
files_budget: 10
privacy_critical: true
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/control-grpc.md ReloadTokens
  - specs/001-tor-route/data-model.md §1.7–1.9
  - specs/001-tor-route/contracts/socks5-auth.md
decision_refs: []
reviews: { round: 1, date: 2026-09-27, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T178: Diagnose and repair live initial token-load failure

## Context

T132 can run on the saved independent Ubuntu VM. Its enforcing AppArmor profile,
production owner rules, Tor bootstrap and both plane processes work. However,
the initial authenticated SOCKS request fails before the DP-only recovery probe.
Two three-minute attempts failed; a third with T173's ten-minute cold-CP setup
allowance also failed (751.54 seconds overall). The longer run observed a
running CP with zero restarts, both IPC sockets, persisted generation 1, zero
configured credentials and no DP snapshot. The follow-up diagnosis below
identifies the initial token-store failure.

The tested checkout was `47011e4e36000496530d58a120e10c9d34815a0a` plus T132's
staged changes. Its CP TLS source SHA-256 is
`a8a17c6252a1bba4cd458fdd4962c6ad42cf2e9976febe7bb228e358b04edc0b`.
Local evidence and the source manifest are under `target/runs/T132-vm/`;
T132's execution record gives environment, commands and artifact hashes.

## Analysis

- **Must hold:** a valid configured credential reaches the durable CP state
  and the authenticated DP generation. Before that, admission remains denied.
  Preserve exact-generation acknowledgment, atomicity and stale-state refusal.
- **Gated:** derive a regression for concurrent SQLite writes before repairing
  the transaction boundary, then repeat the real-stack probe. The named
  `SqliteTokenStateTest.aggregateWriterCannotAbortInitialCredentialCommit`
  reproduces the upgrade conflict. `TestDeploymentSnapshotCommitAndRestore`
  also runs against `/var/lib/stargate` under the enforcing production
  AppArmor profile in the Docker policy gate.
- **Residue:** the database failure is established; the exact SQLite lock
  ownership graph is inferred from timed thread samples. Do not infer missing
  ALPN or relax confinement, logging or authentication.

## Diagnosis (2026-09-27)

- The same generation-1/zero-credential failure recurred on the saved VM with
  T173's two-vCPU `-cpu max` settings. A separate diagnostic CP launch with a
  600-second Quarkus transaction timeout also failed at the same boundary.
  Neither the old CPU model nor the 60-second transaction timeout explains it.
- A disposable CP launch with Java Flight Recorder enabled captured the first
  failing operation. At 08:34:24 UTC, `insert into configured_tokens` threw
  `org.sqlite.SQLiteException: [SQLITE_BUSY] The database file is locked`.
  Hibernate wrapped it in `LockAcquisitionException`; JTA rolled back;
  `SqliteTokenState.commit()` threw its infrastructure exception, which the CP
  bootstrap intentionally contained. This explains generation 1 with no
  credential row or DP snapshot. The control process remained up.
- At that instant, Flight Recorder sampled the `operational-aggregates` worker
  in `SQLiteConnection.commit()`. `AuditLogService` starts a one-second flush
  worker before `TokenLoader.load()`. It writes `operational_aggregates` in a
  separate transaction while token enrollment reads then writes its own
  transaction. This is a concurrent SQLite writer, and the observed failure
  matches SQLite's documented deferred read-to-write upgrade conflict. The
  exact lock ownership sequence was not directly captured.
- Repair should serialize or correctly acquire the SQLite write transaction
  before the loader's read-to-write work, while preserving atomic enrollment
  and the operational-count policy. Extending the JTA timeout alone is not a
  repair. Reproduce the conflict in a test before changing production code.

The recorder used only synthetic disposable credentials and did not enable
application logs. The sanitized event summary is retained under
`target/runs/T178-vm-cpu-max/diagnosis.txt`; raw recorder data is removed after
analysis. No T132 live acceptance is claimed.

### Second boundary exposed by the SQLite repair (2026-09-27)

The first repaired VM run committed generation 1 and one credential, then
wrote a matching DP snapshot, but authenticated SOCKS still failed. Kernel
AppArmor evidence identified repeated denied read opens of the exact
`/var/lib/stargate/` directory. The existing contents rule did not permit
opening the directory itself. `WriteSnapshot` had renamed the file but could
not open the directory for its required fsync, so `ReloadTokens` correctly
did not acknowledge or publish that authority to the authenticator.

The new deployment-path regression passes unconfined and fails under the
old enforcing profile at that exact open. Its repair grants only read access
to the state directory itself; directory sync, authentication and the
network/socket/signal confinement remain enforced. This is the next failing
boundary of Acceptance 3, within this ticket's initial-authentication repair.
The original failed smoke log is preserved under
`target/runs/T178-vm-repair/live-attempt1.log` (SHA-256
`e01855ad4a485e79faa19b2a904f3a0a8a2ddde95e6854f328ce03cd5012fd7c`).

## Acceptance

1. Reproduce and identify the first failing boundary without exposing tokens,
   keys, verifier bytes or request logs. Preserve the current failed artifacts.
2. Derive a regression from the applicable contract before any repair; record
   red/green evidence for the diagnosed property. If the fixture is responsible,
   repair the fixture and document that finding instead of changing production.
3. Pass initial authenticated SOCKS forwarding on the enforcing VM with the
   real CP, DP and Tor. Then rerun T132's snapshot-lost DP-only restart probe
   with CP continuously running and require application bytes after recovery.
4. Keep `scripts/verify.sh` green and obtain independent review. Update the
   threat model if the diagnosed repair changes its implementation claims.

## Out-of-scope

- No policy waiver, disabled AppArmor, plaintext IPC, diagnostic logging or
  manually injected DP verifier set to make the integration test pass.
- Do not count a CP restart as DP-only recovery or mark T132 complete until
  its full live assertion passes.

## Execution evidence

- T178 uses an isolated checkout at baseline
  `47011e4e36000496530d58a120e10c9d34815a0a`; the original checkout's staged
  T132 changes are preserved. The T178 commit excludes every T132 source/test
  change. VM integration uses those existing staged T132 fixtures as a
  separately identified overlay, without claiming T132 completion.
- The SQLite regression failed at `insert into configured_tokens` with
  `SQLITE_BUSY` before repair. The same command passes after reserving the
  SQLite writer before credential reads. Generation reservation still occurs
  first; successful candidate commit still precedes the authenticated push.
- The AppArmor regression executes the production snapshot writer and
  restores authentication from the result at the actual deployment path.
  The identical native test binary passed unconfined, failed under the old
  profile, then passed under the repaired enforcing profile. Both sequences
  are recorded in `../evidence/T178-tests-first.json`.
- Live acceptance passed on the saved Ubuntu VM (`qemu -accel tcg -cpu max
  -m 6144 -smp 2`), with `stargate-dp (enforce)` and the production IPv4/IPv6
  UID-5102 owner rules. Initial authenticated SOCKS forwarding carried
  application bytes. `TestStackSmoke/T132_DPOnlyRestartRecovery` removed the
  stopped DP's snapshot, restarted only DP and carried application bytes
  after authenticated recovery: PASS (47.25 seconds). The complete smoke
  passed in 539.86 seconds; the partition-reference-vector test also passed.
- The unchanged saved integration binary SHA-256 is
  `ee4a8e96bc9322accc2fba5e0fb94ffb5ccbb9b59725eb5f9dc6c9a936836f81`.
  Run from the guest's `tests/integration` directory with
  `BUILDX_BUILDER=t132-native ../../target/integration.test -test.run
  '^(TestStackSmoke|TestT131PartitionUsernameReferenceVector)$' -test.count=1
  -test.v -test.timeout=50m`. The full sanitized output, runtime source/image
  identities, enforcing policy and CP lifecycle evidence are embedded in
  `../evidence/T178-tests-first.json` under `live_acceptance`.
- A separate Docker observer confirmed unchanged CP container ID, start time,
  restart count (zero) and running state across the DP restart. Docker's CP
  lifecycle history contains one start, followed only by the smoke test's
  final cleanup. No CP restart supplied the recovery. The successful log is
  retained at `target/runs/T178-vm-repair/live-attempt2.log` in the original
  checkout (SHA-256
  `2f364cea069faa5c1930078011a728a0924b7c9a36ff7870eeacaa4400408ed1`).
- This satisfies T178's live acceptance. T132 remains in progress with its
  original staged implementation and tests; its own review and focused
  commit remain separate work.
