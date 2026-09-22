<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# T152 evidence

Baseline: `34315e9` on `001-tor-route`. On 2026-09-22 the maintainer authorized one T152 with
`files_budget: 64` after the T148 comparison. This is execution evidence, not a review verdict.
Prior tickets' uncommitted completion metadata was preserved separately before starting T152.

## Writer inventory

| Surface inspected | Candidate boundary | Executable evidence |
|---|---|---|
| CP `AuditLogService`, token loader, sidecar monitor | Five category counts; transaction commit; completed hours; no labels/details | `AuditLogServiceTest`, retained loader/monitor tests |
| SQLite operational and manual-token state | V002 removes event rows and unused credential history; preserves active verifiers/generation | `V001MigrationTest`, `SqliteTokenStateTest` |
| Flyway bookkeeping | Checksums/versions/success retained; install actor/time/duration replaced with constants | Migration/validation test |
| Java protocol-version, reload and runtime adapters | Diagnostic writers removed; current IPC failures preserved | `InterPlaneWireTest`, runtime tests |
| Go controlclient, snapshot and main processes | No event log calls; stdout/stderr redirected before private startup | Controlclient tests, real DP process/socket contracts |
| Quarkus, JVM/native startup and shell output | Framework logging off; actual Java entrypoint discards descriptors and disables dump sinks | Real CP image/mount startup; controlled launcher probes |
| Tor/native shell output | `/dev/null` in loaded torrc and entrypoint; current observer health retained | Static torrc suite; rebuilt real Tor offline probe |
| Docker output, core and health history | Four services: logging `none`, core limit zero, healthcheck disabled | Rendered Compose and actual Docker capture with positive controls |
| Shared diagnostic oracle | Every nonblank operational line forbidden, including former allowed journals | `tests/internal/loginvariants`; real DP harness cleanup |

Current auth snapshots/generation and schema identity are required state, not operational
journals. Dormant future-feature schema declarations have no production writers in this slice.
Existing routing, stream rejection, snapshot contents and authentication checks remain; obsolete
log-based waits now inspect the corresponding behavior. V001 historical tests explicitly target
V001; active-schema and forward-migration tests cover V002. V001's checksum is unchanged.

## Red before green

The local ignored evidence directory is `target/runs/T152-evidence/`. It is not portable proof;
committed tests reproduce the properties. Logs contain developer fixtures, not deployed secrets.

- `cp-red.log`: two token actions immediately produced two persistent rows; the open-hour
  assertion expected zero. The final test also checks one closed-hour count of two and the
  exact three-column operational schema.
- `go-red.log`: `TestOperationalSnapshotWritesAreSilent` failed on a successful snapshot write.
  The test retains the persisted-generation positive control.
- `migration-red.log`: migration left the legacy `audit_log` table. The final real SQLite test
  additionally preserves active auth, deletes revoked history, checkpoints WAL, vacuums, and
  demonstrates that a retired backup still needs separate cleanup.
- `deployment-red.log`: effective production Compose retained raw CP container output.
- `log-guard-red.log`: the prior shared oracle accepted operational journals.
- `clock-rollback-red.log`: both refinement tests failed against the first aggregate candidate:
  rollback-only JTA contributed a count; after expiry/restart a regressed clock reopened history.
  Both now pass with committed-only counting and the latest closed-hour zero checkpoint.
- `schema-history-red.log`: the schema-bookkeeping regression failed before its fix. The first
  assertion concerned the actor placeholder; `schema-history-time-red.log` refines assertion
  order and removes only that fix to directly demonstrate retained installation timestamps.
  The latter is a mutation check, not a second independent initial implementation sequence.

Pre-fix diff SHA-256: `77adddfe7b0ac151354efb01317405a688e041a27a45a5843b0f86a94cc03278`.
Expanded tests-before-fix diff SHA-256:
`2ac7a22ffc8231f1155d27511cb7b3fb3c047d5949f25db604a274ddf6e43aad`.

## Executed checks

- `go test ./data-plane/internal/controlclient ./data-plane/cmd/stargate-proxy
  ./data-plane/cmd/tor-observer ./tests/internal/loginvariants ./tests/contract/torrc`: PASS.
- `go test ./tests/contract/control-grpc -count=1`: PASS, real DP process and authenticated UDS
  calls; closure/backoff/auth assertions replace receipt-log synchronization.
- `control-plane/mvnw -q -f control-plane/pom.xml -pl persistence -am
  -Dtest=V001MigrationTest,AuditLogServiceTest,InterPlaneWireTest
  -Dsurefire.failIfNoSpecifiedTests=false test`: PASS, actual Quarkus/SQLite/JTA and wire checks.
- `STARGATE_TEST_TAGS=docker bash tests/contract/compose/operational_logs_test.sh`: PASS.
  The same controlled writer is captured with `json-file`, suppressed through the real launchers,
  and leaves no log path under each service's effective `none` driver.
- `bash tests/contract/compose/control_mount_test.sh`: PASS. Builds the actual CP image and checks
  both mount cases through completed Quarkus/Flyway migration with zero captured output. The
  writable DB path is fixture-only; these unprovisioned containers do not prove full auth startup.
- `docker build --progress=plain -t stargate-t152-tor:test sidecars/tor`: PASS.
  Local `tor-offline.sh` starts that image with cold disposable volumes and network disabled;
  checks baked torrc bytes, cookie-authenticated `GETCONF Log` and SOCKS isolation flags, running
  state, absent health history and empty output with Docker `json-file` enabled: PASS.
- `bash scripts/verify.sh`: final gate result recorded by the driver before review and commit.
  An earlier pass failed only the old CP banner wait; the replacement migration check passed.

The worker closes/expires on its next scheduled tick (normally within one second); tests advance
an injected clock and invoke the same flush boundary. A stopped/unwritable database cannot erase
itself. Unpersisted counts may be lost on restart. Disabling retention ends the collection lifetime
and removes the checkpoint. No production aggregate export API exists yet.

Live Tor bootstrap/anonymity, remote deployment profiles and release reproducibility remain
separate cadence checks; the offline Tor probe claims none of them. Legacy WAL, retired DB/log
archives and backups require the procedure in THREAT-MODEL §5.18. No forensic host-erasure claim
is made. Required independent reviews and their manifest are produced only by `review-task.sh`.

## Round 1 disposition

Astra requested REWORK for installer readiness; GLM approved with five Minor findings.
Original reports/manifest are preserved under `target/runs/T152-evidence/round1-*`.

- Astra Major: the installer now requires the observer's one-shot cookie-authenticated Tor
  bootstrap result. Running/no-health containers cannot bypass it. `init_readiness_test.sh`
  failed before the repair (`NOT_READY` yielded success); the Docker installer fixture also
  exercises NOT_READY/UNAVAILABLE while its real DP TCP listener is available. Observer tests
  pin READY/NOT_READY/UNAVAILABLE and refusal of unknown modes. A blocking-cookie regression
  failed before adding the four-second whole-query bound; the CLI exits without output.
- GLM Minor 1: startup behavior retained and its documentation narrowed. The counter sink must
  load its persisted clock boundary before collecting; unavailable SQLite may abort CP startup,
  as Flyway already can. The loader's later catch does not promise CP boot availability. DP
  routing remains independent. This is not acceptance of a Blocker/Major security finding.
- GLM Minor 2: remaining degraded-warning prose in the touched wire/architecture contracts now
  names silent degraded state.
- GLM Minor 3: reproduced linux/arm64 `undefined: syscall.Dup2`; both Go entrypoints now use
  the already-pinned `x/sys/unix` duplication API. Both linux/amd64 and linux/arm64 builds are
  checked separately.
- GLM Minor 4: `TestDPDiscardsRuntimeCrashDiagnostics` sends SIGQUIT to the actual DP binary.
  An ordinary Go child is the positive control proving runtime diagnostics are emitted; the
  DP must retain none. Removing only the descriptor boundary fails the test (mutation evidence).
  Harness teardown now waits for the process and its output pumps before checking silence.
- GLM Minor 5: Docker's raw-output error scan uses the suite's standard `grep` dependency.

These changes remain within the authorized 64-file budget. Release-only and forensic-erasure
limitations above remain unchanged. Round 2 must review the full updated candidate.

Additional round-2 execution: rebuilt `stargate-t152-observer:test`; the local
`observer-native-probe.sh` runs it against real Tor with networking disabled and cold volumes.
The real cookie returns NOT_READY (exit 1), a wrong-cookie overlay returns UNAVAILABLE (exit 2),
and both leave empty Docker `json-file` capture. This is native authentication/readiness evidence,
not live bootstrap or anonymity evidence. Focused Go/socket tests, the Docker installer regression,
and Docker operational capture all pass; both Go binaries build for linux/amd64 and linux/arm64.

The isolated installer wait test uses a deterministic clock; the real Docker test retains
wall-clock timeout coverage. A second regression reproduced Compose exec consuming caller
stdin; the one-shot invocation now closes stdin and the test supplies a marker to verify it
cannot reach the child. Closing stdin also preserves the verification runner's test inventory.
