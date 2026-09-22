<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# T158 evidence

Baseline: `0fa5fa1` on `001-tor-route`. The maintainer authorized retaining one ticket with a
22-path budget on 2026-09-22. This is implementation evidence, not an independent approval.

## Red before green

Before any counter implementation change, `TestCurrentHourNeverVisible` used the existing API
and failed on poll zero: one request and 13 bytes appeared in the active hour. The original
source, baseline SHA, test diff and failing output are preserved locally in
`target/runs/T158-evidence/` (ignored local artifacts, not portable review evidence).

The deterministic-clock/worker seams were then added without publication or expiry enforcement.
The full audit regressions failed for current-hour exposure, mutated published rows after
rollback, unexpired rows, missing idle cleanup and disabled collection. Actual authenticated
UDS RPCs exposed private counts during concurrent writes. No missing-tool/compiler error is
counted as the privacy falsifier. Configuration regressions separately rejected a stub that
ignored disabling and malformed values before production parsing was implemented.

Supplemental Java/Go and long-lived forwarding-socket probes were also challenged against the
recorded old counter implementation, rebuilt via a Go source overlay with the clock seams.
Java received one row where it required zero. The forwarding test exposed the active request
in both enabled/disabled cases. These are later mutation/compatibility controls, not a claim
that supplemental tests predated the counter fix. An initial Java run before its peer fixture
existed failed to obtain READY; that fixture failure is explicitly excluded from evidence.

## Executed targeted coverage

- `go test -race ./data-plane/internal/audit -count=1`: passed. Repeated polling, exact totals,
  UTC boundary, no-traffic rollover, rollback through pre-epoch time, long-lived completion,
  snapshot copies, concurrent increments/readers/rollover, seven-day cutoff, forward jump,
  expired-row non-reappearance, disabled state and idle-worker cancellation/deletion.
- `go test ./tests/contract/socks5 -run
  'Test(AuthPassedCounterIncrements|AuthFailureCounterSideChannelResistance|HTTPConnectSameDestinationDistinctFirstPartyRefused|LongLivedCounterCompletionAndDisabledCollection)$'
  -count=1`: passed. Existing bursts retain exact 100-request/819200-byte totals, rejected
  auth/HTTP counts are checked after rollover, and positive controls still detect lost
  accounting. A real authenticated tunnel forwards before and after publication of its
  request; its 24 bytes appear in the next completed hour. Disabled collection still routes.
- `sh control-plane/mvnw -B -q -f control-plane/pom.xml -pl api -am
  -Dtest=CrossPlaneTlsTest -Dsurefire.failIfNoSpecifiedTests=false test`: passed. A generated
  Java v1 client calls the Go service over pinned mTLS/UDS with production version metadata;
  empty/current/finalized/rollback/expired responses decode with the unchanged field layout.
  Existing TLS interoperability cases also pass.
- `bash scripts/regen-proto.sh`: regenerated Go stubs from comment-only proto changes. Field
  numbers, types, methods and major/minor metadata are unchanged. Java regenerates at build.

## Evidence boundaries

Only the selected counter contract tests compile `cmd/stargate-proxy` with `go test -c` to
inject a traffic clock through `runWithCounters`. They retain production listener, confinement,
auth, forwarding, mTLS and RPC wiring. TLS time and network deadlines remain real. The ordinary
`go build` binary has no test-clock environment reader; a packaging regression checks this.
This does not claim that the test binary and production binary are byte-identical.

Memory state is lost on restart. Seven-day cleanup uses synthetic time, not a week-long soak;
clock integrity and scheduler progress are preconditions disclosed in the threat model.
Production CP polling/SQLite traffic storage and T152's operational-log migration are not
implemented here. No browser, live Tor, remote deployment or forensic memory-erasure claim.

The repository-wide `scripts/verify.sh` gate and independent native reviewer set determine
completion; their skipped Docker/live/release obligations are not established by these tests.

## Verification environment repair

The first full gate's CP-image step used Docker's legacy builder because buildx was absent,
streaming about 5 GB of unrelated local artifacts. That build was terminated, so the initial
gate is a failure, not green evidence. The Ubuntu-provided `docker-buildx` client plugin
`0.30.1-0ubuntu1~24.04.1` was installed locally; the complete gate is rerun without skips.
Its downloaded amd64 package SHA-256 is
`30723359cf4825afa5ac2087cf5833163f80fb74802bc32e0ed6c9efc13e4b3c`.
This changes local build tooling, not deployed dependencies or the reviewed Dockerfile.
