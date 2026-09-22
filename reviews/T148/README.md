<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# T148 evidence

Baseline: `2afc6fc` on `001-tor-route`. Maintainer authorized one ticket with a 20-path budget
on 2026-09-22. This record is evidence of executed checks, not an independent review verdict.

## Tests-first sequence

Before the fixes, the spec-derived Go validity tests accepted expired/future pinned identities
for both full/resumed connection states, and both identity selectors failed renewal after a
synthetic long CP outage. Java `rejectsExpiredAndFuturePeersInBothRoles` accepted invalid dates;
`renewsIdentityWithoutPeerOrDiskAccess` failed its renewal assertion.

With only lifetime test seams (no enforcement), `TestTransportLifetimeBothRoles` failed in both
roles: `transport survived its mandatory lifetime`. Java's
`serverClosesActiveStreamWithoutPeerCooperation` and
`clientCannotRetainRevokedServerOnIdleChannel` both failed before their lifecycle fixes.

The baseline SHA, pre-fix diff, initial Go tests, failing command output and subsequent passing
logs are retained locally under `target/runs/T148-evidence/` (ignored, not portable evidence).
The committed tests reproduce the required properties. A preliminary unconnected-Java-engine
session-context comparison was discarded: before a handshake those contexts were null, so its
failure did not discriminate session reuse and is NOT counted as resumption evidence.

## Executable coverage

- `go test ./data-plane/internal/controlclient -count=1`: validity and renewal; independently
  forced idle-transport closure in both roles; T135 current-pin resumption regression; actual
  TLS resumption with an advanced authorization clock; production listener/auth/forwarding
  byte-pipe survival and new admission during CP outage and renewal.
- `sh control-plane/mvnw -B -q -f control-plane/pom.xml -pl api -am
  -Dtest=CpTlsTest,InterPlaneWireTest,CrossPlaneTlsTest
  -Dsurefire.failIfNoSpecifiedTests=false test`: Java date/renewal and active/idle transport
  deadlines; real Go↔Java UDS date rejection, ticket offers, pin replacement, positive authorized
  reconnect and ReloadTokens calls across repeated TLS connections.
- `bash scripts/verify.sh`: complete repository gate; its SKIP report remains authoritative for
  excluded Docker/live/release suites. The Go/Java process tests above run without Docker.

Resumption expiry tests advance only the verifier clock to exercise an actual resumed handshake;
Go's own ticket-expiry checks otherwise fall back to a full handshake. Java deliberately avoids
resumption: successful reconnects must be full handshakes, and invalid peers cannot reuse an old
session. Direct trust-manager unit calls alone are not claimed as transport evidence.

No live Tor anonymity, month-long soak, future remote-profile TLS or host-clock integrity claim
is made. The sidecar in the routing test is a local SOCKS echo fixture. Existing channels may
retain authority for up to 60 seconds; process suspension is outside the scheduling guarantee.
