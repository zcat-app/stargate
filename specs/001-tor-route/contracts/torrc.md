# Contract — Image-baked `torrc` (v1 of Tor Route)

**Status**: Phase 1 contract document

**Scope**: defines the byte-level invariants of the Tor sidecar's
`torrc` configuration file baked into the Tor image at build time for v1
of the Tor route (control-plane rendering deferred to a dynamic-config
feature; see §"Rendered file"). Tested at `tests/contract/torrc/`.

**Source**: FR-011, arch §8 (Tor row).

---

## Rendered file

For this static Tor-only slice, the following `torrc` content is **baked
into the Tor image at build time** (`sidecars/tor/Dockerfile`, T087) and
loaded by the entrypoint (`tor -f /etc/tor/torrc`) at container start.
Tor startup therefore never waits for the control plane (Constitution
Principle II — sol-review B2: Compose starts Tor before the CP can render
a config, so a CP-rendered `torrc` would be a boot-coupling the principle
forbids). Control-plane-rendered `torrc` (atomic write of `tmp` + fsync +
rename into the `stargate-tor-config` volume) is **future work** for a
dynamic-config feature (bridges toggle, live reload) and is deferred by
T089; T037 (`TorrcRenderer`) is deferred with it. The byte-pinned
template below is the single source of truth for v1.

```
# Stargate v1 — Tor sidecar configuration.
# Baked into the Tor image at build time. Do not edit by hand.
# Source: specs/001-tor-route/contracts/torrc.md

SocksPort unix:/run/tor-fabric/private/tor-socks.sock IsolateClientAddr IsolateSOCKSAuth
ControlSocket /var/lib/tor/control/tor-control.sock
CookieAuthentication 1
CookieAuthFileGroupReadable 1
DataDirectory /var/lib/tor
ClientUseIPv6 0
AvoidDiskWrites 1
UseBridges 0

# Logging — diagnostics are discarded before retention (Constitution III).
# Current health comes from the authenticated observer, not retained log lines.
Log notice file /dev/null
SafeLogging 1
```

### Invariants

| # | Invariant                                                                           | Why                                                                                                                                              |
|---|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | `SocksPort` line contains both `IsolateClientAddr` and `IsolateSOCKSAuth`           | FR-011, Principle III — stream isolation by first-party domain depends on `IsolateSOCKSAuth`.                                                     |
| 2 | `SocksPort` is a Unix socket under `/run/tor-fabric/private/`, a Tor-owned 0700 directory | FR-007 — only the hardlinked 0660 socket in the DP fabric root is reachable by the DP group; there is no TCP SOCKS listener. |
| 3 | `ControlSocket` is under `/var/lib/tor/control/`, a Tor-owned 0700 directory, with `CookieAuthentication 1` | Tor's own healthcheck and the contract harness run inside Tor. CP cannot mount this socket or the cookie. T164 gives only the observer a narrow Tor-facing mount. |
| 4 | `CookieAuthFileGroupReadable 1` remains with `CookieAuthentication 1` | Tor's cookie remains in its private DataDirectory. Group readability prepares a narrow observer-only mount under T164; CP no longer has the group or mount. |
| 5 | `ClientUseIPv6 0`                                                                   | FR-011 — avoid dual-stack ambiguity in the local profile; v1 is IPv4-only.                                                                         |
| 6 | `AvoidDiskWrites 1`                                                                 | FR-011, THREAT-MODEL §3.1 — minimise incidental writes; guard state still persists by design (THREAT-MODEL §4.2 "Stargate-specific notes").       |
| 7 | `UseBridges 0` and no `Bridge` lines anywhere in the file                           | FR-011, spec Assumption "No bridges". Bridge support is a separate feature spec.                                                                  |
| 8 | `Log notice file /dev/null` and `SafeLogging 1` | Tor diagnostics are discarded before container capture; the authenticated observer supplies current health without Docker probe history. `SafeLogging 1` remains enabled. |
| 9 | NO `HiddenServiceDir` or `HiddenServicePort` directives                             | This feature is a *client* of onion services, not a service.                                                                                       |
| 10 | NO `ExitPolicy` overrides                                                           | This feature does not run an exit node.                                                                                                            |
| 11 | `DataDirectory /var/lib/tor` is explicit                                            | The image entrypoint runs `tor -f /etc/tor/torrc` WITHOUT `--defaults-torrc /etc/tor/torrc-defaults`, so Debian's defaults file (which would set `DataDirectory /var/lib/tor`) is never loaded (T087 / sol-review B2+M3). Without an explicit directive Tor falls back to its compile-time default of `$HOME/.tor` = `/var/lib/tor/.tor` for USER `tor`, landing the control cookie at `/var/lib/tor/.tor/control_auth_cookie` — not the `/var/lib/tor/control_auth_cookie` the healthcheck and T062's control-port helper assume. Pinning `DataDirectory /var/lib/tor` here makes the cookie path deterministic and keeps guard state on the `stargate-tor-state` volume (mounted at `/var/lib/tor`).                       |
| 12 | NO comments containing per-user data (no labels, no token references, no domains)   | The rendered file is a Principle III boundary — it must contain no per-user content.                                                              |
| 13 | The file ends with a single trailing `\n` (no CRLF, no missing newline at EOF)      | Determinism / byte-for-byte test reproducibility.                                                                                                  |

---

## Contract tests (`tests/contract/torrc/`)

### `render_byte_match_test.go`

Pins the v1 template above as a Go golden constant and cross-checks this
contract document against it byte-for-byte, so any drift between the
image-baked template and the golden fails loudly. The byte-for-byte chain
for v1 is: contract doc == Go golden (this test) == `/etc/tor/torrc`
baked into the Tor image (T087's cold-volume regression test reads the
file out of the image without harness seeding). The Java
`TorrcRenderer.render()` == golden link is **deferred** with T037 to the
dynamic-config feature (T089): the Go contract-test harness is Go-only
per `research.md` §5 (no JVM in the contract-test path), and the v1 slice
no longer ships a Java renderer, so the cross-plane split collapses to a
Go-only chain until dynamic config lands.

### `invariants_test.go`

Parses the golden and asserts each invariant above individually,
including row 11's `DataDirectory /var/lib/tor` directive. This test
gives a clearer diff message than the byte-match test when a directive is
missing or changed.

### `no_bridges_test.go`

Greps the golden for `Bridge`, `obfs4`, `snowflake`,
`webtunnel`. Fails if any of these strings appears anywhere.

### `live_sidecar_test.go`

Spins up the Tor sidecar container with the image-baked config, waits for
bootstrap, then queries the private control socket via `GETCONF SocksPort` and
asserts the response contains `IsolateClientAddr` and `IsolateSOCKSAuth`.
This verifies the config Tor actually loaded matches what the image
baked in. The cold-volume probe retains authenticated bootstrap/cookie-path verification
and asserts that Docker has no health-probe history (T152); the observer supplies current health.
The installer requires its fixed one-shot `--check-ready` sample before declaring the Tor route ready;
running containers and a listening DP alone are insufficient.

### `isolate_socks_auth_effect_test.go`

Spins up the Tor sidecar; issues two SOCKS5 CONNECTs with distinct
usernames; queries the control port for circuit status; asserts the two
streams attached to distinct circuit IDs. This is the same test
described in spec User Story 2 acceptance scenario 1, but as a contract
gate on the `torrc` config Tor loaded: it pins the *behavioral* property
— distinct SOCKS auth identities attach to distinct circuits on the real
sidecar — so a Tor upgrade that ever merges distinct-identity streams
fails here, loudly, at the digest-bump PR's live run. Detecting a
*dropped directive*, by contrast, is the static gates' job, not this
test's: `IsolateSOCKSAuth`'s presence is pinned by invariant #1 via
T029's byte-match and T030's invariants, and T032's live GETCONF proves
Tor loaded what the image baked. (Amended 2026-09-07 per T058's
mutation battery, accepted in SECURITY-DECISIONS.md: on the pinned tor
0.4.9, distinct auth identities isolate even with `IsolateSOCKSAuth`
removed from the config, and identical identities share a circuit with
or without it — so an earlier draft's claim that this test "fails
immediately" on a silent directive drop was empirically false; the
directive stays pinned as cheap defense-in-depth against Tor isolation
defaults changing.)

---

## When this contract changes

Any change to the image-baked `torrc` requires:

1. Updating the file template in this contract document.
2. Updating `render_byte_match_test.go`'s `wantTorrc` golden (and
   `invariants_test.go`'s row assertions) in lock-step.
3. Rebuilding the Tor image so `/etc/tor/torrc` inside it matches the
   new template (T087's cold-volume regression test gates this).
4. Justifying the change in `SECURITY-DECISIONS.md` if the change
   removes a directive that this contract listed as a privacy
   invariant (rows 1, 5, 6, 7, 8, 12).
5. `stargate-redteam` review pass before merge.
