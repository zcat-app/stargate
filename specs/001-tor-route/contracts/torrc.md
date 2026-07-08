# Contract — Rendered `torrc` (v1 of Tor Route)

**Status**: Phase 1 contract document

**Scope**: defines the byte-level invariants of the Tor sidecar's
`torrc` configuration file rendered by the control plane for v1 of the
Tor route. Tested at `tests/contract/torrc/`.

**Source**: FR-011, arch §8 (Tor row).

---

## Rendered file

The control plane renders the following `torrc` content into the
`stargate-tor-config` named volume at startup. The file is written
atomically (write to `torrc.tmp`, fsync, rename). The Tor sidecar reads
it on container start.

```
# Stargate v1 — Tor sidecar configuration.
# Rendered by control plane. Do not edit by hand.
# Source: specs/001-tor-route/contracts/torrc.md

SocksPort 0.0.0.0:9050 IsolateClientAddr IsolateSOCKSAuth
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
ClientUseIPv6 0
AvoidDiskWrites 1
UseBridges 0

# Logging — Notice level to stdout for healthcheck parsing only.
# Stargate does NOT consume Tor log lines as request data.
Log notice stdout
SafeLogging 1
```

### Invariants

| # | Invariant                                                                           | Why                                                                                                                                              |
|---|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | `SocksPort` line contains both `IsolateClientAddr` and `IsolateSOCKSAuth`           | FR-011, Principle III — stream isolation by first-party domain depends on `IsolateSOCKSAuth`.                                                     |
| 2 | `SocksPort` binds `0.0.0.0:9050` (container-internal)                               | arch §4.2 — the port is reachable only on the compose bridge network, never published to the host. The bind address is `0.0.0.0` *inside* the container; the compose file does not map the port to the host. Explicit `0.0.0.0:9050` (rather than bare `9050`) is defensive: the bind-address is part of the byte-match contract, so a future Tor release that changes the default bind-address still produces the same rendered file and a still-passing byte-match test. |
| 3 | `ControlPort` is present on `0.0.0.0:9051` with `CookieAuthentication 1`            | FR-011 + FR-016 — the contract test for stream isolation queries the control port; cookie auth keeps that channel privileged.                     |
| 4 | `CookieAuthFileGroupReadable 1` is present alongside `CookieAuthentication 1`       | Required so the cookie file is readable by callers sharing the volume's group (mode `0640` instead of Tor's default `0600 tor:tor`). Without it, the contract-test harness at T062 cannot read the cookie without privilege escalation. |
| 5 | `ClientUseIPv6 0`                                                                   | FR-011 — avoid dual-stack ambiguity in the local profile; v1 is IPv4-only.                                                                         |
| 6 | `AvoidDiskWrites 1`                                                                 | FR-011, THREAT-MODEL §3.1 — minimise incidental writes; guard state still persists by design (THREAT-MODEL §4.2 "Stargate-specific notes").       |
| 7 | `UseBridges 0` and no `Bridge` lines anywhere in the file                           | FR-011, spec Assumption "No bridges". Bridge support is a separate feature spec.                                                                  |
| 8 | `Log notice stdout` and `SafeLogging 1`                                             | Notice-level logs are sufficient for the healthcheck (it looks for "Bootstrapped 100%"); `SafeLogging 1` is Tor's directive to scrub sensitive fields from logs. |
| 9 | NO `HiddenServiceDir` or `HiddenServicePort` directives                             | This feature is a *client* of onion services, not a service.                                                                                       |
| 10 | NO `ExitPolicy` overrides                                                           | This feature does not run an exit node.                                                                                                            |
| 11 | NO `DataDirectory` override (default `/var/lib/tor` from the Debian package)        | The default is mounted from `stargate-tor-state` for guard persistence; an override would risk pointing somewhere ephemeral.                       |
| 12 | NO comments containing per-user data (no labels, no token references, no domains)   | The rendered file is a Principle III boundary — it must contain no per-user content.                                                              |
| 13 | The file ends with a single trailing `\n` (no CRLF, no missing newline at EOF)      | Determinism / byte-for-byte test reproducibility.                                                                                                  |

---

## Contract tests (`tests/contract/torrc/`)

### `render_byte_match_test.go`

Pins the v1 template above as a Go golden constant and cross-checks this
contract document against it byte-for-byte, so any drift between the
rendered template and the golden fails loudly. The control plane's
`TorrcRenderer.render()` output is gated separately, in Java, by T037's
JUnit test asserting `render()` equals the same golden — the Go
contract-test harness is Go-only per `research.md` §5 (no JVM in the
contract-test path), so the byte-for-byte chain is split across the two
languages: contract doc == Go golden (this test) == Java `render()`
output (T037).

### `invariants_test.go`

Parses the rendered output and asserts each invariant above
individually. This test gives a clearer diff message than the byte-
match test when a directive is missing or changed.

### `no_bridges_test.go`

Greps the rendered output for `Bridge`, `obfs4`, `snowflake`,
`webtunnel`. Fails if any of these strings appears anywhere.

### `live_sidecar_test.go`

Spins up the Tor sidecar container with the rendered config, waits for
bootstrap, then queries the control port via `GETCONF SocksPort` and
asserts the response contains `IsolateClientAddr` and `IsolateSOCKSAuth`.
This verifies the config Tor actually loaded matches what we rendered.

### `isolate_socks_auth_effect_test.go`

Spins up the Tor sidecar; issues two SOCKS5 CONNECTs with distinct
usernames; queries the control port for circuit status; asserts the two
streams attached to distinct circuit IDs. This is the same test
described in spec User Story 2 acceptance scenario 1, but as a contract
gate on the `torrc` rendering — if `IsolateSOCKSAuth` were silently
dropped, this test fails immediately.

---

## When this contract changes

Any change to the rendered `torrc` requires:

1. Updating the file template in this contract document.
2. Updating `render_byte_match_test.go` in lock-step.
3. Justifying the change in `SECURITY-DECISIONS.md` if the change
   removes a directive that this contract listed as a privacy
   invariant (rows 1, 5, 6, 7, 8, 12).
4. `stargate-redteam` review pass before merge.
