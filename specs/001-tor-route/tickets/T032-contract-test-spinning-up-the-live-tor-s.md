---
id: T032
title: 'Contract test spinning up the live Tor sidecar with the rendered confi'
status: done
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T032
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh
parallel: true
files_budget: 3
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - spec.md §FR-011
  - spec.md §FR-012
  - contracts/torrc.md §"Rendered file"
  - contracts/torrc.md §"Invariants" row 1
  - contracts/torrc.md §"live_sidecar_test.go"
decision_refs: []
reviews: { round: 1, date: 2026-07-11, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-07-11
  verdict: PASS
---

# T032: Contract test spinning up the live Tor sidecar with the rendered confi

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test spinning up the live Tor sidecar with the rendered config and asserting `GETCONF SocksPort` returns a value containing `IsolateClientAddr` and `IsolateSOCKSAuth` in `tests/contract/torrc/live_sidecar_test.go`.

## Analysis

**Required** — `privacy_critical: true`. Property map per
`docs/process/analysis.md`.

### Goal restated for grounding

Bring up the live Tor sidecar with the rendered v1 `torrc`, wait for
bootstrap, then query the cookie-authenticated control port with
`GETCONF SocksPort` and assert the response carries both
`IsolateClientAddr` and `IsolateSOCKSAuth`. Closes the gap between
"the rendered file contains the flag" (T029 byte-match / T030 invariants)
and "Tor actually loaded the flag" — a syntactically valid torrc whose
flag Tor silently ignores (typo, alias change, directive drift across
Tor versions) would pass every static gate and still break per-first-party
stream isolation. FR-011 + contracts/torrc.md invariant #1 load-bearing
on `IsolateSOCKSAuth` (Principle III).

### Must hold

- The bytes that seed the sidecar's config volume are **exactly** the
  package-level `wantTorrc` golden T029 pins — no third transcription.
  T032 reuses the constant from `render_byte_match_test.go` directly.
- Tor reaches `BOOTSTRAP PROGRESS=100` with the rendered config: the
  torrc parses cleanly AND Tor starts (a syntactically invalid torrc or
  an unrecognised directive fails bootstrap or refuses to start — the
  bootstrap wait double-duty as a "Tor accepted the rendered config" gate).
- `GETCONF SocksPort` over the **cookie-authenticated** control port
  returns a value containing both `IsolateClientAddr` and
  `IsolateSOCKSAuth` — what Tor loaded, not what we rendered.
- The control-port exchange uses cookie auth (never null auth): the test
  itself preserves FR-012's "ControlPort reachable only via the cookie
  file" property — we never send an unauthenticated control command.

### Gated (no standing human vigilance needed)

- T029 `TestRenderedTorrcByteMatch` gates doc ↔ golden byte-equality;
  T030 `TestTorrcInvariants` gates each parsed directive row; T031
  `TestNoBridgesOrPluggableTransports` gates the no-bridge sweep. T032
  completes the chain at the live-sidecar layer.
- T019b `TestTorPortExposure` gates FR-012 (9050/9051 not published to
  host). T032 does NOT re-assert that — different contract.
- `go vet` + `go build` (tests/contract module) gate syntactic surface;
  verify.sh license-header gate gates SPDX on the new file.

### Residue

- **The seeded torrc equals what T037 will render.** T032 seeds the
  volume with T029's `wantTorrc`; a drift between seed and T037's render
  requires T029 AND T037 to fail together (double-fault). Not promotable
  to a stronger gate without coupling T032 to T037's unbuilt Java
  renderer — which would defeat T032's purpose (an independent
  live-sidecar gate that lands BEFORE the renderer per Principle VII).
  Accepted.
- **Control-port exchange via `docker exec tor` (nc + coreutils).**
  Couples T032 to the tor image shipping `netcat-openbsd` + `od`/`tr`/
  `printf` — the same toolchain the Dockerfile HEALTHCHECK depends on,
  so a future image strip removes both together (caught at image-build /
  HEALTHCHECK-fail time). T062 will land a Go-side TCP+cookie client in
  Phase 4; T032 (Phase 3) cannot depend on it. Accepted; flagged for
  re-evaluation when T062 lands.
- **Bootstrap within the test deadline.** Tor bootstrap time depends on
  the host network + live Tor network. A partition or slow guard
  selection could exceed the bounded deadline (15m) for non-contract
  reasons. We surface the bootstrap-phase response in the failure
  message for diagnosis. Environmental, not a contract gap.
- **PRE-EXISTING T014 bug discovered at /start: tor's effective
  DataDirectory is `/var/lib/tor/.tor`, not `/var/lib/tor`.** The tor
  image ENTRYPOINT (`tor -f /etc/tor/torrc`, sidecars/tor/Dockerfile:124)
  does NOT pass `--defaults-torrc /etc/tor/torrc-defaults`, so Debian's
  defaults file (which would set `DataDirectory /var/lib/tor`) is never
  loaded — tor falls back to its compile-time default of `$HOME/.tor` =
  `/var/lib/tor/.tor` for USER tor (HOME=/var/lib/tor). The cookie
  lands at `/var/lib/tor/.tor/control_auth_cookie`, not the
  `/var/lib/tor/control_auth_cookie` the Dockerfile HEALTHCHECK
  (sidecars/tor/Dockerfile:136) hardcodes. The HEALTHCHECK would
  therefore ALWAYS fail, cascading via FR-014 (UNHEALTHY event →
  routeEnableMask[TOR] DISABLED → ROUTE_DOWN for every request).
  THREE documents carry the now-known-wrong path:
  sidecars/tor/Dockerfile:136, data-model.md:336, and
  contracts/torrc.md invariant #11's comment. T032 works around this in
  the test via `find /var/lib/tor -name control_auth_cookie` (robust to
  any DataDirectory location) but does NOT fix the underlying defect —
  that is T014's scope. **Follow-up filed as T087.** The `find`
  workaround is accepted for T032 because the contract (invariant #11)
  pins "NO DataDirectory override" — which is satisfied — not a
  specific DataDirectory path.

### Why seed the volume directly (not via the control plane)

`stargate-control` is not buildable yet (no `.java` files under
`control-plane/` — same content-gating state T019b self-skips on for
`stargate-dp`). T032's contract is "given the rendered torrc, Tor loads
these flags" — NOT "the control plane renders correctly" (that is T037,
gated by T029 byte-match + T037's JUnit test). Seeding the
`stargate-tor-config` named volume with the golden bytes isolates the
Tor-side load behaviour from the rendering path. When T037 lands, the
seed step is redundant for the rendering path but T032 still verifies
the Tor-side load independently — two failure modes, two tests.

### Why `docker exec tor` (not a Go TCP dial to `tor:9051`)

The cookie file lives on the `stargate-tor-state` volume, mounted only
into the tor service. A bridge-network probe container can dial
`tor:9051` (T019b sub-test (c) proves reachability) but cannot read the
cookie to authenticate. Running the AUTHENTICATE+GETCONF+QUIT exchange
inside the tor container — as USER tor, which owns the cookie — mirrors
the Dockerfile HEALTHCHECK exactly and keeps T032 decoupled from T062.

## Acceptance

**File**: `tests/contract/torrc/live_sidecar_test.go` — same `torrc`
package as T029/T030/T031; reuses the package-level `wantTorrc` golden
pinned by T029 (no third transcription).

**Named test**: `TestLiveSidecarGETCONFSocksPort` with subtests:

- `TorBootstrapsWithRenderedTorrc` — the rendered torrc seeds the
  `stargate-tor-config` named volume before the tor container starts
  (`docker compose up --no-start tor` → SDK label lookup of the volume →
  ephemeral digest-pinned alpine seed container writes `wantTorrc` to
  `/etc/tor/torrc` mode 0644 via stdin → `docker compose up -d tor`);
  then polls `GETINFO status/bootstrap-phase` (via `docker exec tor`,
  cookie-authenticated, same exchange as the Dockerfile HEALTHCHECK)
  until `PROGRESS=100` or a 5-minute deadline.
- `GETCONFReportsIsolateClientAddr` — `GETCONF SocksPort` response
  (parsed in Go from the `docker exec tor nc 127.0.0.1 9051` output)
  contains the token `IsolateClientAddr`.
- `GETCONFReportsIsolateSOCKSAuth` — same response contains the token
  `IsolateSOCKSAuth` (the privacy-load-bearing half of invariant #1).

**Runnable command** (manual until T076 wires Go contract tests into
verify.sh; same self-invocation model as T029/T030/T031):

```
cd tests/contract && go test ./torrc/ -run TestLiveSidecarGETCONFSocksPort -v -timeout 15m
```

**Self-skip conditions** (mirror T019b): docker daemon unreachable
(`cli.Ping` fails), docker CLI not on PATH. Do NOT skip on control-plane
unbuilt — the test seeds the volume directly and has no CP dependency.

**Conventions reused from T019b** (`tests/contract/tor/port_exposure_test.go`):
`composeProject` namespacing every compose invocation under a test-local
project name; `t.Cleanup` running `docker compose down --volumes
--remove-orphans` best-effort; digest-pinned alpine probe image for the
seed container (reuse the same `probeImage` constant value); SDK
label-based lookup for the compose-managed volume name (avoid the
undocumented `<project>_<name>` mangling).

## Out-of-scope

- T037 (control plane renders torrc into the volume): T032 seeds the
  volume with the golden bytes directly; the rendering path is gated
  separately by T029 + T037's JUnit test.
- T062 (cookie-authenticated Go control-port client, Phase 4): T032 uses
  `docker exec tor` mirroring the Dockerfile HEALTHCHECK; T062 lands
  later and may refactor T032 to use it.
- FR-012 port-exposure (host publication of 9050/9051): gated by T019b.
- A live-sidecar bridge/pluggable-transport sweep: the rendered-file
  invariant is gated by T031; a runtime `GETCONF UseBridges` assertion is
  not in v1's threat-model surface (the rendered-file gate is what v1
  pins).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

### Green run log (2026-07-11, round-1 implementation)

Manual invocation (not yet wired into verify.sh — T076's scope):

```
cd tests/contract && go test ./torrc/ -run TestLiveSidecarGETCONFSocksPort -v -timeout 15m

=== RUN   TestLiveSidecarGETCONFSocksPort
    live_sidecar_test.go:190: seeded 487-byte rendered torrc into volume stargate-t032-test_stargate-tor-config
=== RUN   TestLiveSidecarGETCONFSocksPort/TorBootstrapsWithRenderedTorrc
    live_sidecar_test.go:215: Tor bootstrapped: 250 OK
        250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
        250 OK
        250 closing connection
    live_sidecar_test.go:226: GETCONF SocksPort response:
        250 OK
        250 SocksPort=0.0.0.0:9050 IsolateClientAddr IsolateSOCKSAuth
        250 closing connection
=== RUN   TestLiveSidecarGETCONFSocksPort/GETCONFReportsIsolateClientAddr
=== RUN   TestLiveSidecarGETCONFSocksPort/GETCONFReportsIsolateSOCKSAuth
--- PASS: TestLiveSidecarGETCONFSocksPort (7.80s)
    --- PASS: TestLiveSidecarGETCONFSocksPort/TorBootstrapsWithRenderedTorrc (6.40s)
    --- PASS: TestLiveSidecarGETCONFSocksPort/GETCONFReportsIsolateClientAddr (0.00s)
    --- PASS: TestLiveSidecarGETCONFSocksPort/GETCONFReportsIsolateSOCKSAuth (0.00s)
PASS
```

The GETCONF response confirms Tor loaded the rendered torrc and reports
both isolation flags. The single-keyword GETCONF reply uses the `250 `
(space) separator — the parser accepts both `250 ` and `250-` for
forward-compatibility with the continuation-line form.

The cookie was located at `/var/lib/tor/.tor/control_auth_cookie` (not
`/var/lib/tor/control_auth_cookie`) — see §Residue for the pre-existing
T014 bug and the T087 follow-up.
