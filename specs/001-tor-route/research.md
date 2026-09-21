# Phase 0 Research — Tor Route v1 Vertical Slice

**Status**: Complete (informs `plan.md` and Phase 1 artifacts)

Each entry follows the Decision / Rationale / Alternatives format. The
section number is referenced from `plan.md`.

---

## 1. Toolchain pins (Go, JDK, Quarkus, Mandrel)

**Decision**: pin the data-plane Go toolchain to the latest `1.26.x` patch
available at the time the scaffolding task lands (`go.mod` `go 1.26` +
`toolchain go1.26.3` as of 2026-05-18). Pin the control-plane to JDK 25 LTS via
`<maven.compiler.release>25` plus Temurin 25 in the CI build matrix. Pin
Quarkus to the 3.33 LTS line (`quarkus.platform.version` property in the
parent POM, managed by the Quarkus BOM). Defer the concrete Mandrel 25
builder image digest pin until the first release tag — the JVM-mode build
is what this feature exercises.

**Rationale**:

- Go 1.26 is the current full-support line (Go's policy: only the two
  latest minor releases receive security backports). The earlier pin
  considered Go 1.23.x; that line reached end-of-support when Go 1.26
  shipped in Feb 2026, so pinning to it now would accept zero security
  backports for the lifetime of v1. `crypto/subtle` constant-time
  primitives (needed for `auth.token`, FR-006), the `slog` package, and
  the `-trimpath` + `-buildvcs=false` byte-reproducible build flags
  (arch §12.1) all continue to work in 1.26.
- JDK 25 LTS + Quarkus 3.33 LTS is the pin set by constitution v1.1.0
  (Sync Impact Report). Quarkus 3.33's platform BOM officially supports
  JDK 25 as a runtime target.
- Temurin is the CI artefact distribution for reproducibility; the
  bytecode-reproducibility property does not depend on a specific
  distribution as long as one is pinned (architecture spec §12.2).
- Mandrel 25 native-image: not load-bearing here; deferred per arch §15
  #9. The constitution Sync Impact Report explicitly defers the Mandrel
  digest to first release tag.

**Alternatives considered**:

- Go 1.25.x (previous full-support line): rejected — adds friction with
  no security benefit; we'd flip the pin again in ~3 months when Go 1.27
  ships and 1.25 drops to security-only.
- Go 1.24.x (security-only as of 1.26's release): rejected — drops to
  end-of-support when 1.27 ships.
- Go 1.23.x (the prior pin, now EOL): rejected — has been EOL since
  Feb 2026; no security backports.
- JDK 21 LTS: rejected — constitution v1.1.0 explicitly moved off 21+.
- Quarkus 3.20.x: rejected — not the LTS line constitution pins.

---

## 2. Mullvad Browser Manifest V2 support window (arch §15 #6)

**Decision**: implement the extension as Manifest V2 with
`proxy.onRequest`. Carry the assumption that Mullvad Browser ships MV2
support throughout the v1 release window. Add a maintenance flag (see
"Follow-up" below) for the v1.5+ extension audit.

**Rationale**: As of 2026-05, Firefox ESR (the engine Mullvad Browser is
built on) supports MV2 and MV3 in parallel. The `proxy.onRequest` API used
by this feature is Firefox-specific (Chromium's MV3 dropped blocking
`webRequest` in favour of `declarativeNetRequest`; neither is equivalent to
`proxy.onRequest`). Mozilla's stated policy is to maintain MV2 indefinitely
for APIs that have no MV3 equivalent. Mullvad Browser's release notes
through 2026 confirm MV2 continues to load.

There is no MV3 migration path for this feature that preserves
per-request routing — `proxy.settings` is a single global proxy. A
declarativeNetRequest-style approach cannot return a per-request SOCKS5
proxy descriptor with a per-request username (which is how stream
isolation is driven).

**Alternatives considered**:

- MV3 with `proxy.settings` + an in-extension PAC blob: rejected. PAC
  cannot set SOCKS5 username per request, so the stream-isolation
  property (FR-002) would not hold.
- MV3 with `dns.setMode` + manual proxy chain: rejected. Same issue
  plus more browser-level state that the extension does not need to
  read.
- Wait-and-see (defer the feature until MV3 supports `proxy.onRequest`):
  rejected. Mozilla has not signalled this is on the roadmap, and
  Stargate's first-class browser is Firefox-ESR-based.

**Follow-up**: amend `specs/000-architecture/spec.md` §15 #6 to mark this
as resolved-for-v1 with a maintenance entry noting we should re-verify
during each Mullvad Browser major-version bump.

---

## 3. Control-plane scope in this slice

**Decision**: build a *headless* control plane for this feature. Modules
populated: `api/` (gRPC server only), `core/` (token loader, sidecar
monitor, healthcheck), `persistence/` (audit-log writes; entity classes
for the full schema arch §6 created up-front but only `audit_log` written
by this feature), `runtime/` (`@QuarkusMain`, packaging). `ui/` is a stub
that responds to a Compose healthcheck path (`GET /healthz` → 200) and
serves nothing else. No admin REST endpoints. No Qute admin templates.

**Rationale**: the spec (Assumptions section) defers the admin dashboard
to a later feature, but the control plane must run because (a) it is the
process that reads `tokens.yaml` and pushes hashes via `ReloadTokens`
(FR-013 / FR-018) and (b) it owns the sidecar lifecycle monitoring that
emits `SidecarEvent` (FR-014 / arch §5.2). The minimal subset that
satisfies these without dragging in admin UI surface is the gRPC service
plus token loader plus a healthcheck endpoint.

**Alternatives considered**:

- Skip the control plane entirely, have the data plane read `tokens.yaml`
  directly: rejected. Principle II forbids merging the planes. The
  data plane is Go and should not pick up YAML parsing for what is a
  control-plane responsibility.
- Build the full admin UI in this feature: rejected. That is explicitly
  out of scope per spec Assumptions and would massively expand the
  vertical.
- Ship a CLI tool that runs the token loader once and exits, with no
  long-running control plane: rejected. The control plane still needs
  to be alive to emit `SidecarEvent`s and answer `ReloadTokens` on
  demand (even though in v1 the demand is one-shot at startup, the
  gRPC service must be reachable for the data plane to retry handshake
  per arch §5.5).

---

## 4. Reconciliation of arch §11 (Live token reload) with FR-018 (startup-only)

**Decision**: keep both behaviours. Document the relationship clearly:

- The **inter-plane RPC** `ReloadTokens` is a Live operation in the data
  plane (arch §11 row 1). New token generations are atomically swapped
  in; the data plane never drops connections to apply a new generation.
- The **v1 upstream cadence** for the source-of-truth file is
  startup-only: the control plane reads `tokens.yaml` once at startup,
  hashes the entries, and pushes them via `ReloadTokens` (FR-018).
  Adding or revoking a token therefore requires restarting the
  control-plane container.
- During the control-plane restart, the data plane continues serving
  with its previous in-memory token list (Principle II). When the
  control plane reconnects and pushes the new generation, the data
  plane Live-applies it.

**Rationale**: `§11` describes the *capability* of the inter-plane
contract; FR-018 describes the *v1 input shape*. The Live capability is
what makes future features (dashboard token UI, fs-watch, SIGHUP) drop in
without a contract change; the v1 input shape is the smallest viable
ingest path. Each governs a different boundary.

**Alternatives considered**:

- Add fs-watch in v1: rejected — out of scope per spec.
- Add SIGHUP in v1: rejected — same reason.
- Skip `ReloadTokens` in v1 and have the data plane read the token
  list at startup directly from a control-plane snapshot: rejected.
  That couples the v1 boot order tightly and removes the Live capability
  that later features rely on; better to exercise the RPC end-to-end now.

---

## 5. Contract-test harness language

**Decision**: write `tests/contract/tor/`, `tests/contract/error-template/`,
and `tests/contract/torrc/` in Go.

**Rationale**:

- Stays in the same toolchain as the data plane — single `go test
  ./...` runs the data-plane unit, integration, and contract tests
  together in CI.
- Docker SDK for Go (`github.com/docker/docker/client`) is mature and
  the data-plane build environment already needs it for the
  reproducibility test runner.
- `tests/contract/tor/` exercises the SOCKS5 surface; that is exactly
  what the data plane's outbound `forward/tor.go` does — sharing test
  helpers across the two is straightforward.
- The contract tests act as gates on sidecar image digest bumps;
  matching their language to CI's primary test runner avoids a separate
  CI job.

**Alternatives considered**:

- Java + Quarkus Test: rejected. Pulls a JVM into a path otherwise
  dominated by Go binaries and adds CI complexity. Tor SOCKS5 contract
  is intrinsically a Go-data-plane property.
- Shell + curl + nc: rejected. Hard to express "byte-for-byte
  template match" or "leak corpus scan" in shell cleanly; brittle
  against minor whitespace.
- Polyglot (Java for `error-template/`, Go for `tor/`): rejected.
  Splits the gate across runners.

---

## 6. Extension bearer-token storage (arch §14.4 / arch §15 #8)

**Decision**: store the bearer token in `storage.local` for v1. Display
a visible UX warning in the options page noting the residual risk that
`storage.local` is reachable to any other extension that obtains
`storage` permission on the same profile (it isn't, in practice, because
`storage.local` is per-extension — but the on-disk file is readable by
any process with filesystem access to the profile).

**Rationale**: WebExtensions on Firefox ESR (Mullvad Browser's engine)
expose no first-class credential-grade storage API to extensions.
The browser's built-in password manager is for form-filled credentials
only and is not addressable via the extension API surface. `storage.local`
is the only path that the API offers, and its per-extension isolation is
the correct mitigation against *cross-extension* access; the residual
risk is filesystem-level access, which is the same threat any locally
stored secret faces (THREAT-MODEL §2.8 OS-level attacker — out of scope).

**Alternatives considered**:

- Use `chrome.identity` / WebAuthn for token presentation: rejected. The
  v1 bearer token is a 32-char hex string, not a WebAuthn assertion;
  swapping to WebAuthn requires the admin enrollment flow which is a
  separate feature.
- Encrypt the token at rest with a passphrase the user enters on browser
  start: rejected. Adds significant UX friction for a loopback-bound
  proxy port whose threat model already accepts local-execution attackers
  as game-over (THREAT-MODEL §3.1).
- Defer the feature until a credential API exists: rejected. Mozilla has
  not signalled work on this and Stargate cannot wait.

**Follow-up**: update arch §14.4 to mark this resolved-for-v1, with
SECURITY-DECISIONS.md carrying the rationale — see the existing
§"2026-07-04 — Tor sidecar trust rationale (FR-015)" entry (T017).

---

## 7. Throughput-test methodology for SC-005 (≥200 concurrent CONNECTs)

**Decision**: SC-005 is measured against a **synthetic SOCKS5 backend**
that mimics the Tor sidecar's accept-and-relay surface. The synthetic
backend lives at `tests/integration/fake_socks5_tor.go` and exposes a
SOCKS5h endpoint that accepts CONNECTs, allocates a logical "circuit
id" per distinct SOCKS5 username, and echoes back a known byte pattern.
The real Tor sidecar is used for the SC-001 walkthrough, the SC-003 DNS-
leak capture, and the SC-002 corpus (100 sequential CONNECTs) which is
within the Tor network's normal load envelope.

**Rationale**:

- The property under test is the data plane's forwarding hot path —
  zero per-request allocation retained beyond request lifetime, ≥200
  concurrent CONNECTs without head-of-line blocking. That property
  does not depend on the upstream being the real Tor network.
- Driving 200 concurrent live circuits against `duckduckgogg42xjoc72...`
  (the reference target onion) would (a) flood the destination
  service, (b) consume a disproportionate share of Tor guard capacity
  for what is a throughput test, and (c) make the test non-reproducible
  because Tor circuit-build latency varies.
- The synthetic backend exposes the same SOCKS5 surface, so the data
  plane's forwarding code is exercised identically to production.

**Alternatives considered**:

- Drive against a local `chutney` Tor test network: rejected. Adds a
  large dependency, slows the test suite materially, and exercises
  more than the property under test.
- Drive against the real Tor with rate-limiting: rejected. Still
  abuses guards, and rate-limiting bounds the concurrency under
  test below the 200 target.
- Drop SC-005 to a unit-test mock: rejected. SC-005 needs real
  goroutine and socket pressure to validate the forwarding hot path;
  a unit-mock cannot exercise the network primitives.

---

## 8. Scope split for `scripts/stargate init` in this feature

**Decision**: deliver only the subset of `init` (arch §9.1) needed to
bring up the local stack for this feature. Specifically:

- Preflight (docker present, docker compose v2 present, socket
  reachable) — **delivered**.
- Profile selection — **local only** in this feature; no `--profile`
  flag yet (the script hard-codes `compose/docker-compose.local.yml`).
- Key generation (inter-plane ed25519 pair) — **delivered**, populates
  `stargate-keys` volume with 0600 perms.
- Admin enrollment URL / WebAuthn relying-party setup —
  **deferred to the admin-UI feature**.
- Compose-up with bounded healthcheck wait — **delivered**.
- Verification (subset of contract tests against the live stack) —
  **delivered** for the Tor SOCKS5 endpoint only; other sidecars are
  not in scope.
- Status table — **delivered** for the components present in this
  feature (data plane, control plane, Tor sidecar).
- Failure-mode error codes (preflight=10, key-gen=20, compose=30,
  healthcheck=40, verify=50) — **delivered** (the codes are stable
  contract surface; later features add behind them).

**Rationale**: the spec assumes the operator runs `init` to populate the
inter-plane keys and bring up the stack. That assumption holds because
this feature ships exactly the subset of `init` needed for the local-
profile slice. Deferring the admin enrollment / `--force` repair /
multi-profile logic keeps the cone manageable and matches the
"vertical slice" framing.

**Alternatives considered**:

- Defer all of `init` to the admin-UI feature: rejected. Without `init`
  the operator has no way to generate the inter-plane keys, which the
  gRPC mutual-TLS handshake requires.
- Ship full `init` now: rejected. Pulls the admin enrollment surface
  into this slice unnecessarily.

---

## 9. Historical `AUTH_REQUIRED` HTTP decision (superseded by T172)

The earlier two-response-shape decision assumed HTTP CONNECT was supported on
Tor port 8881. T147 showed its upstream NO_AUTH path lacks the required
initiating-site/profile partition. The selected T172 contract supports only
authenticated SOCKS5: RFC 1929 auth failure is `0x01 0xFF` and close; HTTP
first byte `C` closes without response, authentication, counters or upstream
socket. The HTML template remains a renderer-only future format. Current code
still follows the earlier decision until T173; this section is history, not
an HTTP success/error promise.

---

## 10. JS test toolchain pin (added by /speckit-analyze C1 remediation)

**Decision**: pin **Node 20 LTS** as a CI-only dependency for extension
JavaScript unit tests. Use Node's built-in `node:test` runner (no third-
party JS libraries) with `node:assert` for assertions. Browser-style
global scripts (MV2 `background.scripts` entries) are loaded into the
test by `vm.runInNewContext()` with a synthesized `browser` global —
no source-code wrapper (UMD, conditional `module.exports`, etc.) is
added to the extension to make it testable.

**Rationale**:

- C1 remediation requires a JS unit test for `extension/background/
  hardening.js` (FR-004; Principle VII). Some JS-side test runner is
  unavoidable for any unit-test strategy; the choice is which one.
- `node:test` is stable in Node 20 LTS and 22 LTS. Built-in API for
  `describe`/`it`, structured output, optional JUnit XML reporter for
  CI. Zero npm install — no `package.json` required for the test
  files when used with `vm` loading.
- The "no third-party JS deps" constraint in plan.md §"Technical
  Context" is about the **extension's runtime code** (the bytes that
  ship to users), not about CI tooling. A CI-only Node binary is the
  same category of dep as Go, Java, or Docker — all already pinned
  for CI. Principle VI's supply-chain motivation (avoid npm on a
  privacy-critical component) is not violated.
- MV2 background scripts are loaded as browser globals, not ES
  modules. `vm.runInNewContext()` with a synthesized `browser` global
  keeps `hardening.js` (and any sibling background script added
  later) authored in idiomatic browser style — no UMD wrapper, no
  test-only export branch. The vm approach contains the
  ESM/CJS/global mismatch in the test file, not in the production
  code.

**Alternatives considered**:

- Hand-rolled assertion harness (`function it(name, fn) { ... }` over
  `node:assert`): rejected. Same Node-as-CI-dep, fewer features (no
  JUnit XML for CI, no parallel test execution if needed later), and
  a maintenance surface that `node:test` provides for free.
- `web-ext` (Mozilla's official extension tooling): rejected. Test
  surface is anaemic; pulls a large npm tree; arguably violates the
  "no third-party JS deps" principle even for CI use.
- Karma / Mocha / Jest / Vitest: rejected. All require npm installs
  and dependency trees; `node:test` reaches the same destination with
  zero install. No JSDOM-style browser-env simulation is needed
  because the test mocks the `browser` global directly.
- Hand-driven verification only (markdown checklist like T034a /
  T077): rejected. FR-004 is privacy-critical (Principle III
  hardening invariants); a release-cadence check is too weak a
  regression gate for code that gates whether routing happens at
  all.
- No JS-side tests; document Principle VII waiver in
  SECURITY-DECISIONS.md: rejected. The hardening audit is the
  Principle III enforcement point for the extension; a waiver would
  set a precedent that extension privacy code can ship without
  tests.

**Follow-up**: when a second extension JS test task lands (e.g.,
router.js block-flag verification, currently surfaced as a separate
gap from C1 in the analyze report), reuse the `vm.runInNewContext` +
`browser` mock pattern. If a third sibling materializes, consider
extracting the mock to a shared `extension/test-mocks/browser.js`.

---

## 11. Minimum-subset `GetStatus` RPC in v1 proto (added by /speckit-analyze F3 remediation)

**Decision**: declare a minimum-subset `GetStatus` RPC in v1's proto
now — `rpc GetStatus(StatusRequest) returns (StatusResponse);` with
`StatusRequest {}` and `StatusResponse { repeated RouteCounter
counters; }` and `RouteCounter { string route; uint64 hour_bucket;
uint64 request_count; uint64 byte_count; }`. The RPC is hosted by the
data plane on `/run/stargate/dp.sock` (T007 / T045) and is exercised
only by the contract tests T025c and T025d in this feature. The
production CP→DP pull and SQLite persistence remain deferred to the
admin-UI feature, exactly as `data-model.md` §3 already records.

**Rationale**:

- `data-model.md` §3 already commits to "in v1 the counters live in
  the data plane's process memory only and are lost on DP restart"
  and lists `GetStatus` under `contracts/control-grpc.md` "RPCs
  explicitly NOT used by this feature". That records the
  *production* deferral. The choice here is the orthogonal question
  of where the RPC's *declaration* lives — `stargate.v1` proto now,
  or `stargate.v2` proto later.
- Declaring it in `stargate.v1` is a purely additive minor-version
  change (constitution Inter-Plane Contract section explicitly
  permits additive minor changes; the gate is a backwards-compat
  test). Declaring it in `stargate.v2` would require a major-version
  bump — a much larger ceremony for what is one new RPC plus two
  messages.
- T025c (auth-fail counter non-increment) and T025d (auth-pass
  counter increment) need to read counters from the data plane to
  assert the FR-008 invariant from both directions. The two clean
  paths to do that are (a) the public gRPC surface the admin-UI
  feature will eventually consume, or (b) a test-only side channel
  (e.g. a `/debug` HTTP endpoint, an exported package variable, a
  Unix-socket probe distinct from the gRPC server). Path (a) keeps
  the test exercising the same observation surface production will
  use; path (b) adds a parallel test-only surface with its own
  privacy review burden and risks drift from the eventual
  production path.
- The cost of (a) for the lifetime of this feature is a single
  always-on gRPC handler that returns the current in-memory counter
  snapshot. No new privacy surface — the counters are already
  hour-bucketed aggregates (FR-008) and the UDS is in
  `stargate-ipc`, not host-published.

**Alternatives considered**:

- **Defer the declaration to `stargate.v2`** (the path before this
  decision): rejected. Forces a major-version bump in the next
  feature for a purely additive RPC; forces T025c/T025d to use a
  test-only sideline that the production observation path will not
  share.
- **Test-only `/debug` HTTP endpoint on the data plane**: rejected.
  Adds a parallel network listener to the DP whose privacy
  properties (what it leaks, who can dial it, whether it survives a
  bind-safety regression) need their own reasoning and their own
  contract tests. The gRPC surface already has a transport-invariant
  contract (`contracts/control-grpc.md` §"Transport invariants",
  T022) that covers all the access-control concerns.
- **Skip counter-invariant tests in v1 entirely**: rejected. FR-008
  is privacy-critical (Principle III's "Logs contain only aggregate
  counters at ≥1 hour resolution"). Principle VII's discipline
  table puts auth and logging-restraint code in the test-first
  mandatory tier; deferring the gate would ship the invariant
  without a regression line.
- **Inline the counter probe in the data-plane test binary** (a
  test-only Go API call bypassing the RPC): rejected. The data
  plane is built with `-trimpath` and ships as the production
  binary; adding a build-tag-gated test surface diverges the test
  binary from production and weakens the SC-005 perf-pass
  guarantee.

**Forward note (out of scope for v1)**: when the admin-UI feature
lands, it wires the CP-side caller and the SQLite persistence layer
on top of this same RPC declaration. The protobuf contract above is
the long-lived shape; the only follow-up is CP-side code, not a
schema change. `T025c` and `T025d` remain valid at that point and
should keep passing without modification.

---

## Outstanding open questions (none blocking)

All architectural open questions enumerated in arch §15 that affect this
feature are resolved in §1–§9 above. The remaining open questions in arch
§15 (Nym, signing tool, backup encryption, IPFS) do not affect this
feature.

The constitution Sync Impact Report's deferred Mandrel 25 digest pin is
intentionally left to first release tag — see §1.
