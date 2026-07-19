# Stargate design and implementation review

**Reviewed:** 2026-07-11  
**Tree:** `001-tor-route` at `d30ace6`  
**Scope:** binding project rules, architecture and threat model, feature 001
specification/plan/contracts/tickets, implemented production code, Compose and
installer code, current tests, and workflow tooling.

## Executive summary

The project has unusually explicit privacy invariants and several strong
tests-first artifacts. The current implementation is still scaffolding: 43 of
115 tickets are marked done, while the listener, forwarder, token verifier,
control-plane runtime, and extension are not implemented. That incompleteness
is not itself a finding.

The review did find release-blocking contradictions that should be resolved
before implementing the remaining vertical slice:

1. The local installer/Compose path cannot work as written. It omits the env
   file, writes keys into a different volume from the one Compose mounts,
   inspects nonexistent container names, does not provision writable volume
   ownership for non-root services, and starts Tor before the control plane has
   rendered Tor's configuration.
2. Cold-start route gating makes the data plane depend on the control plane,
   contrary to binding Constitution Principle II.
3. The browser extension cannot inspect the raw DoH and HTTP/3 preferences
   named by the design through the declared WebExtension APIs. The mock-based
   test plan invents an API surface that Firefox does not expose.
4. Per-request Argon2id verification can allocate about 12.8 GiB for 200
   simultaneous one-token authentications. The performance model accounts for
   CPU scheduling but not concurrent memory allocation.
5. Token generation/state persistence is underspecified. A control-plane
   restart has no defined source for a higher generation, and the missing-file
   path pushes an empty generation that revokes the data plane's last-known
   tokens.
6. The single green gate does not run any Go contract or integration module.
   Several completed privacy-critical tickets therefore have no standing
   regression gate.

These are design defects, not reasons to discard the architecture. Most can be
fixed more cheaply now, before the pending implementation tickets make the
contracts expensive to change.

## Review method

Every finding below was treated as a hypothesis. For each one, the review
states what evidence would have disproved it and what was actually found.

Checks performed:

- Read `.specify/memory/constitution.md`, `THREAT-MODEL.md`,
  `CONTRIBUTING.md`, `.specify/memory/review-loop.md`, the workflow and ticket
  schema, architecture spec, feature 001 spec/plan/research/data model,
  contracts, status board, relevant tickets, and `SECURITY-DECISIONS.md`.
- Ran `scripts/verify.sh` on the clean baseline: **14 PASS, 1 SKIP, 0 FAIL**.
  The skipped gate was release-cadence reproducibility.
- Compiled every Go test module omitted by `verify.sh` with `go test ./...
  -run '^$'`; contract, integration, and shared log-invariant modules compile.
- Rendered Compose with the example env. Compose selected project name
  `compose` and physical volume `compose_stargate-keys`.
- Rendered the installer's exact Compose command without an env file. It exited
  1 because `DOCKER_SOCKET_PROXY_IMAGE` was unset and the proxy service had
  neither an image nor build context.
- Inspected the generated extension zip. Its member timestamp is the source
  file's 2026 timestamp, not `SOURCE_DATE_EPOCH`; Info-ZIP 3.0 ignored the
  variable.
- Ran ShellCheck over shell sources. It is not part of `verify.sh` and reported
  errors/warnings, mostly workflow-script robustness issues.
- Checked current Firefox WebExtension behavior against Mozilla's official
  [ProxyInfo documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/ProxyInfo),
  [privacy.network documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/privacy/network),
  [privacy API schema](https://searchfox.org/firefox-main/source/toolkit/components/extensions/schemas/privacy.json),
  and [management API documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/management/get).

## Blockers

### B1. The local installer and Compose identity model are incompatible

**Claim tested.** `./scripts/stargate init` creates the local stack, installs
keys into the volume the two planes mount, waits for health, and reaches the
Tor listener. See `scripts/subcommands/init:5-16` and quickstart step 1.

**What would falsify this finding.** The installer would pass the required env
file, use Compose's physical project-scoped volume/container identities, and
initialize every writable mount for the service UID/GID before starting the
non-root containers.

**Evidence.**

- `scripts/subcommands/init:53,221-224` runs `docker compose -f ... up` but
  never passes `--env-file compose/env/local.env.example` and never creates
  `compose/env/local.env`. The exact command fails configuration because
  `${DOCKER_SOCKET_PROXY_IMAGE}` expands to an empty string.
- The installer writes to literal volume `stargate-keys`
  (`scripts/subcommands/init:66,134,153,198`). Compose renders that logical
  volume as `compose_stargate-keys`. The keys are installed into an unused
  volume; both planes mount an empty different volume.
- The health loop calls `docker inspect stargate-dp`, `stargate-control`, and
  `tor` (`scripts/subcommands/init:237-246`). Compose creates names such as
  `compose-stargate-dp-1`; there are no `container_name` overrides. The loop
  therefore times out even if the containers run.
- The installer only sets ownership inside the key volume. It does not prepare
  `stargate-ipc`, `stargate-control-state`, `stargate-dp-state`, or
  `stargate-tor-config`. Empty named-volume roots are root-owned; UID 5101/5102
  cannot create the UDS files, SQLite DB, snapshot, or rendered torrc there.
- Quickstart step 2 and teardown use the same non-namespaced literal volume
  names (`specs/001-tor-route/quickstart.md:83-101,230+`), so the manual token
  and wipe instructions target the wrong volumes too.
- `tests/contract/stargate-cli/init_test.sh` checks text patterns and only runs
  the missing-Docker path. It never renders the exact Compose invocation or
  exercises Compose identity/ownership, so it passes all of the failures above.

**Impact.** A fresh install exits 30 before build in the default environment.
If the image variable is exported manually, keys and service state are still
miswired and the health loop exits 40. This blocks SC-001 and every live test
that assumes the installer provisions the stack.

**Recommendation.** Make one Compose command builder authoritative for project
name, compose file, and env file. Create the project volumes first, resolve
physical volumes by Compose labels or rendered config, then initialize all
volume roots with explicit UID/GID/mode. Query service IDs with `docker compose
ps -q <service>`, never guessed names. Add a Docker-backed init contract test
that uses tiny fixture images so it can prove env loading, project isolation,
volume ownership, idempotence, and health behavior without building Stargate.

### B2. Tor starts before its Stargate configuration exists

**Claim tested.** The integrated boot path is CP renders torrc, Tor loads it,
then DP routes through it (`T033` analysis, `data-model.md` section 6).

**What would falsify this finding.** Tor would depend on a completed config
render, or the exact safe default torrc would already be baked into the image.

**Evidence.** `stargate-control` depends on `tor` in
`compose/docker-compose.local.yml:78-96`, while Tor reads the shared config at
its entrypoint (`sidecars/tor/Dockerfile:120-124`). Compose starts Tor first.
The CP later writing the file does not make a running Tor reload it. T032 avoids
this by seeding the volume before starting Tor
(`tests/contract/torrc/live_sidecar_test.go:164-198`), so that test cannot catch
the production ordering defect. T033 is opt-in, not in the green gate, and has
not executed because the implementation is absent.

**Impact.** Tor may start with the Debian package default torrc, fail because
the expected file is absent, or remain running without the mandated isolation
directives. The last case is a privacy failure, not just an availability issue.

**Recommendation.** For the static Tor-only slice, bake the byte-pinned safe
torrc into the Tor image. If CP ownership is retained for future dynamic config,
remove the cycle: start CP without Tor, make CP healthy only after an atomic
render, and make Tor depend on that health condition. Add a cold-volume boot
test that does not seed config from the test harness.

### B3. Cold start violates binding plane separation

**Claim tested.** Constitution Principle II requires the data plane to continue
routing when the control plane is unreachable
(`.specify/memory/constitution.md:126-138`).

**What would falsify this finding.** On cold start with CP absent, the DP would
still attempt its fixed Tor upstream and produce a safe route error only if Tor
itself is unavailable.

**Evidence.** `data-model.md:186-216` initializes `routeEnableMask[TOR]` to
disabled, does not persist it, and waits for a CP `HEALTHY` event. Architecture
section 5.5 simultaneously says cold start continues from the snapshot and
then says the route stays disabled (`specs/000-architecture/spec.md:307-326`).
T020a explicitly expects auth to succeed but every routed request to return
`ROUTE_DOWN` until CP reconnects. No other component can send the enabling
event.

**Impact.** Restarting only the DP during a CP outage stops routing, even when
Tor and the last-known token snapshot are healthy. This is the failure coupling
Principle II forbids.

**Recommendation.** Remove the CP-driven mask from request admission. The
fixed upstream dial is authoritative: try `tor:9050`, forward on success, and
return the protocol-safe route failure on connect/handshake failure. CP events
may improve status and avoid a known-doomed dial, but absence of an event must
not disable routing. Amend the spec/data model before T045/T050/T073.

### B4. The browser hardening contract is not implementable with the declared APIs

**Claim tested.** The extension enforces DoH off, DoT off, WebRTC disabled,
HTTP/3 off, and a foreign-extension allowlist before routing
(`architecture spec:893-919`; FR-004; T034b/T055).

**What would falsify this finding.** Firefox's stable WebExtension schema would
expose the named settings, and the manifest task would request every permission
needed to inspect them.

**Evidence.** Mozilla's `privacy.network` API exposes
`peerConnectionEnabled`, but not `network.trr.mode`,
`network.dns.over_tls.*`, or `network.http.http3.enable`. The proposed T034b
test supplies handwritten mock properties that do not exist in Firefox. The
manifest task requests `privacy` but not `management`; enumerating other
extensions requires the `management` permission. The proxy descriptor itself
is feasible: current `ProxyInfo` does support SOCKS username/password and
`proxyDNS`.

**Impact.** A fail-closed implementation blocks all routing because settings
are unavailable; a fail-open implementation violates Constitution Principle
III. A green mock test would provide false assurance.

**Recommendation.** Stop T034b/T051/T055 and choose a real enforcement
boundary. Practical choices are managed Firefox policies installed alongside
Stargate, a separately reviewed privileged Firefox experiment for a controlled
distribution, or a constitution amendment that makes hardened Mullvad Browser
configuration an externally verified precondition rather than an extension
guarantee. Add `management` only if the foreign-extension inventory remains a
requirement, and test in the actual target browser rather than only Node mocks.

### B5. Per-request Argon2id is an allocation-based denial-of-service path

**Claim tested.** The 64 MiB, parallelism-4 Argon2id verifier is negligible and
the DP can establish 200 concurrent authenticated connections within 30 seconds
(`data-model.md:138-174`; `plan.md:70-89`).

**What would falsify this finding.** Authentication would globally bound active
Argon2 jobs and memory before allocation, or the KDF implementation would
allocate only for CPU-scheduled jobs.

**Evidence.** `golang.org/x/crypto/argon2.IDKey` allocates its complete
`memory` block slice before processing. Two hundred simultaneous one-token
checks can therefore allocate roughly `200 * 64 MiB = 12.8 GiB`; N=4 can cause
up to four allocations per request over its lifetime. The plan assumes only
two hashes are simultaneous on eight cores, but Go has no implicit global
Argon2 semaphore. Any local process can reach the loopback proxy and trigger
auth work. The proposed T079a test checks only a 16 GiB reference workstation,
so an OOM may look environment-dependent rather than architectural.

The benefit is also weak: tokens are required to be uniformly random 128-bit
values. Offline brute force of a correctly generated token is already
infeasible with a fast verifier; Argon2 is primarily useful for low-entropy
human passwords.

**Recommendation.** Prefer HMAC-SHA-256 over the random token with a dedicated
install-time pepper shared by CP and DP. Hash the candidate once, compare every
stored verifier in constant time, and keep the pepper out of the snapshot. If
Argon2 remains, add a strict weighted semaphore and bounded queue before any
allocation, rate-limit auth failures, and specify behavior under saturation.
Falsify the redesign with peak-RSS and unauthenticated-flood tests, not only
pool fill time.

## Major findings

### M1. Token lifecycle state is internally inconsistent

**Claim tested.** CP restart re-hashes tokens, pushes a monotonically newer
generation, and DP atomically replaces its last-known list without accidental
revocation.

**What would falsify this finding.** A persistent generation source or retry
protocol would be specified, IO failures would preserve the last-known list,
and the persistence schema would accept manual token records.

**Evidence.**

- The model says generation is monotonic and assigned by CP
  (`data-model.md:96-103`), but no DB column, state file, startup query, or task
  defines how it survives CP restart. Starting again at 1 is stale once DP has
  generation 1 or higher.
- T035/T041 say a missing or unreadable token file pushes an empty generation.
  During an ordinary CP restart this replaces the DP's valid last-known list
  and rejects every client. A valid explicit empty list and an IO/parse failure
  need different semantics.
- T035 must insert manual label records into `enrolled_devices`, but V001 makes
  `pubkey` and `token_hash` non-null (`V001__init.sql:20-27`). The manual YAML
  format contains no device public key, and the diff only needs labels.
- The design promises plaintext zeroing, but SnakeYAML materializes token values
  as immutable Java `String` objects. Zeroing a later `byte[]` does not erase
  the parser's String. T035a only observes the byte array and would falsely
  prove the broader claim.

**Recommendation.** Define a single persisted generation record and a
reconciliation handshake (`current_generation`, proposed generation, explicit
retry on stale). Preserve DP state on missing/unreadable/invalid input; reserve
an explicit valid `tokens: []` for revoke-all. Introduce a temporary
`configured_tokens(label, verifier, ...)` entity or make enrollment-only fields
nullable until real device enrollment exists. Narrow the memory claim to what
Java can guarantee, or replace the YAML String path with a deliberately mutable
secret parser.

### M2. The Compose network grants avoidable egress and Docker API reachability

**Claim tested.** No component makes outbound connections except routed
requests, and compromise of one service does not unnecessarily expand the TCB.

**What would falsify this finding.** DP/CP would be on internal-only networks,
only Tor would have general egress, and only the exact lifecycle observer would
reach a narrowly filtered host interface.

**Evidence.** All four services share one ordinary bridge
(`compose/docker-compose.local.yml:39-179`). It is not `internal: true`, so CP,
DP, Tor, and docker-socket-proxy have general Docker-NAT egress. All three
application containers can also reach the root-running docker-socket-proxy.
`CONTAINERS=1` exposes Docker's broad container list/inspect surface, not only
Tor or only health fields. The decision log honestly acknowledges the
DP/CP/Tor reacher set, but accepts a risk that network separation can remove.

The same Compose file omits `read_only`, `cap_drop`, `no-new-privileges`, and
resource limits. This directly contradicts threat-model lines 860-862 and
architecture lines 446-448, which claim read-only sidecar roots and only one
writable mount.

**Recommendation.** Remove Docker API access from this slice if CP only needs
Tor health; Tor's authenticated control port and connection failure already
provide that signal. Otherwise use separate networks: DP+Tor on an internal
transport network, CP+purpose-built observer on an internal management network,
and Tor alone on an egress network. Replace generic Docker inspect with a small
daemon returning a fixed Tor health enum. Add read-only roots, minimal tmpfs
mounts, dropped capabilities, `no-new-privileges`, and memory/PID limits, then
test the negative network paths.

### M3. The Tor healthcheck is known to read the wrong cookie path

**Claim tested.** The image healthcheck reports Tor bootstrap state.

**What would falsify this finding.** Tor would load Debian's defaults torrc or
the rendered torrc would explicitly set `DataDirectory /var/lib/tor`.

**Evidence.** The entrypoint supplies only `-f /etc/tor/torrc`; Debian's
`torrc-defaults` is not loaded. Tor therefore uses `$HOME/.tor`, while the
healthcheck reads `/var/lib/tor/control_auth_cookie`
(`sidecars/tor/Dockerfile:120-140`). T087 already documents that the healthcheck
will remain unhealthy. T032/T033 use `find` and therefore mask the image
healthcheck defect.

**Recommendation.** Prioritize existing T087 before any lifecycle work, and
make the live image test assert Docker `State.Health.Status == healthy`, not
only a separately implemented control-port probe.

### M4. `verify.sh` is green without running the completed contract suite

**Claim tested.** `scripts/verify.sh` is the single deterministic answer to
whether the current tree is green.

**What would falsify this finding.** The log would show all workspace Go
modules, with explicit accounting for test-level skips.

**Evidence.** Gate 2 runs only `cd data-plane && go test ./...`; gate 4 runs
only shell/Bats files (`scripts/verify.sh:84-143`). The baseline log contains
three DP unit packages and no `tests/contract`, `tests/integration`, `proto`, or
`tests/internal/loginvariants` package. T076 is deferred to Polish even though
T019b-T033 are already marked done. Docker-dependent Go tests also self-skip
when Docker is unavailable; plain `go test` then exits 0 and would be counted as
PASS rather than SKIP.

**Recommendation.** Move T076 to a foundational blocker now. Run every
workspace module at PR cadence, and consume `go test -json` so required tests
that all skip cannot be reported as a pass. Separate hermetic PR tests from
explicit release/live jobs, but make both lists exhaustive and machine
auditable. Add a CI mirror before calling the branch releasable.

### M5. Inter-plane version/auth claims have no complete wire contract

**Claim tested.** Both sockets are mutually authenticated and reject a higher
major protocol version before accepting RPC behavior.

**What would falsify this finding.** Proto/TLS metadata would contain a version
marker and T022 would test real UID/GID, peer certs, version mismatch, and
plane-down survival before implementation.

**Evidence.** `control.proto` and `events.proto` contain no handshake/version
RPC or metadata field; the package name is not a runtime version negotiation.
T038/T045 mention TLS authentication but not the unknown-major marker. T022 is
marked done while `transport_test.go:7-16` explicitly defers socket ownership,
peer UID access, mutual Ed25519, schema-version rejection, and most plane-down
behavior. The ticket says those are its acceptance surface, and no dedicated
pre-implementation contract ticket now owns all deferred rows.

**Recommendation.** Specify an explicit `Handshake` RPC or authenticated
transport metadata carrying protocol major/minor and capabilities. Define the
X.509 certificate derivation, peer public-key pin check, validity policy, and
UDS authority/SAN handling. Reopen or remediate T022 with container-level tests
before T038/T045, instead of letting implementation define the contract.

### M6. The workflow driver does not implement the canonical workflow

**Claim tested.** One ticket equals one branch and one reviewed commit, with a
mandatory red-team gate for `privacy_critical: true`.

**What would falsify this finding.** `run-task.sh` would create the ticket
branch, enforce the review/red-team artifacts, commit on approval, and merge
that branch only.

**Evidence.**

- The pending phase never creates or switches a branch.
- APPROVE changes the ticket to `done` but does not create or verify a commit.
- The script admits the privacy red-team gate is informational and not wired
  (`scripts/run-task.sh:35-40`), yet it can reach `done` and `--merge`.
- Merge requires the current branch name to contain the ticket ID. Current
  history consists of per-ticket commits directly on feature branch
  `001-tor-route`, so the canonical `T-NNN-*` branch model and actual practice
  disagree.
- `derive-deps.sh` treats `Pairs with TNNN` as test-blocked-by-implementation.
  T035a therefore depends on T035 even though its own text says the test must
  be failing before T035. T020a/T025c/T025d/T034e/T068a have the same pattern.

**Impact.** The process can label privacy-critical work done without the gates
the constitution requires, and its generated dependency graph can make
tests-first sequencing impossible.

**Recommendation.** Decide whether the real unit is a ticket branch or a
feature branch with one ticket commit, then make docs and scripts identical.
Fail closed on missing reviewer/red-team artifacts, clean-tree state, ticket
scope, and commit trailers. Replace the ambiguous `Pairs with` dependency rule
with explicit directed dependencies and add a linter rule rejecting a
privacy-critical implementation that is runnable before its named test.

### M7. Reproducibility and supply-chain claims are ahead of mechanisms

**Claim tested.** Extension zip, JVM bytecode, Tor image, and toolchain are
pinned/reproducible as claimed by Principles IV and VI.

**What would falsify this finding.** A two-build test would pass across changed
source mtimes; Maven would have deterministic timestamp configuration; Tor
packages would resolve from an immutable snapshot; wrapper downloads would be
hash-verified.

**Evidence.**

- `extension/package.sh` relies on `SOURCE_DATE_EPOCH=0`, but the installed
  Info-ZIP 3.0 stores the source mtime. The built archive contains
  `README.md` dated 2026-05-18. Sorted entries and `-X` do not normalize DOS
  timestamps.
- `control-plane/pom.xml` has no `project.build.outputTimestamp` or
  `reproducible-build-maven-plugin`, despite the Dockerfile saying the POM owns
  this guarantee.
- `sidecars/tor/Dockerfile` runs unversioned `apt-get install`. A clean build
  at the same source commit can select newer Tor/Debian packages. The decision
  log acknowledges this, but the architecture still says the final image is
  pinned in current Compose when it is not.
- Maven wrapper properties pin a versioned URL but omit
  `distributionSha256Sum`, although the wrapper supports it.
- Pending T081 proposes building after a `v*` tag and then committing resolved
  digests/decision text. That means the tag cannot point to the source tree
  containing its own release Compose file and decisions.

**Recommendation.** Normalize archive entry mtimes in a staging tree and land
T075b immediately. Add deterministic Maven timestamps plus a two-clean-build
comparison. Build Tor from immutable Debian/Tor snapshot URLs with explicit
package versions and retained package hashes, or narrow the reproducibility
claim honestly. Add the Maven distribution SHA-256. Use a two-phase release:
build a candidate, record/sign digests in a reviewed commit, then tag that exact
commit; never mutate source metadata after the release tag.

### M8. The authoritative threat model and user docs contain known false claims

**Claim tested.** Threat surfaces change in the same PR and authoritative docs
describe current behavior.

**What would falsify this finding.** The threat model would reflect July's
Tor/proxy decisions and actual Compose hardening; security/reporting links and
quickstart commands would resolve.

**Evidence.**

- `THREAT-MODEL.md` is still Draft, last updated 2026-05-17.
- Lines 854-862 claim every sidecar is digest-pinned and runs with a read-only
  root; current Tor is built locally, current Compose has no final digest and
  no `read_only`.
- Lines 871 and 1168-1175 say `SECURITY-DECISIONS.md` is not authored and Tor
  maintainer trust is unresolved, despite July decisions.
- Lines 1207-1213 say `CONTRIBUTING.md` does not exist. It exists, but its
  security advisory URL still contains `<org>`, so the private reporting route
  is unusable as written.
- `CONTRIBUTING.md` points to a missing `CODE_OF_CONDUCT.md`, contains multiple
  `[fill in once architecture spec lands]` placeholders, and documents test
  commands/directories that do not exist yet without consistently labeling
  them future work.
- Quickstart claims init performs a SOCKS5h and CP gRPC handshake; the code only
  attempts a TCP open after its health loop. Its volume commands are also wrong
  under Compose namespacing.

**Recommendation.** Treat T082/T083 and quickstart reconciliation as
foundational, not polish. Replace false present-tense claims with explicit
implemented/planned labels. Put a release-blocking doc consistency test on the
few load-bearing facts (read-only roots, image pins, security contact, volume
names), while avoiding broad prose regexes that merely preserve stale wording.

## Additional weaknesses

### A1. Persistence tests prove table names, not the contracts consumers need

`V001MigrationTest` only checks that five tables exist and Flyway recorded the
migration. It does not inspect columns, nullability, checks, uniqueness, or
exercise T035's insert shape. That is why the non-null `pubkey` contradiction
survived a green Maven gate. Add schema introspection and a real repository
integration test. Also consider DB triggers that reject `audit_log` UPDATE and
DELETE if "append-only" is intended as a mechanism rather than a code convention.

### A2. Several leak/log tests still contain false-assurance paths

The shared `loginvariants` scanner covers raw, hex, four base64 forms, and
decimal forms, which is good. The older control-gRPC copy omits raw plaintext
(`dpharness_test.go:392-411`), so a verifier logging the offered token as a
string can pass those local assertions. The allowlist matches any line with an
allowed `msg=` value and permits arbitrary extra fields on that line; it does
not by itself catch `msg=startup dst=...`. Finally, allowlist failure messages
print the full rejected line and can echo the secret into CI output. Consolidate
on one scanner, define allowed fields as well as message classes, and keep all
failure output index/length-only.

### A3. The secret-scanner fallback does not catch Stargate bearer tokens

The pre-commit hook says its fallback protects fresh machines, but its regexes
do not include a contextual 32-hex bearer-token rule. Hooks are also optional
and there is no CI mirror. Add a high-signal pattern such as a 32-hex value next
to `token`, `bearer`, or `STARGATE_TEST_TOKEN`, and run gitleaks in CI/history at
push/release cadence. Keep the narrow documented example allowlist.

### A4. Shell quality is not part of the green gate

ShellCheck is installed but not run by `verify.sh`. It reported robustness
issues in workflow scripts, including ambiguous `&& ... || ...` control flow,
ad-hoc glob/`ls` selection, missing shebang context for adapters, and unchecked
`cd` calls. Most are not immediate security defects, but the installer and
workflow are release-critical shell code. Add `bash -n` and a scoped ShellCheck
gate, fixing or narrowly annotating intentional array/parser constructs.

### A5. Egress testing should attribute traffic to the component under test

Pending T034f proposes asserting that every TCP SYN on the host egress NIC
during a window belongs to the Tor consensus. Unrelated host traffic can fail
the test, while container attribution remains implicit. Capture the Tor
container network namespace/veth or filter by container source IP/cgroup, and
assert separately that DP and CP namespaces have no non-internal egress.

## Findings that did not survive falsification

The following suspected problems were checked and are not recommendations:

- **Bind safety:** `data-plane/internal/bind.Check` uses `netip.ParseAddr`,
  rejects hostnames without resolution, accepts only loopback, and has focused
  tests. No bypass was found in the implemented function. Startup integration
  remains pending T050.
- **Error template literal:** the implemented constant is deliberately narrow,
  contains only three placeholders, and unit tests pin byte shape. The risky
  renderer/substitution logic is not implemented yet.
- **Tor signing-key file injection:** the Dockerfile checks both the pinned
  fingerprint and exactly one primary key before dearmoring. The earlier
  appended-key bypass is closed.
- **SOCKS descriptor feasibility:** Firefox currently supports SOCKS username,
  password, and proxy-side DNS in `proxy.ProxyInfo`; the blocker is the
  hardening-pref audit, not per-request proxy selection.
- **Test code compilation:** all omitted Go test modules compile on the reviewed
  tree. The finding is that they are not executed/accounted for by the green
  gate, not that they are syntactically broken.

## Recommended order of work

1. Amend the design for CP-independent routing, browser hardening, and token
   verification/generation. Do this before T035/T038/T044/T045/T050/T055.
2. Repair installer/Compose identity, volume ownership, Tor config ordering,
   and T087. Add behavior-level install and cold-volume tests first.
3. Wire all hermetic Go modules and skip accounting into `verify.sh`; make
   privacy-critical red-team enforcement fail closed in the driver.
4. Split networks/remove the generic Docker socket proxy and add container
   hardening.
5. Fix reproducibility mechanisms and adopt the two-phase release flow.
6. Reconcile threat model, quickstart, security contact, tickets, and status
   claims before declaring the vertical slice runnable.

## Verification snapshot

- Clean baseline `scripts/verify.sh`: `PASS=14 SKIP=1 FAIL=0`.
- Compile-only omitted modules: contract, integration, and shared log-invariant
  modules all compile.
- Exact installer Compose render without env: fails as described in B1.
- Compose render with example env: confirms project-scoped physical names.
- No source files were changed by this review; this report is the only worktree
  addition.
