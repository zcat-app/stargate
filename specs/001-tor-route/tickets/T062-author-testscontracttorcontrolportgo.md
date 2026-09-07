---
id: T062
title: 'Author `tests/contract/tor/control_port.go`'
status: done
created: 2026-07-04
last_updated: 2026-09-07
source: tasks.md#T062
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T087]
parallel: false
files_budget: 5   # 3 code (helper + hermetic parser test + live self-test) + ticket + STATUS regen (T116 raw-diff-path convention)
privacy_critical: true
complexity: medium
risk: low
round_cap: 2
spec_refs:
  - spec.md §"User Story 2" acceptance scenarios 1–3 (control-port assertion surface for US2)
  - spec.md §FR-012 (ControlPort 9051 cookie-authenticated, compose-internal only)
  - spec.md §FR-016 (names the T062 helper, consumed by tests under torrc/ and integration/)
  - spec.md §SC-002 (100-CONNECT circuit-count measurement reads circuit IDs through this helper)
  - contracts/torrc.md §"Invariants" #3, #4, #11 (ControlPort 9051; CookieAuthentication 1 + CookieAuthFileGroupReadable 1; cookie at /var/lib/tor/control_auth_cookie)
  - contracts/torrc.md §"isolate_socks_auth_effect_test.go" (first consumer's circuit-ID assertion)
  - tasks.md#T062
decision_refs:
  - research.md §5 (contract-test harness language: Go + Docker SDK, shared data-plane toolchain)
  - tests/contract/torrc/live_sidecar_test.go (T032/T087): liveTorControl shell precedent + the explicit note "T062 will land a Go-side TCP+cookie client in Phase 4"
  - tests/contract/tor/port_exposure_test.go (T019b): same-package conventions — compose project namespacing, label-based network/container lookup, docker build-tag cadence, pre-registered cleanup
  - control-plane/core/.../SidecarMonitor.java (T039/T074/T094a): production protocol precedent — AUTHENTICATE carries lowercase hex of raw cookie bytes, bounded reply reads, QUIT; cookie never enters logs
  - docs/process/analysis.md (privacy_critical property-map gate)
  - tickets/T019a (precedent: a helper ticket ships library code + a committed self-test)
  - AGENTS.md doctrine: validate at edges (bounded reads on replies), no secrets in logs/prompts
reviews: { round: 2, date: 2026-09-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T062: Author `tests/contract/tor/control_port.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `tests/contract/tor/control_port.go` — cookie-authenticated Tor control-port client (helper consumed by T058, T058a, and the integration tests T059–T061); reads the cookie from the `stargate-tor-state` volume mount.

## Analysis

Property map built at /start (privacy-critical: every US2 circuit-isolation
assertion, SC-002's measurement, and T070a's no-retry proof read circuit
state through this helper — a helper that mis-parses `circuit-status` or
mis-authenticates would make those gates lie in either direction). Grounded
against the live side of the house this file joins: `tests/contract/tor/`
(T019b conventions), the two existing control-port consumers
(`live_sidecar_test.go` shell path, T033 `t033CircuitStatus` shell path),
the production client (`SidecarMonitor.java`), `compose/docker-compose.local.yml`
(network/volume topology), and `sidecars/tor/Dockerfile` (netcat-openbsd
present; image USER tor owns the 0640 cookie).

### Must hold

- **M1 — Cookie authentication, authoritative path.** The helper reads the
  raw cookie bytes from `/var/lib/tor/control_auth_cookie` inside the tor
  container (invariant #11 path pinned by T087's explicit
  `DataDirectory /var/lib/tor`), hex-encodes lowercase, and sends
  `AUTHENTICATE <hex>` — byte-for-byte the SidecarMonitor wire shape. An
  empty/wrong-path cookie read fails loudly, never authenticates "something".
- **M2 — No host reachability (FR-012).** The ControlPort is compose-internal;
  a host-side Go process cannot dial `tor:9051` and MUST NOT (no published
  port exists to dial — T019b sub-test (a)/(b) gate that). The helper's TCP
  session therefore terminates inside the compose network via
  `docker compose exec -T tor nc 127.0.0.1 9051` (exec default user is the
  image's `USER tor`, the cookie's 0640 `tor:tor` owner — the same reason
  `liveTorControl` runs in-container). The helper never asks for, or
  tolerates, a host-published control port.
- **M3 — One session, interleaved request/response.** Commands run write→
  read-reply→next on a single control connection. Dump-all-then-read would
  deadlock on large replies (`circuit-status` for T061's 100 circuits can
  exceed the 64 KiB OS pipe buffer); interleaving cannot.
- **M4 — Reply parsing per control-spec §2.3, bounded.** `250 ` final /
  `250-` continuation / `250+KEY=` data block (dot-stuffed, terminated by a
  lone `.`); block lines un-stuffed; non-2xx status (4xx/5xx) is an error
  naming the status line. Reads are bounded (line length, line count, total
  bytes) — the reply is external input (validate-at-edge doctrine); tor's
  control protocol has no reply-size contract.
- **M5 — Cookie secrecy in the harness.** The cookie is harness plumbing,
  not log material: no failure message, t.Log, or error string carries the
  hex or raw cookie bytes (SafeLogging parity — test infrastructure must not
  become the leak the feature exists to prevent). Failure diagnostics carry
  statuses and byte counts only.
- **M6 — Consumable from both consumer modules (FR-016).** Untagged
  library file in `package tor` (same dir as T019b's docker-tagged tests):
  compiles hermetically (`go vet ./...`), compiles under `-tags docker`
  alongside the package's tests, and is importable by `tests/contract/torrc`
  and by the `tests/integration` module (non-`internal/` path; module-mode
  consumers add require+replace, the loginvariants pattern).
- **M7 — The helper is exercised, not just compiled (Principle VII).** A
  committed hermetic parser test gates M4's logic at PR cadence; a committed
  docker-cadence self-test gates M1/M2/M3 live; the consumer family
  (T058, T058a, T059–T061, T070a) is the behavioral surface (FR-016).

### Gated

- Hermetic: `scripts/verify.sh` — `go vet` over `tests/contract` (the
  untagged helper + parser test are inside the PR gate); SPDX license-header
  check; `python3 scripts/lint-ticket.py` on this ticket.
- Docker cadence (`STARGATE_TEST_TAGS=docker scripts/verify.sh` or the
  named job): `go vet -tags docker` compile-check of the live self-test,
  then the self-test itself — named cases (a)–(d) in §Acceptance gate
  M1/M2/M3/M4-at-runtime against the production tor image, cold volume.
- M2's premise (the compose topology itself) is gated separately by
  `local_compose_test.sh` M2/M3 (static) and T019b (runtime) — not
  re-asserted here.
- M5 is mechanically greppable pre-commit: the secret scanner
  (`.githooks/pre-commit`) + the self-test asserting error strings stay
  cookie-free.

### Residue

- **R1 — Runtime path not PR-gated.** The AUTHENTICATE/exec/nc transport
  only runs where docker + a bootstrapped tor exist (docker cadence); the
  hermetic gate exercises parsing and framing against canned bytes only.
  Mitigation: the docker job runs the self-test on every named run; the
  risk window is a CI that never runs the docker job — accepted, same
  cadence trade-off as every `//go:build docker` suite in this repo.
- **R2 — Consumer dep edges are prose, not frontmatter.** tasks.md says
  T058, T058a, T059–T061 (and T070a) consume this helper, but their
  `blocked_by` carries only `[T009]`/`[]` (derive-deps TODO). Out of this
  diff's scope (editing five sibling tickets is drive-by); every consumer's
  /start grounding reads tasks.md and will find the landed file. Recorded
  here so the next derive-deps pass can wire `blocked_by: [T062]`.
- **R3 — Cookie transits host memory/pipe.** Reading the cookie for a
  host-driven harness necessarily copies it through the docker exec stdout
  pipe and helper memory. No gate can catch a harness that logs it; M5 +
  pre-commit scanner are the vigilance. Inherent to the harness posture
  T032 established; not fixable inside this ticket.
- **R4 — `nc` is a transport dependency.** The helper (and both existing
  shell-path consumers) assume netcat-openbsd inside the tor image. Package
  drift is caught by the reproducibility manifest test, not by this package;
  noted so an image-side nc removal surfaces as a known-shaped failure
  across three call sites, not a mystery.

## Acceptance

1. **NEW: `tests/contract/tor/control_port.go`** — `package tor`, no build
   tag, Apache 2.0 SPDX header. Exported surface:
   - `CookieAuthPath = "/var/lib/tor/control_auth_cookie"` (invariant #11).
   - `type ControlPortConfig struct { Project, ComposeFile, EnvFile string }`
     — the compose invocation context (project namespacing per T019b).
   - `ReadCookie(ctx, cfg) ([]byte, error)` — raw cookie bytes via
     `docker compose exec -T tor cat $CookieAuthPath`; non-empty, bounded
     size; bytes never logged.
   - `Connect(ctx, cfg) (*ControlPort, error)` — opens the session
     (`exec -T tor nc 127.0.0.1 9051`), wires stdin/stdout pipes.
   - `(*ControlPort).Authenticate(cookie []byte) error` — M1 wire shape;
     requires a 2xx reply.
   - `(*ControlPort).Command(command string) ([]string, error)` — sends
     `command` CRLF-terminated, reads the full reply (M3 interleaving, M4
     parsing), returns the data payload lines.
   - `(*ControlPort).Close() error` — `QUIT`, drain, wait for nc exit.
2. **NEW: `tests/contract/tor/control_port_test.go`** — UNTAGGED hermetic
   parser test (PR gate). Named cases over canned reply bytes:
   - **(a) single-line 250** → payload line returned;
   - **(b) multi-line 250- continuation** → payloads concatenated in order;
   - **(c) data block `250+K=`** with dot-stuffed `.` line → un-stuffed
     block lines, `250 OK` terminator consumed;
   - **(d) empty data block** (`250+K=` immediately `.`) → zero lines, no
     hang;
   - **(e) 4xx/5xx status** → error naming the status, nil payload;
   - **(f) oversized line / line-count blowout** → bounded error (M4).
   Runnable: `cd tests/contract && go test ./tor/ -run TestParseReply -v`.
3. **NEW: `tests/contract/tor/control_port_live_test.go`** —
   `//go:build docker`, compose project `stargate-t062-test`, cold volume,
   pre-registered `down --volumes` cleanup (T019b/T032 conventions). Named
   subtests:
   - **(a) LiveAuthenticatesWithCookieFromVolume** — `ReadCookie` +
     `Connect` + `Authenticate` → nil error (M1/M2).
   - **(b) LiveGETCONFControlPortRoundTrip** — `Command("GETCONF
     ControlPort")` → `ControlPort=0.0.0.0:9051` (invariant #3; round-trip
     framing).
   - **(c) LiveBootstrapPollViaSession** — poll `GETINFO
     status/bootstrap-phase` on ONE session until `PROGRESS=100` (bounded
     ~5 min) — many sequential Commands on one connection, the M3
     no-deadlock shape.
   - **(d) LiveCircuitStatusParses** — post-bootstrap `GETINFO
     circuit-status` parses; ≥1 `BUILT` circuit within a grace window
     (T033's assertion shape, now through the Go client).
   - plus: **(e) error diagnostics stay cookie-free** — failure paths
     surface statuses/counts, never cookie bytes (M5).
   Runnable: `cd tests/contract && go test -tags docker ./tor/ -run
   TestControlPortLive -v -timeout 20m`; hermetic `scripts/verify.sh`
   compile-checks this file via `go vet -tags docker` and accounts it
   SKIP[docker].
4. **Consumer-facing declaration (M6/M7, no new files):** the consumer
   family named in tasks.md (T058, T058a, T059–T061, T070a) consumes this
   API in their own diffs; this ticket's §Residue R2 records the missing
   `blocked_by` wiring for the next derive-deps pass.
5. **Falsification battery (pre-review, recorded in §Notes):** against the
   landed helper — (i) point `CookieAuthPath` read at the T087 wrong path
   `/var/lib/tor/.tor/control_auth_cookie` → read fails loudly (M1);
   (ii) strip the CRLF from one Command → tor times out / errors, never a
   silent empty success (M4 framing); (iii) feed the parser a 5xx reply →
   named error, not nil-error-empty-payload (case (e) catches); (iv)
   dot-stuffed block parsed without un-stuffing → case (c) catches; (v)
   dump-then-read session shape on a >64 KiB synthetic reply → deadlock
   (case (c) of the live test, many sequential commands, is the structural
   guard; the hermetic suite pins the interleaved reader itself).

## Out-of-scope

- The consumer test files themselves (T058, T058a in `torrc`/`tor`,
  T059–T061 integration, T070a) — they author their own diffs against this
  API; T058a's direct-to-9050 SOCKS5 transport is T058a's design problem.
- `SidecarMonitor.java` and anything in the production path — this helper
  is test-surface only (FR-016); the CP keeps its own three-command
  allowlist (redteam 20260727-001 posture untouched).
- Compose/image/torrc changes — the network topology and cookie path this
  helper depends on are already gated (T015, T019b, T029–T032, T087).
- Fixing R2's `blocked_by` edges in the five consumer tickets (drive-by
  edit; recorded for the next derive-deps pass instead).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**Falsification battery outcomes (§Acceptance #5), recorded pre-review:**

- **(i) wrong cookie path fails loudly** — exercised against the live
  sidecar (isolated module copy, own compose project): with `CookieAuthPath`
  pointed at the T087 wrong path `/var/lib/tor/.tor/control_auth_cookie`,
  the auth subtest fails loudly with
  `read control cookie (docker compose exec tor cat /var/lib/tor/.tor/control_auth_cookie failed): cat: No such file or directory`;
  with the authoritative path restored the suite is green. Re-gated at
  docker cadence: the live auth subtest reads the invariant-#11 path on
  every named run (R1 residue — not PR-gated).
- **(ii) CRLF stripped → not a silent success** — hermetic
  `AuthenticateSuccessAndFraming` pins the exact wire bytes
  (`AUTHENTICATE <hex>\r\n`); a framing mutation fails that assertion.
- **(iii) 5xx → named error, not nil-success** — hermetic
  `ErrorStatus551` / `ErrorStatus513` (plus the live auth-failure subtest,
  where real tor answered `515 Authentication failed` and the parser named
  it).
- **(iv) dot-stuffing parsed correctly** — hermetic
  `DataBlockWithDotStuffing` (un-stuffing) and
  `TerminatorOnlyWhenLineExactlyDot` (`..` is data, `.` terminates).
- **(v) dump-then-read deadlock is structurally excluded** — the live
  `LiveBootstrapPollViaSession` subtest drove many sequential Commands
  through ONE real session (passed against the production tor image,
  bootstrap PROGRESS=100), and the hermetic suite drives the interleaved
  reader directly; a write-everything-first regression deadlocks the live
  subtest into its named deadline failure.

**Round-1 review note:** the reviewer independently re-ran the hermetic
suite (PASS) and confirmed items (ii)–(iv) evidence; its Major finding (the
`maxReplyLines` bound had no demonstrating test → `LineCountOverBound`
added) and two Minor doc items (Command discard-after-error contract; this
battery record) were fixed in round 2.
