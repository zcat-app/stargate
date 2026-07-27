---
id: 20260727-001-tor-controlport-unbounded-cp-authority
status: open
severity: major
principle: [I, II, III, V]
threat-model: 5.8 (adjacent); no dedicated section exists — that absence is part of the finding
location: sidecars/tor/torrc:6-8
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: SECURITY-DECISIONS.md "2026-07-16 — docker-socket-proxy mechanism removed (T094a)"
---

# Tor ControlPort grants unbounded authority to the control plane; production torrc weakens the cookie for it and the threat model is silent

## What the code does

`sidecars/tor/torrc:6-8` ships `ControlPort 0.0.0.0:9051`, `CookieAuthentication 1`, and
`CookieAuthFileGroupReadable 1` in the production image. The last directive lowers
`control_auth_cookie` from Tor's default `0600 tor:tor` to `0640 tor:tor`; per
`specs/001-tor-route/contracts/torrc.md` invariant #4 its only stated justification is that
*"the contract-test harness at T062 cannot read the cookie without privilege escalation."*

`compose/docker-compose.local.yml:107-130` places the control plane on `stargate-cp-tor`
with L3 reach to `tor:9051`, and `:99-105` records that the narrow cookie-read volume mount
lands with T039 (`SidecarMonitor`). `SECURITY-DECISIONS.md:83` accepts the design on the
basis that *"the control-port cookie exchange carries only what `SidecarMonitor` needs
(bootstrap/health state)"*, and `:73` claims the control port is *"a strictly narrower
observation surface than a generic Docker Engine observer."*

## Why it leaks

Tor's control protocol has **no per-command ACL**. Authentication is all-or-nothing: any
holder of `control_auth_cookie` commands the entire surface.

| Command | Consequence |
|---|---|
| `SETEVENTS STREAM` / `GETINFO stream-status` | Live feed of every destination the DP routes, `.onion` included, with per-event timestamps. Principle I ("MUST NOT … log request metadata"), Principle III ("MUST NOT log destination hostnames … per-request timestamps"), Principle II (CP "MUST NOT sit in the request path"). |
| `SETCONF SafeLogging=0` + `SETCONF Log="debug file /var/lib/tor/x.log"` | Persists per-request destinations to the `stargate-tor-state` volume. Principle I explicitly prohibits persisting request metadata to disk. |
| `SETCONF __LeaveStreamsUnattached=1` + `ATTACHSTREAM` | Forcibly co-locates streams the extension isolated by first-party domain onto one circuit. Defeats Principle III's stream-isolation clause and User Story 2 wholesale. |
| `SETCONF UseBridges=1 Bridge=…` | Silently redirects the guard hop. Contradicts torrc invariant #7 and the constitution's "bridges default off". |
| `ADD_ONION` | Turns the client into a hidden service. Contradicts torrc invariant #9. |

The accepted rationale at `SECURITY-DECISIONS.md:83` is a **policy** statement about what
the CP intends to send. It is not enforceable by any mechanism — precisely the pattern
Principle III's rationale rejects, and the pattern already caught once in
`redteam/findings/closed/20260712-001-confirmed-for-session-gap.md` (policy asserted in
mechanism language).

The comparative claim at `:73` is also contestable. The removed Docker observer exposed
container lifecycle and (per the flagged `CONTAINERS=1` bug) container filesystem reads.
The Tor control port exposes a live per-request destination oracle **inside the anonymity
TCB**, plus arbitrary reconfiguration of it. That is a different surface, not a strictly
narrower one.

`grep -n -i "controlport\|GETINFO\|SETCONF\|SETEVENTS\|stream-status" THREAT-MODEL.md`
returns **two** hits, both in §5.8 and both about the *bind address*, not about control
authority. Principle V requires the threat model to state "which third parties are trusted,
and what they can observe"; for the control plane's Tor authority it states nothing.

**Adversary.** Any compromise of the control plane (Quarkus admin UI, YAML parsing of an
operator-authored `tokens.yaml`, SQLite) converts into a live destination oracle over the
anonymity layer, plus the ability to defeat stream isolation and write request metadata to
disk. Under a future LAN/VPS profile the CP is remotely reachable, which changes the
compromise probability materially.

**Present-tense confirmed component** (independent of pending T039):
`CookieAuthFileGroupReadable 1` ships today, in the production image, with no present-day
consumer — only a pending test. The container's `tor` group has exactly one member, so it
is currently inert; a production privilege reduction whose sole stated justification is
test-harness convenience is a defect on its own terms.

## Suggested fix

**Default: do not give the control plane the cookie.** `SidecarMonitor` needs bootstrap and
health only, and two authority-free sources already exist:

- relay the DP's `tor:9050` dial result over the existing inter-plane RPC (`GetStatus`
  already carries counters); or
- a bare TCP-connect liveness probe to `tor:9050`, which yields liveness with zero control
  authority.

Remove `CookieAuthFileGroupReadable 1` from the production golden and move it to a test-only
`torrc` overlay consumed by `tests/contract/tor/`.

**Alternative, if control access is genuinely required:** replace `ControlPort 0.0.0.0:9051`
with `ControlSocket /var/run/tor/control` + `ControlSocketsGroupWritable 1` on a dedicated
volume mounted only into the CP. Trade-off: still full command authority, but access becomes
mount-scoped rather than L3-reachable, and it simultaneously closes the DP→`tor:9051`
residue named in `THREAT-MODEL.md` §5.8.

**Either way:** add `THREAT-MODEL.md` §5.15 enumerating the command classes a control-cookie
holder commands and naming the trusted party, and correct the "strictly narrower observation
surface" comparison at `SECURITY-DECISIONS.md:73`.

## Regression test

`tests/contract/torrc/invariants_test.go` gains a row asserting `CookieAuthFileGroupReadable`
is **absent** from the production golden (the byte-match golden in `contracts/torrc.md`
updates in lockstep per its own change procedure).
`tests/contract/compose/network_hardening_test.go` gains an assertion that no service other
than `tor` mounts a path containing `control_auth_cookie`, via `docker inspect` mount-set
comparison. That would catch the T039 cookie mount at review time rather than after it lands.

## Related

- Pattern-identical to closed finding `20260712-001` (policy asserted in mechanism language).
- Interacts with `i2` from the same run: `compose/docker-compose.local.yml:125` mounts
  `stargate-tor-config:/etc/tor` **RW into the CP** while `tor` deliberately does not mount
  it — a second latent CP→Tor authority channel that T037 will reconnect.
- `THREAT-MODEL.md` §5.8 already names the adjacent CP→`tor:9050` residue; this finding is
  the ControlPort half it does not cover.
- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S1).
