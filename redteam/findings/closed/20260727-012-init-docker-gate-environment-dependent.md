---
id: 20260727-012-init-docker-gate-environment-dependent
status: closed
severity: minor
principle: [V]
threat-model: n/a — operator-diagnosis / harness robustness
location: scripts/subcommands/init (preflight) + tests/contract/stargate-cli/fixtures/fixture-compose.yml:26-28
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: 7d4016a
decision-ref: null
closed-date: 2026-09-25
closed-by: T146 reports only the observed timeout, gives the operator both
  data-plane and host Docker-publishing paths to inspect, assigns fixture
  loopback ports through Docker, and proves owned-only cleanup after an
  injected failure. The historical missing-trap allegation was refuted;
  the reproduced leak was two unmounted project-labelled volumes.
---

# `init` misattributes a blocked Docker publish path to a dead data plane

## Closure — 2026-09-25

T146 took the suggested diagnosis-softening option. A timed-out TCP connect
now reports only that route readiness was not observed; it does not assert
that the container, VPN, firewall, or Docker publishing caused the failure.
The fixture uses Docker-assigned loopback host ports, so two projects can run
together while production still binds its specified `127.0.0.1:8881` listener.
The existing EXIT/INT/TERM cleanup path now also removes project-labelled
volumes that the fixture leaves unmounted. The injected-failure test checks
that owned resources are gone and a foreign project volume remains; the
retrospective pre-fix reproduction is recorded in
`specs/001-tor-route/evidence/T146-fixture-cleanup.md`. The older sections
below remain as the historical finding and suggestions, not current code
behavior.

> **Severity corrected 2026-07-28 from major to minor, and the mechanism rewritten.**
> The original text blamed the fixture's busybox `nc` listener and "Docker 29.6.2".
> **That diagnosis was wrong.** See "Correction" below. The residue is real but small,
> and it is about *diagnosis quality*, not a broken gate.

## What actually happens

On a host where Docker's published-port path to the container is blocked, every
`stargate init` run exits 50 and `tests/contract/stargate-cli/init_docker_test.sh` FAILs
with three findings. Since `20260727-011` bounded the probe, the message reads:

```
stargate init: 127.0.0.1:8881 timed out after 5s — port published but nothing accepting
               (inspect the stargate-dp container).
```

That message is **wrong on this class of host**, and it sends the operator to inspect a
container that is perfectly healthy.

## Correction — the real mechanism

Two hypotheses were raised and both were **refuted by measurement**:

1. **Concurrency** — the fixture randomises the compose project name but publishes a fixed
   host port `127.0.0.1:8881`, so concurrent runs could collide. Refuted: a fully isolated
   re-run (no concurrent stacks, port free, no other test processes) reproduced the failure
   identically.
2. **The busybox `nc` stand-in** — refuted three ways:
   - `nc -l -p 8881` binds `:::8881` (IPv6 wildcard). Forcing IPv4 with
     `nc -l -s 0.0.0.0 -p 8881` still hung 3/3.
   - `nc -lk` (keep-listening) still hung 3/3.
   - **`nginx:alpine`** — a known-good production TCP server, no `nc` involved — published
     the same way *also* hung 3/3.

The actual cause is host-level, and outside this repository entirely:

| Probe | Result |
|---|---|
| host → published `127.0.0.1:<port>` | **hangs** (docker-proxy accepts, then cannot reach the backend) |
| host → container IP `172.17.0.2:80` directly | **refused** |
| inside container → `127.0.0.1:8881` | **succeeds** |

`net.ipv4.ip_forward = 1` (fine). The routing rules carry:

```
32765:	not from all fwmark 0x6d6f6c65 lookup 1836018789
```

`0x6d6f6c65` is ASCII `"mole"` — **Mullvad's fwmark**. With `wg0-mullvad` up and

```
$ mullvad lan get
Local network sharing setting: block
```

Mullvad's killswitch blocks private-range traffic, which includes Docker's
`172.16.0.0/12` bridge networks. Any unmarked forwarded packet is diverted into Mullvad's
routing table and dropped, so docker-proxy accepts the loopback connection and then stalls
with no backend.

**Host fix (operator's decision, not a code change):** `mullvad lan set allow`, or stop the
tunnel while running Docker-backed tests. Note this is a deliberate exposure trade-off —
allowing LAN sharing permits traffic outside the tunnel — and on a privacy project that
choice belongs to the operator, not to a test harness.

**Proven 2026-07-28.** The operator set `mullvad lan set allow`. With **no change whatsoever
to the fixture or the `nc` listener**, the control probe went `rc=124` → `rc=0` (3/3) and the
gate flipped:

```
OK: T088 init_docker_test (env-file · project-scoped volumes · key+pepper ownership ·
    volume-root init · health via ps -q · idempotence · two-project isolation)
exit=0 elapsed=12s
```

6+ min FAIL → 27 s FAIL (after `20260727-011`) → **12 s PASS** (after the host fix). The
`nc` stand-in is exonerated: it was never the cause, and replacing it would have been a
no-op change made against a wrong diagnosis.

**The gate is therefore behaving correctly**: Docker networking is genuinely broken on this
host, and a test that depends on it should fail. The original finding's claim that "the
authoritative gate is environment-dependent" was itself a misdiagnosis — CI is not
"more trustworthy than local"; local was simply running behind a killswitch.

## What is still a real defect

1. **`init` cannot distinguish "Docker publishing is blocked" from "the data plane is
   down", and guesses wrong.** It tells the operator to inspect `stargate-dp` when the
   container is healthy and the fault is host firewall/routing. This matters more than
   usual here: Stargate is a privacy tool whose reference browser is **Mullvad Browser**,
   so a large share of its operators will be running exactly this killswitch. Principle V —
   do not assert more than the evidence supports; "nothing accepting" was not established.
2. **Fixed published host port.** The fixture randomises the project name but hardcodes
   `127.0.0.1:8881:8881`, so two concurrent runs contend for one global resource despite
   the test's stated two-project-isolation purpose. Not the cause of this failure, still a
   robustness gap.
3. **Teardown leaks on the failure path.** A failed run left six fixture volumes
   (`t088iso*_stargate-*`) behind; cleanup is not `trap`-based.

## Suggested fix

- **Preflight probe for Docker publishing.** `preflight()` already checks `docker`,
  `docker compose`, and daemon reachability. Add a cheap self-test: publish a throwaway
  container on an ephemeral loopback port and connect to it. If that fails, exit
  `EXIT_PREFLIGHT` (10) with a message naming the real cause — blocked Docker port
  publishing — and mention a VPN killswitch / `mullvad lan set allow` as the common case.
  That converts a misleading exit-50 into an accurate exit-10 before any keys are generated.
- Alternatively (cheaper), soften `verify_tor`'s timeout message so it names both
  possibilities instead of asserting the container is at fault.
- Randomise the published host port alongside the project name.
- Make fixture teardown `trap`-based so failures do not leak volumes.

**Do not replace the `nc` listener.** It was measured as not being the cause, and swapping
it would leave this finding open while appearing to close it.

## Regression test

For the preflight probe: a contract test asserting that when Docker publishing is
unavailable, `init` exits 10 with the publish-path message rather than 50 with the
data-plane message.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding R2), corrected
  2026-07-28.
- `20260727-011` (unbounded connect) is closed (`f2b5988`); it made each failure take
  minutes and is what made this one cheap enough to diagnose properly (6+ min → 27 s).
- Method note: this is the second refuted hypothesis on this finding. `.scratch/audit.md`
  §9 records both. A finding that survives two wrong mechanisms is worth re-deriving from
  measurement rather than from its own prose.
