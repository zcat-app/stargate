---
id: 20260727-011-verify-tor-unbounded-connect
status: open
severity: major
principle: [VI]
threat-model: n/a — availability / operator-experience defect
location: scripts/subcommands/init:408 (`verify_tor`)
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: null
---

# `verify_tor()` performs an unbounded TCP connect — `stargate init` hangs for minutes instead of failing fast

## What the code does

```bash
verify_tor() {
  note "verifying Tor route (loopback proxy 127.0.0.1:8881)..."
  if (exec 3<>/dev/tcp/127.0.0.1/8881) 2>/dev/null; then
    exec 3>&- 3<&-
    note "Tor route reachable on 127.0.0.1:8881."
    return 0
  fi
  note "127.0.0.1:8881 not reachable — data plane listener did not come up."
  return "$EXIT_VERIFY"
}
```

There is **no timeout**. `bash`'s `/dev/tcp` inherits the kernel's default connect behaviour.

## Why it matters

**Reproduced empirically.** With a fixture-identical container (`nc -l -p 8881` on
`alpine:3.20`, published to a loopback host port), the container was `Up`, the port was
published, and `nc` was listening inside — yet the probe **hung 3/3 times past a hard 5-second
timeout**, while the identical probe against an ordinary host port (`127.0.0.1:9050`,
returned instantly, `rc=0`).

On any host or network configuration where the SYN is dropped rather than refused — a
firewall `DROP` rule, certain Docker publish paths, a wedged listener that never `accept()`s —
this blocks for the kernel's full SYN-retry budget (~130 s on Linux) per probe.

Observed consequences:

1. **Operator experience:** `stargate init` appears to hang for minutes when the data-plane
   listener is wedged, instead of reporting the failure promptly. `init` is the first command
   a new operator runs.
2. **Developer loop:** this is the root cause of `contract:init_docker_test.sh` taking **6+
   minutes** while all 15 other `verify.sh` gates complete in near-instant succession — the
   test calls `init` three times. A performance review in the same run measured the symptom
   and attributed it to host contention; the actual cause is this unbounded connect.
3. It turns a legitimate "not reachable" verdict into a very slow one, which reads as a hang
   rather than a diagnosis.

## Suggested fix

Bound the probe and distinguish the failure modes:

```bash
if timeout 5 bash -c '(exec 3<>/dev/tcp/127.0.0.1/8881)' 2>/dev/null; then
  note "Tor route reachable on 127.0.0.1:8881."
  return 0
fi
rc=$?
if [ "$rc" = 124 ]; then
  note "127.0.0.1:8881 timed out — port published but no listener accepting (check the DP container)."
else
  note "127.0.0.1:8881 refused — data plane listener did not come up."
fi
return "$EXIT_VERIFY"
```

*Refused* (fast) and *timed out* (slow) are different diagnoses and should read differently;
today both surface as the same message after an unbounded wait.

Consider making the timeout configurable alongside the existing
`STARGATE_HEALTHCHECK_TIMEOUT`.

## Regression test

A contract test that points `verify_tor` at a black-holed address (e.g. a firewalled port or
`10.255.255.1`) and asserts it returns within a bounded wall-clock time rather than hanging.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding R1).
- Root cause of the perf finding C-3 in the same run.
- Interacts with 20260727-012: the same gate is also environment-dependent for a separate
  reason.
