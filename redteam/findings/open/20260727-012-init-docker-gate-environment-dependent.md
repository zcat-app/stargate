---
id: 20260727-012-init-docker-gate-environment-dependent
status: open
severity: major
principle: [VI, VII]
threat-model: n/a — build-integrity surface
location: tests/contract/stargate-cli/fixtures/fixture-compose.yml:26-28
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: null
---

# `init_docker_test.sh` FAILs on a developer workstation while passing in CI — the authoritative gate is environment-dependent

## What the code does

The fixture stands in for the real compose stack with three Alpine containers. The data-plane
stand-in is:

```yaml
stargate-dp:
  image: alpine:3.20
  command: ["sh", "-c", "while true; do nc -l -p 8881 </dev/null >/dev/null 2>&1 || sleep 0.2; done"]
  ports:
    - "127.0.0.1:8881:8881/tcp"
```

Its stated purpose (fixture header) is that `stargate-dp` "re-arms a busybox nc listener on
8881 (enough for init's TCP-connect verify_tor)".

## Why it matters

At `8bc5f6a` on a developer workstation (Docker 29.6.2), `scripts/verify.sh` is **RED**:

```
FAIL: T088 init_docker_test (3 finding(s)):
  - init project A exited 50 (expected 0)
  - idempotent re-init exited 50 (expected 0)
  - init project B exited 50 (expected 0)
```

each from `stargate init: 127.0.0.1:8881 not reachable`. The same gate passes in CI on a
clean `ubuntu-latest` runner.

A concurrency hypothesis was investigated and **refuted**: a fully isolated re-run — no
concurrent fixture stacks, host port 8881 free, no other test processes — reproduced the
failure identically (`exit=1`, same three findings). The busybox `nc` re-arm loop does not
reliably complete a TCP handshake through the published port on this Docker version. A
separate defect makes each failure slow rather than fast (20260727-011).

**Why this is a finding and not just local noise:** `scripts/verify.sh`'s own header, and
`.github/workflows/verify.yml:4-5`, establish **local `verify.sh` as the authority** and CI
as its mirror. A gate whose verdict depends on the host's Docker version or configuration
inverts that relationship — the authority becomes less trustworthy than the mirror, and
developers learn to discount a RED tree. Constitution Principle VI requires the green gate be
machine-checked and meaningful; a gate that is red-by-environment trains people to ignore it,
which is worse than not having it.

Taken with 20260727-007 (a mode bit hollows three gates) and 20260727-008 (a one-line
`go.work` edit drops the data plane), the "single green gate" the constitution leans on is
currently the project's weakest link.

Secondary issue observed: the fixture randomises the compose **project name**
(`t088isoa-<pid>-<epoch>`) but publishes a **fixed** host port `127.0.0.1:8881`, so two
concurrent runs on one host contend for a global resource even though the test's stated
purpose includes two-project isolation. This was not the cause of the failure above, but it
is a real robustness gap. A failed run also leaked six fixture volumes
(`t088iso*_stargate-*`), so teardown is incomplete on the failure path.

## Suggested fix

1. Replace the `nc` re-arm loop with a listener that reliably accepts, e.g.
   `socat TCP-LISTEN:8881,fork,reuseaddr` or a three-line `python3 -m http.server 8881`.
   The fixture only needs a socket that completes a handshake.
2. Randomise the **published host port** alongside the project name, and pass it to `init`
   via the existing env-override mechanism, so concurrent runs cannot collide.
3. Apply 20260727-011's timeout so any future failure is fast and legible.
4. Make teardown unconditional (`trap`-based) so failed runs do not leak volumes.

## Regression test

The gate is its own regression test once fixed; add an assertion that the fixture listener
actually accepts a connection **before** `init` is invoked, so a fixture regression reports
"fixture broken" rather than "data plane did not come up" — the current message misattributes
a harness failure to the product.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding R2).
- 20260727-011 (unbounded connect) makes each failure take minutes.
- Same green-gate-integrity class as 20260727-007 and 20260727-008.
