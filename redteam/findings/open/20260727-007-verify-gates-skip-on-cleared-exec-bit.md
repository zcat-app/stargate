---
id: 20260727-007-verify-gates-skip-on-cleared-exec-bit
status: open
severity: major
principle: [VI, VII]
threat-model: n/a — build-integrity surface
location: scripts/verify.sh:79-94,169-175
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: null
---

# `verify.sh` gates silently downgrade to SKIP when a gate script's exec bit is cleared — aggregate stays GREEN

## What the code does

The license-header, ground-check and go-workspace gates all guard on `[ -x <script> ]` and
record **SKIP** — not FAIL — when the predicate is false:

```sh
if [ -x scripts/check-license-headers.sh ]; then … else record "license-headers" SKIP "… absent"; fi
```

This is deliberate design: `verify.sh`'s header states each gate "SELF-DETECTS whether it has
anything to run and reports SKIP rather than FAIL when the code it would check does not exist
yet." The flaw is that the predicate conflates *"the gate does not exist"* with *"the gate
exists but is not executable."*

## Why it leaks

**Reproduced.** In a scratch clone, clearing the exec bit on `check-license-headers.sh`,
`ground-check.sh` and `go-workspace-gate.py`, and adding a header-less
`data-plane/NOHEADER.go`, produced:

```
[SKIP] license-headers — scripts/check-license-headers.sh absent
[SKIP] ground-check    — scripts/ground-check.sh absent
[SKIP] go-workspace    — scripts/go-workspace-gate.py absent
```

The license gate went dark, did **not** catch the un-headered file, and the aggregate
reported GREEN. The whole change is a one-bit file-mode delta (`100755` → `100644`) that a
reviewer must spot as `old mode / new mode` in a diff — subtle and easy to miss.

Constitution Principle VI requires *"the green gate to be machine-checked, not honor-system."*
A gate a mode bit can hollow is honour-system. Combined with 20260727-008 (a one-line
`go.work` edit drops the data plane) and 20260727-012 (the gate's verdict depends on the
host), the single green gate the constitution leans on is currently the project's weakest
link.

An agent commit — including one driven by the `agent-task.yml` workflow — is a plausible
vector for an accidental mode change, not only a malicious one.

## Suggested fix

1. Invoke gates by interpreter rather than exec bit: `bash scripts/check-license-headers.sh`,
   `python3 scripts/go-workspace-gate.py`.
2. Distinguish the two cases: a gate script that is **absent** may SKIP; one that is
   **present but not executable / not runnable** must **FAIL**. The honest-SKIP design stays
   intact for genuinely-unbuilt code.

## Regression test

A contract test asserting that each named gate script exists and is invokable, and that
clearing an exec bit yields FAIL rather than SKIP — the same negative-control discipline
`verify_discovery_test.sh` already applies to discovery logic.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S6).
- Same "green gate can be silently hollowed" class as 20260727-008.
- The prior open finding `20260706-002` was an earlier instance of the false-PASS class; its
  specific hole is closed, this one is distinct and still open.
