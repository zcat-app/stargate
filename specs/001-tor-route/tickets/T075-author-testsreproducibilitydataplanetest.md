---
id: T075
title: 'Author `tests/reproducibility/data_plane_test.sh`'
status: done
created: 2026-07-04
last_updated: 2026-10-10
source: tasks.md#T075
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T009", "T155", "T156"]
parallel: true
files_budget: 6
privacy_critical: false
complexity: medium
risk: low
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §12.1
  - .specify/memory/constitution.md §VI
decision_refs: []
reviews: { round: 2, date: "2026-10-10", verdict: ESCALATE, candidate: 26e513fe6e782cc313ebf90165546f45980d973aaa80849cd18eba0b78acc2a7, reviewers: "GLM APPROVE (minor future-mutation test gap); Astra ESCALATE only for omitted whole-repository verifier" }
overrides: [{"date":"2026-10-10","by":"user","decision":"Limit verification to T075's affected parts; do not run whole scripts/verify.sh or unrelated suites","reason":"The user explicitly directed affected-part-only verification for the remaining batch. The candidate records passing focused tests, a real two-build comparison, and a Gate-5-only result. Astra's sole escalation requires the expressly prohibited whole-repository verifier; its code and acceptance findings were otherwise met, and GLM approved."}]
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T075: Author `tests/reproducibility/data_plane_test.sh`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

This ticket implements Constitution VI's byte-reproducible Go data-plane tier
and records the build inputs and comparison evidence needed to audit it.

> **Full task body (verbatim from tasks.md):**
>
> Author `tests/reproducibility/data_plane_test.sh` — build the data-plane Go binary twice in clean containers (matching arch §12.1) and `cmp` the output; CI runs this on every PR touching `data-plane/`.

## Acceptance

1. `tests/reproducibility/data_plane_test.sh` builds the Dockerfile's pinned
   `builder` target twice with `--no-cache`, extracts only
   `/out/stargate-proxy`, requires both files to be nonempty, and compares
   their bytes. The two builds use one local Docker platform; the test does
   not compare final image metadata or claim cross-platform identity.
2. Each invocation fails if Docker or its daemon is unavailable, a build or
   extraction fails, an output is missing or empty, or the outputs differ.
   Cleanup is bounded to that invocation's two uniquely named containers,
   image tags, and temporary directory; no global prune is allowed.
3. Gate 5 of `scripts/verify.sh` preserves its existing all-script release
   behavior when `STARGATE_VERIFY_REPRO_ONLY` is unset. When set, the value
   must name one exact `.sh` basename in `tests/reproducibility/`; empty,
   path-like, glob-like, unmatched, or disabled-Gate-5 selections fail closed.
   Selected success explicitly reports that sibling and release-wide
   reproducibility gates were not run.
4. The existing `.github/workflows/docker-cadence.yml` remains the only CI
   entrypoint and selects `data_plane_test.sh` through `scripts/verify.sh` on
   every PR/push touching the data-plane build inputs (`data-plane/**`,
   `proto/**`, `.dockerignore`) or the selector/test/workflow wiring. It does
   not enable the unrelated JVM, extension, or Tor reproducibility scripts.
5. `data_plane_repro_gate_test.sh` passes from the repository root. It
   exercises Gate 5 selection and failure accounting, workflow path/entrypoint
   wiring, and fake-Docker equal, mismatched, missing, empty, and failed-build
   cases including named cleanup. The actual two-build comparison passes on
   the local Docker daemon.

## Out-of-scope

This ticket does not change Go source, the Dockerfile, build flags, the
extension/JVM/Tor reproducibility checks, or the final image. It does not
claim cross-architecture output identity. Architecture §12.1 also names
`GOFLAGS=-mod=readonly`, which the current Dockerfile and Makefile do not set;
this test records the gap but does not change those producers or assert that
the flag is present.

## Verification evidence

Executed against this T075 candidate on 2026-10-10:

- `bash tests/contract/workflow/data_plane_repro_gate_test.sh` — exit 0;
  output: `PASS: data_plane_repro_gate_test.sh — Gate 5 selection, workflow
  inputs, and bounded Docker failure cleanup.` This includes assertions for
  the actual Docker build argv (`--no-cache --target builder --file
  data-plane/Dockerfile`), acquired-versus-removed image/container sets,
  invocation-scoped names, green and partial-failure cleanup, and a controlled
  mutation removing `--no-cache`; the mutation was rejected by the argv check.
- `bash tests/reproducibility/data_plane_test.sh` — exit 0; output reported
  builder `golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c`,
  platform `linux/x86_64`, and `PASS: two independent linux/x86_64 builds
  produced identical nonempty data-plane binaries.`
- The production Gate 5 block was extracted from `scripts/verify.sh` into a
  temporary focused harness at
  `.scratch/tmp/T075-round2-evidence/gate5-only.sh`. Invocation:
  `STARGATE_VERIFY_REPRO=1 STARGATE_VERIFY_REPRO_ONLY=data_plane_test.sh bash .scratch/tmp/T075-round2-evidence/gate5-only.sh`
  — exit 0; output included `[PASS] repro:data_plane_test.sh` and
  `RESULT: GREEN — Gate 5 only; no other verifier gates executed.` This is a
  Gate-5-only result, not a whole-verifier result.
- `python3 scripts/lint-ticket.py specs/001-tor-route/tickets/T075-author-testsreproducibilitydataplanetest.md`
  — exit 0; ticket lint reported `OK`.
- `bash -n scripts/verify.sh tests/reproducibility/data_plane_test.sh tests/contract/workflow/data_plane_repro_gate_test.sh`
  — exit 0; no syntax diagnostics.
- `shellcheck -i SC2012,SC2015,SC2148,SC2164 scripts/verify.sh tests/reproducibility/data_plane_test.sh tests/contract/workflow/data_plane_repro_gate_test.sh`
  — exit 0; no diagnostics.
- `python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/docker-cadence.yml"))'`
  — exit 0; workflow YAML parsed.
- `git diff --check` — exit 0; no whitespace errors.

Per the user's affected-part verification instruction, the full
`scripts/verify.sh` command was not run. No Java or unrelated suites were run.
These results do not claim a whole-verifier GREEN.

## Notes

The existing Docker-cadence workflow owns the Docker runner and remains the
single CI command surface, per T076. Gate 5 selection is exact-basename only
so a path or glob cannot silently broaden or miss coverage. The focused
workflow harness extracts the production Gate 5 block, avoiding execution of
unrelated verification gates during focused validation.
