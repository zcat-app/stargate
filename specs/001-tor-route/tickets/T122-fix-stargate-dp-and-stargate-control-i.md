---
id: T122
title: 'Fix DP/CP image builds: proto/ outside build contexts'
status: done
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: []
parallel: true
files_budget: 4   # compose/docker-compose.local.yml + data-plane/Dockerfile + control-plane/Dockerfile (+ this ticket)
privacy_critical: false   # build plumbing; gates the runtime privacy tests (US1/US2 scenarios) but is not itself a privacy surface
complexity: low
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md §"User Story 1" acceptance scenario 1   # "docker-compose.local.yml up" — the acceptance scenarios presuppose the stack BUILDS
   - specs/001-tor-route/tasks.md#T059   # discoverer: live run failed at `docker compose up -d --build` (2026-09-07)
decision_refs: []
reviews: { round: 1, date: 2026-09-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T122: Fix stargate-dp/stargate-control image builds: repo-top proto/ outside the build contexts

## Context

Hand-filed from T059's live run (2026-09-07): `docker compose up -d --build`
of `compose/docker-compose.local.yml` fails building `stargate-dp` —

```
go: github.com/zcat-app/stargate/proto@v0.0.0-00010101000000-000000000000
(replaced by ../proto): reading /proto/go.mod: no such file or directory
The command '/bin/sh -c go mod download' returned a non-zero code: 1
```

Root cause (both images, same class):

- `data-plane/go.mod` carries `replace github.com/zcat-app/stargate/proto =>
  ../proto` (needed for standalone module builds), and the DP source imports
  the generated stubs. The compose build context is `../data-plane`, so the
  builder never sees `../proto` — `go mod download` AND `go build` both fail.
  The DP image has been unbuildable since the DP started importing the
  generated stubs (T009/T046); only the tor service had ever been built live
  (T019b/T032/T058/T058a).
- `control-plane/api/pom.xml` points Quarkus gRPC codegen at
  `${project.basedir}/../../proto/stargate/v1` (repo-top `proto/`). The CP
  build context is `../control-plane`, so codegen would fail the same way —
  masked in the T059 run because compose aborted at the DP failure first.

Every full-vertical runtime test (T033, T059, T060, T061, T070, …) is blocked
by this; the hermetic PR gate never builds images, which is why it stayed
green.

## Analysis

*(Quick pass — non-privacy, low complexity.)*

- **Fix (chosen):** move the two Stargate-built images' build contexts to the
  repo root (`context: ..`, `dockerfile: <plane>/Dockerfile`) and copy the
  `proto/` module to `/proto` in each Dockerfile — satisfying both
  consumers' `../proto`-style relative references verbatim (go.mod's
  `replace => ../proto` from `/src`; the pom's `basedir/../../proto` from
  `/src/<module>`). COPY paths inside the Dockerfiles gain their `data-plane/`
  (resp. `control-plane/`) prefix; the DP keeps its dep-layer/source-layer
  cache split by copying `go.mod`+`go.sum` of BOTH modules in the dep layer.
  The tor service (self-contained context) is untouched.
- **Rejected:** (a) `build.additional_contexts` — couples compose+Dockerfile
  to a BuildKit-specific surface for no gain over a root context; (b) vendoring
  the generated stubs into each plane — duplicates generated code and breaks
  T009's single-proto-source layout; (c) rewriting go.mod/pom paths — the
  repo-relative layout is the workspace contract (go.work + both module
  docs); the image should mirror it, not fight it.
- **Residue:** a repo-root context ships the whole tree to the daemon
  (no .dockerignore exists; context-transfer cost is local-dev noise, and
  explicit COPY paths keep layer cache keys tight). The structural compose
  contract (`local_compose_test.sh`) asserts user:/UID/volumes, not build
  contexts — verified no gate pins the old context shape.

## Acceptance

1. `docker compose -p t122-check -f compose/docker-compose.local.yml --env-file compose/env/local.env.example build stargate-dp stargate-control tor`
   succeeds on a clean tree (all three images build; `go mod download`,
   `go build`, and the Maven codegen/package all resolve `proto/`).
2. The built DP image runs: the binary starts and fails fast on its
   composition-dependent surfaces only (no listener assertions here — the
   full-vertical behaviour is T059/T033's gate).
3. `bash scripts/verify.sh` GREEN — hermetic gates (incl. compose structural
   contracts) unaffected.

## Out-of-scope

- Any runtime-behaviour change (ports, users, volumes, networks, entrypoints)
  — build topology only.
- Adding a root `.dockerignore` (worthwhile, but its exclude list deserves
  its own ticket once image builds are exercised in CI).
- Reproducibility gates for the images (T075/T081 territory; build flags are
  untouched by this fix).
