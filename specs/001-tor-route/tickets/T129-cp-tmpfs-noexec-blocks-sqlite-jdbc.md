---
id: T129
title: 'CP crash-loop: noexec tmpfs /tmp blocks sqlite-jdbc native lib'
status: done
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T122]   # needs buildable images; discovered on the first CP boot ever (T059 live chain)
parallel: false   # same compose file family as T125's publish fix; lands with it
files_budget: 2
privacy_critical: false   # boot mechanics; the exec relaxation is confined to the CP's own tmpfs
complexity: low
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md#FR-012   # CP persistence (SQLite) is the surface that cannot initialise
   - specs/001-tor-route/tasks.md#T059   # discoverer (live run, 2026-09-07)
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

# T129: CP crash-loop: noexec tmpfs /tmp blocks sqlite-jdbc native lib

## Context

Hand-filed from T059's live chain (2026-09-07). On its FIRST boot under
`docker-compose.local.yml` ever, the control plane crash-loops:

```
ERROR [org.sqlite.SQLiteJDBCLoader] Failed to load native library:
sqlite-…-libsqlitejdbc.so … failed to map segment from shared object
```

sqlite-jdbc extracts its native library to `java.io.tmpdir` (/tmp) and
mmaps it with PROT_EXEC. The T094b hardening shape mounts the CP's /tmp
as a tmpfs — and Docker's tmpfs default options are `noexec` (probed:
default → `rw,nosuid,nodev,noexec`; `--tmpfs /tmp:rw,exec` → exec
honoured). read-only rootfs + tmpfs /tmp with noexec ⇒ the CP can never
open its SQLite database ⇒ no persistence, no token load, no
ReloadTokens push — the DP rejects every request (AUTH failures) and the
full vertical is dead. Masked until now: the CP image had never been run
(see T122/T123/T124/T125 — same discovery chain); the CP's own Maven
tests run on the host filesystem, not under the container tmpfs.

## Analysis

*(Quick pass — one mount option.)*

- **Fix (chosen):** allow exec on the CP's /tmp tmpfs only
  (`tmpfs: ["/tmp:rw,exec"]` — engine-honoured, probed above). The JVM
  requires an executable tmpdir for sqlite-jdbc (and various JNI
  libraries); there is no declarative compose way to carve an exec
  sub-path, and redirecting java.io.tmpdir onto the persistent state
  volume would scatter native caches into operator data.
- **Rejected:** dropping the tmpfs (read-only rootfs leaves no /tmp at
  all); redirecting TMPDIR to stargate-control-state (mixes runtime
  caches into operator state; same executability question on the volume,
  which IS exec-capable but pollutes state).
- **Residue:** exec-on-/tmp slightly widens what a code-execution
  primitive inside the CP could do with a written file — accepted: the
  CP already runs trusted application code, and the alternative is a CP
  that cannot boot. The DP (scratch runtime, no JVM) needs no change.

## Acceptance

1. A freshly provisioned stack (operator-provisioned keys per T059
   §Residue) brings stargate-control to healthy — no crash-loop; the CP
   log shows the SQLite connection open and the seeded tokens.yaml loaded.
2. `docker exec` (or procfs) confirms /tmp mounted without noexec on the
   CP only; the DP's /tmp stays noexec.
3. `bash scripts/verify.sh` GREEN (structural compose contract intact).

## Out-of-scope

- Re-litigating the T094b read-only/caps/tmpfs hardening beyond this
  single mount option.
- The DP's tmpfs (static scratch runtime; unaffected).
