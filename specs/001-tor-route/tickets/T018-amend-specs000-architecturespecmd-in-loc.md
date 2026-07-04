---
id: T018
title: 'Amend `specs/000-architecture/spec.md` in lock-step: §4.3 inter-plane '
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T018
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T018: Amend `specs/000-architecture/spec.md` in lock-step: §4.3 inter-plane 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Amend `specs/000-architecture/spec.md` in lock-step: §4.3 inter-plane socket bullet already replaced (during /speckit-analyze remediation, finding F6) with the two-socket / mode-0660 / per-plane-UID topology — verify at implementation time that the rendered compose / Dockerfile UIDs match (`stargate-cp` 5101, `stargate-dp` 5102, `stargate-ipc` GID 5100); §5.5 last paragraph (snapshot contents) updates to strike "+ route enable/disable mask" — the snapshot is **token-list-only** per `data-model.md` §1.4 / §2, and DP cold-start unconditionally begins DISABLED until the first `HEALTHY` event arrives; replace the struck phrase with a cross-reference to `data-model.md` §1.4 / §2 so future readers don't re-introduce the mask into the snapshot; §6.5 `audit_log.action` enum already extended (during /speckit-analyze remediation, finding F4) to include `config_error`, `sidecar_healthy`, `sidecar_unhealthy` — verify at implementation time that the enum still matches `data-model.md` §4 and that every action this feature inserts is listed; §7 Tor row updates to drop the `NEEDS CLARIFICATION` and reference FR-015's image-provenance pin; §10.1 already extended (during /speckit-analyze remediation, finding C6) with a `SOCKS5 reply` column populating AUTH_REQUIRED (sub-negotiation `0x01 0xFF` per RFC 1929 §2), ROUTE_DOWN/DISABLED (REP `0x03`), ROUTE_REFUSED (REP `0x04`), ROUTE_TIMEOUT (REP `0x06`), and BIND_REFUSED (n/a) — verify at implementation time that the rendered SOCKS5 bytes from `data-plane/internal/socks5/` match the table and that `contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"` has not drifted; §10.3 step 2 updates to change "four permitted fields" to "three permitted fields" (matches `contracts/error-template.md` §"Response body" placeholder list — `{ROUTE_LABEL}`, `{CODE}`, `{LOCAL_REFERENCE_ID}`; the off-by-one came from conflating literal template chrome with substitutions, surfaced by /speckit-analyze finding F12); §14.4 (token storage path) — the `NEEDS CLARIFICATION` marker is already resolved-for-v1 by FR-019 + `research.md` §6 (`storage.local` with the canonical UX warning text pinned in `data-model.md` §5.1); T018 propagates that resolution into arch by stripping the marker and adding the cross-reference; §15 #6 (`Manifest version`) — the open question is resolved-for-v1 per `research.md` §2's follow-up; T018 propagates by marking §15 #6 resolved with a maintenance entry that we re-verify MV2 support on each Mullvad Browser major-version bump; new §16 "Auxiliary Infrastructure Containers" already added (during /speckit-analyze remediation, finding C7) covering the docker-socket-proxy trust model — verify at implementation time that the compose service name, image digest, and proxy environment lockdown (`EVENTS=1`, `CONTAINERS=1`, `POST=0`) match the description and that T017a's `SECURITY-DECISIONS.md` entry remains the authoritative rationale.

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
