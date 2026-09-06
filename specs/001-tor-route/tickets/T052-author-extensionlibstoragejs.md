---
id: T052
title: 'Author `extension/lib/storage.js`'
status: in-progress
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T052
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh; T009 done — runnable
parallel: true
files_budget: 4   # tightened at /start: storage.js + storage.test.js + this
                  # ticket (+ STATUS.md regen — excluded per ticket-template.md)
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/tasks.md#T052 (verbatim body: thin async wrappers over browser.storage.local.get/set for the device schema)"
  - "specs/001-tor-route/data-model.md §5 (device schema: device.{name, bearerToken: 32-char lowercase hex, tokenStoredAt: <hourBucket>}; validation lives in the options page, NOT here)"
  - "specs/000-architecture/spec.md §14.4 (storage.local layout the device field extends; §14.3–§14.5: lib scripts are classic scripts sharing one background-page global scope)"
  - "specs/001-tor-route/research.md §6 (storage.local is the accepted v1 token path; warning text owned by T056/data-model §5.1 — not this module)"
  - "specs/001-tor-route/research.md §10 (node:test + node:assert, no third-party JS deps, no package.json; discovery runner)"
decision_refs:
  - "T051 /start grounding (502f71d): background.scripts pins exactly four paths with lib/storage.js listed second (load order firstparty → storage → hardening → router); manifest is single-owned — T052 amends no manifest key"
  - "extension/lib/firstparty.test.js (T034d + T034g round-1 FINDINGS[1] precedent): MV2 classic-script surface exclusivity — assert exactly-one-new-global, an extra top-level binding is a namespace-collision surface"
  - "specs/001-tor-route/tickets/T034b-unit-test-for-extensionbackgroundhardeni.md (round-1 APPROVE precedent: recording browser mock via vm.runInNewContext, node:test, discovery runner picks the file up with no runner amendment)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T052: Author `extension/lib/storage.js`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `extension/lib/storage.js` — thin async wrappers over `browser.storage.local.get/set` for the device schema in data-model.md §5.

## Analysis

Quick-pass property map (privacy_critical: false, complexity: low; grounded
2026-09-06 in the isolated t052 worktree off 502f71d).

**Consumers (who this surface exists for):** `background/router.js` (T054)
reads the bearer token for the SOCKS5 password inside `proxy.onRequest`;
`options/options.js` (T056) writes the validated token + device name. Both
are internal callers inside the extension trust boundary — per the working
doctrine ("no defensive code inside trust boundaries"), this module does
**not** validate token format; data-model.md §5 puts `^[0-9a-f]{32}$`
validation "in the options page".

**Must-hold properties:**

- P1 — get/set fidelity: the stored `device` value round-trips verbatim;
  no shape invention on read (absent key resolves `undefined`, never a
  fabricated default device).
- P2 — schema stamping: `setDeviceToken` stamps `tokenStoredAt` with the
  current hour-bucket and preserves sibling fields (notably `name`) — the
  schema in data-model.md §5 carries all three fields together.
- P3 — async contract: every wrapper returns a Promise (router.js awaits
  inside `proxy.onRequest`; a sync throw/sync return would break T054).
- P4 — surface exclusivity: lib scripts share one background-page global
  scope (arch §14.3–14.5; T034g) — exactly one new global (`StargateStorage`),
  no other top-level bindings.

**Gated by:** `extension/lib/storage.test.js` (node:test, recording
`browser.storage.local` mock, discovered automatically by
`extension/run-tests.sh` → verify.sh Gate 2b).

**PRIVACY-FLAG-MAYBE-MISSET — verified at /start, flag correctly false:**
the keyword hits in this body are the schema *field name* (`bearerToken`)
and *consumer* references (T054's SOCKS5 auth), not a privacy mechanism
implemented here. The extension's privacy-critical surfaces are owned by
`privacy_critical: true` tickets — first-party computation (T034d), the
canonical storage warning (T034e/T056), hardening (T034b/T055) — and the
Constitution's privacy principles (III, V) ride on those. This module is
the plumbing between them; its failure mode is a broken wrapper (caught by
A1–A6), not a privacy leak.

**Residue (no gate catches):** hour-bucket *granularity* is spec-pinned
(`<hourBucket>` throughout data-model/arch) but the *formula* is not — this
ticket pins `Math.floor(Date.now() / 3600000)` as a ticket-level decision
(epoch seconds ÷ 3600, UTC-immune since epoch has no timezone). A wrong-but-plausible
bucket (e.g. minute bucket) would pass CI; only T054/T056 integration could
notice, and nothing consumes the value in v1 beyond display. Accepted as
low-risk residue.

## Acceptance

- **A1 — named test:** `extension/lib/storage.test.js` exists, is picked up
  by `extension/run-tests.sh` (discovery, no runner amendment), and is GREEN
  with the impl present. It was authored FIRST and demonstrated RED against
  the missing module before the impl landed (non-vacuity: each test names a
  concrete mutation of storage.js it catches).
- **A2 — get fidelity:** `StargateStorage.getDevice()` resolves the stored
  `device` value verbatim; resolves `undefined` when the key is absent.
- **A3 — set fidelity:** `StargateStorage.setDevice(d)` issues exactly one
  `browser.storage.local.set` whose argument is `{ device: d }` (data-model
  §5 key), and the value round-trips through a subsequent `getDevice()`.
- **A4 — token stamping:** `StargateStorage.setDeviceToken(t)` persists
  `bearerToken: t` and `tokenStoredAt: <hour-bucket of now>`, preserving an
  existing device's other fields (e.g. `name`); with no stored device it
  creates `{ bearerToken, tokenStoredAt }`.
- **A5 — async contract:** `getDevice`, `setDevice`, `setDeviceToken` each
  return a Promise (thenable), and rejections propagate (storage errors are
  not swallowed).
- **A6 — surface exclusivity:** evaluating storage.js in a fresh vm context
  adds exactly one global, `StargateStorage`, whose enumerable method set is
  exactly `getDevice/setDevice/setDeviceToken` (T034g namespace-collision
  surface; firstparty.test.js precedent).
- **A7 — green gate:** `bash scripts/verify.sh` GREEN from the repo root
  (Gate 2b executes the extension discovery runner).

## Out-of-scope

- Token format validation (`^[0-9a-f]{32}$`) — the options page owns it
  (data-model.md §5 "Validation in the options page"; T056).
- The canonical storage.local warning text — T056 / data-model §5.1, gated
  by T034e.
- `schemaVersion`, `routes`, `blocklist`, `hardening` fields of arch §14.4 —
  not the device schema; hardening.js (T055) owns its own record.
- Any manifest edit — T051 is the single owner of all manifest keys
  (grounding decision ref).
- Keyring/credential-grade storage — resolved for v1 by research.md §6;
  FR-019 carries the user-facing consequence instead.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
