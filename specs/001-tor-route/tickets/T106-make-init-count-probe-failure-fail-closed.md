---
id: T106
title: 'Make the init count-probe failure path fail-closed (no key clobber)'
status: in-progress
created: 2026-07-17
last_updated: 2026-07-18
source: redteam round-3 + codereview round-3 of T088
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: []
parallel: false
files_budget: 3
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §9.3 (idempotence; do-not-clobber-keys)
  - specs/001-tor-route/tickets/T088-repair-local-init-compose-provisioning.md §Analysis M5
decision_refs: []
remediates: T088
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T106: Make the init count-probe failure path fail-closed (no key clobber)

## Context

`scripts/subcommands/init` `generate_keys` runs a hardened helper container
to count the existing key+pepper files in the `stargate-keys` volume before
deciding whether to generate fresh keys (M5: do-not-clobber). The capture is
currently fail-OPEN:

```sh
existing=$(docker run --rm --network none … 2>/dev/null) || existing="0"
```

A transient `docker run` failure (daemon hiccup, OOM, or an attacker-induced
crash like SIGKILL on the helper between `ensure_volumes` and `generate_keys`)
defaults `existing` to `0` → init treats a populated volume as fresh →
**regenerates ed25519 keys + pepper over existing ones** → every previously
issued bearer token (HMAC'd under the old pepper) stops verifying and every
enrolled device's inter-plane public key is invalidated. This contradicts the
M5 fail-closed invariant (arch §9.3: never clobber existing keys) that T088's
own §Analysis asserts.

T088's round-3 codereview and redteam both flagged this; both classified it
**availability-only / Minor** (a confidentiality leak is NOT in scope: the
count-probe runs `--network none` non-root with stdout sanitized, so the
failure path cannot exfil; and forcing a `docker run` crash needs same-host
attacker capability = game-over per THREAT-MODEL §3.1/§2.8). Filed separately
so T088 stays surgical; the count-probe hardening that landed in T088 is
unaffected.

## Acceptance

1. `generate_keys` treats a non-zero exit from the count-probe `docker run`
   as KEYGEN failure (exit 20), NOT as "fresh volume": on helper failure,
   `note` an explicit message ("count-probe helper failed; aborting to avoid
   clobbering existing keys") and `return "$EXIT_KEYGEN"` — never default to
   `existing="0"`.
2. The pre-existing-keys paths still hold: 0/5 (fresh) → generate; 5/5 →
   skip; 1–4 → abort (unchanged); non-numeric stdout → abort without echo
   (the T088 sanitize, unchanged).
3. A Docker-backed regression case in
   `tests/contract/stargate-cli/init_docker_test.sh` (or a focused unit
   assertion) proves a failed count-probe does NOT lead to key regeneration:
   e.g. point `STARGATE_KEYGEN_IMAGE` at a non-existent digest-pinned image
   so the count-probe fails, and assert init exits 20 (not 0) and the
   pre-existing keys are byte-identical.
4. `scripts/verify.sh` is GREEN.

## Out-of-scope

- Re-litigating the count-probe's network/cap/user hardening (that landed in
  T088 and is CLEAN per redteam round 3). This ticket only flips the failure
  default from open to closed.
- The same fail-open pattern does not appear elsewhere in init's key path
  (the install helper is under `if ! docker run …`; only the count capture
  uses `|| existing="0"`).

## Notes

The fix is one line (`|| existing="0"` → fail-closed abort) plus the
regression case. Discovered during `/run T088`'s round-3 adversarial pass;
the Constitution VIII adversarial-review gate is what surfaced it.
