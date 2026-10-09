---
id: T064
title: 'Author the curated leak corpus for shared error scans'
status: in-progress
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T064
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T063", "T155", "T156"]
parallel: true
files_budget: 3   # leak-corpus.txt, this ticket, generated STATUS
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md SC-004 and User Story 3 (fixed privacy-safe failure surfaces)'
  - 'specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant"'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"Invariants enforced by the contract test"'
decision_refs:
  - 'T063 completed synthetic corpus at tests/integration/synthetic_onion_corpus.txt; copy entries byte-for-byte'
  - 'T172 selected acceptance: shared scanner input for SOCKS failure replies, logs, and renderer-only HTTP format; runtime values injected by tests'
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T064: Author the curated leak corpus for shared error scans

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Author the curated leak corpus `tests/contract/error-template/leak-corpus.txt` (**SC-004** anchor — this corpus is the substring set every error-template response is scanned against by T065–T068, gating SC-004's "no leak-corpus match in any of the four error-code responses") per `contracts/error-template.md` §"Leak-corpus invariant" — the SC-001/002 reference target onion; the 100-domain synthetic corpus from T063; placeholder lines for the data plane's egress IP and a representative Tor exit IP filled in at test time; version-string fragments (`Tor`, `Quarkus`, `Hibernate`, `SQLite`, `Mandrel`); backtrace fragments (`panic:`, `goroutine`, `stack trace`, `at line`).

## Analysis

- **Must hold:** the static corpus contains the reference onion, all 100
  checksum-valid synthetic onion strings from T063 copied verbatim, and every
  stable version/header/backtrace substring required by
  `contracts/error-template.md`. Entries remain plain substrings, one per LF
  line, with no blank lines, comments, or duplicates.
- **Gated:** a focused Python check compares the file byte-for-byte with the
  expected sequence derived from T063 plus the pinned static entries; it checks
  count, order, uniqueness, LF-only encoding, and one trailing newline.
- **Residue:** runtime egress/exit IPs, offered tokens, destinations, and
  control-port events vary per test. Consumers append those values to their
  in-memory scan set; this ticket must not persist run-specific values in the
  shared file. Existing consumers do not yet all load this file; T065–T073
  own their respective scanner wiring and behavior.

## Acceptance

1. Add only `tests/contract/error-template/leak-corpus.txt` as the implementation
   artifact. It contains exactly, in this order: the SC-001/SC-002 reference
   onion; the 100 lines from `tests/integration/synthetic_onion_corpus.txt`
   copied byte-for-byte and in source order; then the stable entries
   `Server: tor/`, `Tor`, `Tor Browser`, `Mandrel`, `Quarkus`, `Hibernate`,
   `SQLite`, `panic:`, `goroutine`, `stack trace`, and `at line`. Do not
   regenerate, retype, normalize, or alter the synthetic addresses.
2. The file is plain UTF-8/ASCII data with LF line endings, exactly 112
   non-empty unique lines, and one final newline. It contains no comments,
   whitespace padding, runtime placeholders, host-specific addresses,
   credentials, or test-run data. Tests inject actual egress/exit IPs, tokens,
   destinations, and captured control-port events into their per-run scan set;
   those values are never written to this shared file.
3. Verify only this artifact with a focused Python assertion that reconstructs
   the expected line sequence from the reference string, the committed T063
   source file, and the pinned static fragments, then compares the expected
   bytes exactly with `leak-corpus.txt`. The check must fail on a missing,
   changed, reordered, duplicated, blank, CRLF, or extra entry. Run the same
   check after any correction. Do not run unrelated language suites or the
   repository-wide verification gate for this data-only ticket.

## Out-of-scope

- No Go/Java implementation or scanner/test rewiring; T065–T073 own their
  consumers under the T172/T173 refinements.
- No live Tor, Docker, network, IP discovery, or host-specific data capture.
- No renderer or HTTP-ingress claim on Tor port 8881; HTTP format remains
  renderer-only under the selected contract.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**Refinement (2026-09-07, post-T063).** The "100-domain synthetic corpus
from T063" entries must be embedded verbatim from the committed
`tests/integration/synthetic_onion_corpus.txt` (T063, done; final corpus
bytes landed in commit `ddc51b9`). Do NOT retype, regenerate, or "fix" the
addresses: T063's round-1 corpus bytes were malformed (wrong v3 byte order)
and were regenerated in round 2 — copying from any pre-`ddc51b9` source
embeds dead strings into the leak corpus and silently voids their SC-004
coverage. (T063 round-1/2 verdict follow-up; recorded here because
`target/runs/*.verdict` is gitignored.)

## T172 selected acceptance (supersedes conflicting historical task text)

Keep the curated corpus as a shared scanner input for fixed SOCKS failure replies, logs, and the renderer-only future HTTP format. Runtime values are injected by tests; no HTTP response on Tor port 8881 is assumed.
