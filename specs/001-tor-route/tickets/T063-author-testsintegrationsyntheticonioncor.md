---
id: T063
title: 'Author `tests/integration/synthetic_onion_corpus.txt`'
status: in-progress
created: 2026-07-04
last_updated: 2026-09-07
source: tasks.md#T063
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 3   # raw-diff-path counting (run-task.sh): 1 data file + this ticket + STATUS.md regen, per the T116 convention (ticket-template.md excludes specs/ paths)
privacy_critical: false
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md SC-002 (100 distinct first-party .onion domains, synthetic corpus published in tests/integration/)'
  - 'specs/001-tor-route/spec.md §Assumptions — reference-target bullet (synthetic corpus of 100 distinct onion-style address strings; reachability not required, only that the Tor sidecar attempts distinct circuits)'
  - 'specs/001-tor-route/tasks.md#T063'
  - 'specs/001-tor-route/research.md §7 (the SC-002 corpus run goes against the real Tor sidecar — within its normal load envelope)'
decision_refs:
  - 'T061 (direct consumer: `circuit_isolation_corpus_test.go` reads the corpus, one CONNECT per line)'
  - 'T064 (downstream consumer: leak-corpus.txt embeds every corpus entry as a must-not-appear substring)'
  - 'contracts/error-template.md §"Leak-corpus invariant" (every synthetic .onion string from this corpus enters the leak corpus)'
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T063: Author `tests/integration/synthetic_onion_corpus.txt`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `tests/integration/synthetic_onion_corpus.txt` — 100 distinct onion-style address *strings* (well-formed but not necessarily reachable; the property under test is circuit selection, not reachability, per research.md §7 / spec Assumptions).

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

The corpus file exists at `tests/integration/synthetic_onion_corpus.txt` and
satisfies all of the following (each is falsifiable by the runnable check
below):

- **A1 — shape**: exactly 100 lines; LF line endings; a single trailing
  newline; no comments, no blank lines, no leading/trailing whitespace.
  Lines are consumed verbatim by T061 (one SOCKS5 CONNECT target per line)
  and embedded verbatim as substrings by T064 — so the file carries *data
  only*, no prose.
- **A2 — well-formed v3**: every line matches `^[a-z2-7]{56}\.onion$`
  (canonical lowercase base32). "Well-formed" is the strong sense per
  rend-spec-v3 §[ONIONADDRESS]: the 35-byte payload is
  `key(32) ‖ checksum(2) ‖ version(1)` in exactly that order, with
  `checksum = SHA3-256(".onion checksum" ‖ key ‖ version)[:2]` and version
  byte `0x03`. A random-looking string that fails the checksum is *not*
  well-formed: the real-Tor sidecar (research.md §7 — the SC-002 run uses
  real Tor) rejects it at parse time and never attempts a circuit, which
  would make T061's ≥95-distinct-circuits assertion untestable. The 32-byte
  keys are random, so the services are unreachable in practice (no
  descriptor exists) — exactly the spec-Assumptions pairing of "well-formed
  but not necessarily reachable". (Cheap invariant: with version `0x03`
  last, every correct address's 56th base32 char is `d`.)
- **A3 — distinctness**: all 100 addresses are pairwise distinct
  (SC-002: "100 distinct").
- **A4 — no reference-target conflation**: the corpus does NOT contain the
  SC-001/SC-002 reference target
  `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion` — that
  address enters the leak corpus via its own dedicated line
  (contracts/error-template.md §"Leak-corpus invariant") and is reachable,
  unlike every corpus entry.
- **A5 — runnable check** (the acceptance command; exit 0 = pass):

  ```sh
  python3 - <<'PY'
  import base64, hashlib, re, sys
  raw = open("tests/integration/synthetic_onion_corpus.txt", "rb").read()
  assert b"\r" not in raw, "CR found — LF only"
  assert raw.endswith(b"\n") and not raw.endswith(b"\n\n"), "single trailing newline"
  lines = raw.decode().splitlines()
  assert len(lines) == 100, f"expected 100 lines, got {len(lines)}"
  assert len(set(lines)) == 100, "duplicate addresses"
  assert "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion" not in lines
  for ln in lines:
      assert re.fullmatch(r"[a-z2-7]{56}\.onion", ln), f"bad shape: {ln}"
      blob = base64.b32decode(ln[:56].upper())
      key, chk, version = blob[:32], blob[32:34], blob[34]
      assert version == 3, f"bad version byte: {ln}"
      want = hashlib.sha3_256(b".onion checksum" + key + bytes([version])).digest()[:2]
      assert chk == want, f"checksum mismatch: {ln}"
  print("OK: 100 distinct, checksum-valid v3 .onion addresses")
  PY
  ```

## Out-of-scope

- **No Go code, no test logic** — T061 (`circuit_isolation_corpus_test.go`)
  and T064 (`leak-corpus.txt`) author their own consumers; this ticket ships
  the data file only.
- **Not the reference target onion** — the DuckDuckGo address is pinned in
  spec §Assumptions and is T064's separate line item (see A4).
- **No torrc / compose / sidecar changes** — the corpus never names real
  infrastructure, and per spec §Assumptions reachability is explicitly not
  a property of these addresses.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**Quick analysis pass (not privacy-critical, complexity low — §Analysis
omitted per its own instruction).** What must hold: the three corpus
properties A1–A3 (shape, well-formedness, distinctness) plus the A4
non-conflation. Which gates catch it: none — `verify.sh` has no gate that
inspects a `.txt` corpus, so the §Acceptance A5 command IS the check, and
T061's integration test fails loudly if a line ever drifts malformed.
Residue no gate catches: silent post-hoc edits to the corpus (a hand-tweak
that breaks checksum validity or reintroduces the reference target) pass
verify.sh green; mitigation is the A5 command recorded here for re-runs and
T061 consuming the file verbatim.

**Provenance / regeneration.** The file is generated deterministically
(100 32-byte keys expanded as `SHA-256("stargate T063 synthetic onion
corpus" ‖ big-endian uint32 index)` for index 0..99 → each address is
lowercase `base32(key ‖ SHA3-256(".onion checksum" ‖ key ‖ 0x03)[:2] ‖
0x03) + ".onion"` per rend-spec-v3 §[ONIONADDRESS]), so a re-run of the
documented procedure is byte-stable and the corpus is auditable without
trusting the author. The generator lives in the implementation commit
message; the committed artifact is pure data per A1. *(Round-1 correction:
the first generation assembled the payload as key ‖ version ‖ checksum —
caught by codereview round 1 against the rend-spec byte order and the
published reference addresses; corpus and A5 regenerated in the correct
order.)*

**Parallel note (2026-09-07).** Run concurrently with T062 by explicit user
instruction. Both tickets' file sets are disjoint (`tests/contract/tor/
control_port.go` vs `tests/integration/synthetic_onion_corpus.txt`); the
only shared mutation points are STATUS.md regen and the git index, both
safe under retry. Neither ticket carries `parallel: true` (tasks.md gives
neither a `[P]` marker); the marker's worktree-disjointness precondition
holds anyway, which is what makes the user's override sound.
