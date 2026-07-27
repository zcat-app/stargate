---
id: 20260706-002-detail-rejected-echo-false-pass
status: closed
severity: major
principle: [III, VII]
threat-model: n/a (test-only; log-leak class per Constitution Principle III)
location: tests/contract/control-grpc/watch_events_test.go — assertDetailRejected
first-seen-run: 2026-07-06 stargate-redteam pass on T021 (HEAD 417ca54)
first-seen-date: 2026-07-06
fix-commit: 417ca54
decision-ref: null
closed-date: 2026-07-27
closed-by: 2026-07-27 milestone audit — fix verified live at 8bc5f6a. The FindSecretLeaks
  assertion against the forbidden `detail` echo is present at
  tests/contract/control-grpc/watch_events_test.go:359-360. Was misfiled under open/ despite
  status "fixed-pre-merge".
---

# Closed-vocabulary `detail` gate false-passes when DP echoes the offending value

## What the code did before the fix

`assertDetailRejected` sent a `SidecarEvent` with an out-of-vocabulary
`detail` and asserted exactly two things: (1) the DP closes the stream
(`cs.done` fires within 10 s), and (2) `journalHasDetailViolation()`
returns true. `journalHasDetailViolation` greps the captured journal
case-insensitively for any of `{"violation", "unknown detail", "invalid
detail", "forbidden detail", "rejected"}`. The `ForbiddenDetailRejected`
sub-test did not call `assertNoSecretLeak` and never checked that the
forbidden detail string `"could not bind 0.0.0.0:9050"` was absent from
the journal.

## Why it leaks

The closed-vocabulary `detail` enforcement (contracts/control-grpc.md
§"WatchEvents · Contract") exists so that the data plane never has to
handle — and therefore never has to log — arbitrary sidecar free text,
which a maintainer could accidentally pipe in (the exact regression
scenario the gate is named for). The ticket's own §Residue states row 2
is "the ONLY gate" for this property at the contract level.

A DP that, on receiving the forbidden detail, logged

```
rejected event sidecar=tor detail="could not bind 0.0.0.0:9050"
```

to stderr (the captured journal) would PASS every assertion in the test:

- stream closes → `cs.done` fires ✓
- journal contains "rejected" → `journalHasDetailViolation()` true ✓

…while having written the offending sidecar free text (which in production
could carry hostnames, IPs, ports, timestamps) into the DP journal. That
is a Constitution Principle III tension (logs contain no per-request /
secret bytes) and defeats half the purpose of the closed-vocabulary
check. Because `ForbiddenDetailRejected` also skipped
`assertNoSecretLeak`, no other assertion caught the echo.

Adversary: anyone with read access to the DP's stderr/journal (local
process, log aggregator, VPS provider per the threat model's VPS
profile) gains the sidecar-originated text the vocabulary was designed
to keep out.

## Fix (applied pre-merge in 417ca54)

`assertDetailRejected` now additionally asserts the offending value is
absent from the journal across every encoding `findSecretLeaks` covers
(hex / base64 x4 / decimal-slice / decimal-run), so a DP that logs the
value in any common encoding is caught:

```go
if leaks := findSecretLeaks(h.journal.String(), []byte(detail)); len(leaks) != 0 {
    t.Errorf("journal echoes forbidden detail verbatim (%s) — "+
        "closed-vocabulary violation must be journaled without the "+
        "offending sidecar free-text (constitution Principle III)",
        strings.Join(leaks, ", "))
}
```

This reuses the existing `findSecretLeaks` machinery (dpharness_test.go)
for free, inherits its multi-encoding coverage, and keeps failure
messages encoding-name-only (no byte values) per the established
index-only hygiene.

Two minor hardening items fixed alongside in the same commit:

- **Plaintext `%q` in failure messages** — `socks5ConnectReply`'s
  auth-failure `t.Fatalf` previously interpolated the plaintext via `%q`;
  removed, since failure output lands in CI logs (index-only hygiene).
- **Hash+salt not in the leak-scan set** — the two route-observation
  sub-tests previously called `mintToken(t, plaintext)` inline and
  scanned only `[]byte(plaintext)`. Now `tok := mintToken(...)` is
  captured and `assertNoSecretLeak(t, h, tok.GetHash(), tok.GetSalt(),
  []byte(plaintext))` matches T020's discipline.

## Why this is the right home for the fix

`assertDetailRejected` is the shared seam T070b sub-test (e) reuses for
the failure-transition pairings per the T021 task body. Fixing it here
hardens both call sites at once; T070b cannot be authored against a
weaker version of this helper.

## Related

- Ticket §Residue item 2 explicitly flags row 2 as the sole gate for
  closed-vocabulary enforcement; this finding closed the hole the
  residue note named.
- Mirrors the 20260706-001 finding pattern (a contract test's leak
  scan under-pinning the no-log clause) found in T020's redteam pass.
