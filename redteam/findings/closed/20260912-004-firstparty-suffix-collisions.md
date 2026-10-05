---
id: "20260912-004-firstparty-suffix-collisions"
status: "closed"
severity: "major"
principle: ["III"]
threat-model: "5.10"
location: "extension/lib/firstparty.js:109"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: "3393309"
decision-ref: null
remediation-ticket: "T136"
closed-date: "2026-10-05"
closed-by: "T136 derives first parties from Firefox's native publicSuffix API and tests the complete router path with public/private suffix collisions such as alice/bob.co.uk and alice/bob.github.io"
---

# Distinct registrable first parties share the Tor isolation key

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M3**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Closed by T136 (3393309). `extension/background/router.test.js` and
`extension/lib/firstparty*.test.js` are the regressions. T155's (c688164) 2026-10-05 F4 run
(`TestStreamIsolationPerFirstPartyDomain` and the site axis in `partition_axes_test.go`) landed
distinct sites on distinct circuits.
