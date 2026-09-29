---
id: "20260929-004-blocked-null-is-direct"
status: "closed"
severity: "major"
principle: ["III"]
threat-model: "4.2"
location: "extension/background/router.js:381"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: "aed38cc"
decision-ref: null
remediation-ticket: "T186"
closed-date: "2026-09-29"
closed-by: "T186 returns an unreachable Unix-socket SOCKS5h sink plus terminal null for every blocked protected path; with the cancel listener removed, .onion, .onion., mixed-case and unmapped forms reach no destination, proxy, SOCKS or resolver in Mullvad Browser 153.3.0esr, with red before green and calibrated controls"
---

# Blocked protected proxy result is Firefox explicit DIRECT

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A2-M1**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T186** under `specs/001-tor-route/tickets/`.
Closed by T186 (aed38cc): `extension/background/router.js` returns
`[{socks, file:///dev/null/stargate-blocked, proxyDNS}, null]` instead of
`null` for every blocked protected request and classifies all trailing-dot
and case variants as protected. `probe.py --only blocked-proxy` (cancel
listener removed) and `--only descriptor-matrix` are the regression; the
evidence is in THREAT-MODEL (T186) and
`specs/001-tor-route/evidence/T186-tests-first.json`.
