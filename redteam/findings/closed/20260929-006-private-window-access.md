---
id: "20260929-006-private-window-access"
status: "closed"
severity: "major"
principle: ["III"]
threat-model: "4.2"
location: "extension/background/router.js:372"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: "00e9c6f"
decision-ref: null
remediation-ticket: "T188"
closed-date: "2026-09-30"
closed-by: "T188 ships a fail-closed dedicated-profile baseline (manual SOCKS5 to the T186 Unix sink with proxy-side DNS, bypassed only for ICANN TLDs), startup private-window access detection that blocks protected routing and warns, and a proxy.settings tamper check; with the extension absent or lacking access in Mullvad Browser 153.3.0esr permanent private mode, .onion, .onion., mixed-case and unknown-TLD requests reach no destination, proxy or resolver, with red before green and calibrated controls"
---

# Extension without private-window access silently yields to the ordinary proxy

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A2-m4**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T188** under `specs/001-tor-route/tickets/`.
Closed by T188 (00e9c6f): `browser-profile/user.js` makes the browser's own
proxy settings fail closed for every non-ICANN name, and
`extension/background/router.js` blocks protected routing and warns while
private-window access is missing, and warns on baseline drift.
`probe.py --only private-access` is the regression; the evidence is in
THREAT-MODEL (T188) and `specs/001-tor-route/evidence/T188-tests-first.json`.
Disclosed residues (skipped baseline, emptied or garbled SOCKS pref, new-TLD
staleness) are stated in the quickstart, spec and THREAT-MODEL.
