# Future work — ideas, not commitments

> **Status: a memory aid, not a roadmap.** Captures features that have been
> considered and survived a Constitution-fit check, with the architectural
> constraints that any future spec must honour. Nothing here is scheduled,
> staffed, or promised. v1 (`specs/001-tor-route/`) finishes first; the
> vertical-slice contract has to be proven end-to-end before anything in this
> file moves to a numbered spec.
>
> When an item here moves to a real spec, it gets a `specs/NNN-feature/`
> directory, a Constitution Check in its `plan.md`, and a row in
> `THREAT-MODEL.md` — and the entry in this file is replaced with a one-line
> pointer to the spec. Entries here are deliberately more detailed than a
> backlog and less detailed than a spec.

Last updated: 2026-07-04

---

## FW-1: Malicious-URL reputation check (extension-side warning interstitial)

### The idea

The browser extension consults an in-package blocklist of known malicious
websites when the user enters or navigates to a URL, and surfaces a warning
interstitial if there's a hit. The user can dismiss the warning and proceed;
the data plane dumb-forwards whatever the user accepts.

### Where it fits

**Extension, not proxy.** Principle I (data plane = dumb router: no payload
parsing, no TLS termination, no header inspection, no local DNS) is binding
and load-bearing here — a blocklist check at the proxy requires reading the
destination host off the request, which is header inspection. Definitively
out at the data plane. The extension already sees the destination URL and
already makes the per-request route decision, so the warning is in-lane
rather than a new surface.

A small control-plane role: an admin-UI page to view the bundled blocklist
version + a manual-refresh command. Still ship-in-package, not runtime-fetch.

### Constraints any future spec must honour

1. **In-package, digest-pinned.** The blocklist ships with the release
   artefact; never fetched at runtime. Runtime fetch would leak "this user is
   checking URL X" to whoever hosts the list. CONTRIBUTING.md §"Code style /
   Browser extension" already enforces this for the existing extension
   blocklist — same rule, second bundle. Principle IV (digest-pin every
   external component) bites on the list source.
2. **Flag, not block.** Preserve user agency. The Constitution's posture is
   privacy-first, not paternalistic — the warning is a nudge, the user
   decides, the data plane forwards whatever they accept. A spec that proposes
   hard-blocking is a Constitution-amendment discussion, not a feature
   decision.
3. **Blocklist source is a trust artefact.** Whoever curates the list (Google
   Safe Browsing, URLVoid, a community list) shapes what users get warned
   about — that's a content-curation decision with its own bias surface.
   Principle VI (Open and Auditable) requires the source, version, and
   provenance to be inspectable in the release artefact, not opaque. The
   spec names the upstream, the update cadence, and the override path.

### Smells to surface in the spec, not relitigate later

- **List bias is a privacy-adjacent surface.** A list that systematically
  over-warns on some categories of site and under-warns on others shapes
  user behaviour even when warnings are dismissable. The spec calls this out
  honestly rather than presenting the list as neutral.
- **"Known malicious" is a moving target.** Domains are registered, taken
  down, re-registered; lists go stale. The spec defines a maximum-staleness
  invariant (blocklist version older than N days = visible degraded-mode
  indicator in the extension UI).
- **Override audit.** If a warning is dismissable, the dismissal is an audit
  event (no URL, no PII — just "warning dismissed for an entry in blocklist
  version V at time T", recorded per FR-008's aggregate-counter pattern).

### Do not start before

- `specs/001-tor-route/` vertical slice is `done` (the dumb-router contract
  must be proven before layering new extension behaviour on top of it).
- A second route (I2P, Nym, or Direct) has landed, so the extension's
  route-selection UI has a non-trivial surface to compose with.

---

## FW-2: Multi-engine search merge (sibling service, not stargate)

### The idea

A service that triggers a search across multiple engines (Google, Bing,
DuckDuckGo, etc.), merges the results with per-engine attribution, and
presents the user with a unified list that surfaces engine bias — "found in
A, omitted from B". The goal is to make search-engine reality-shaping
visible rather than to build a better single search engine.

### Where it fits

**Sibling service in the same Docker compose stack, consuming stargate's
SOCKS5/CONNECT port like any other client. NOT part of stargate itself.**

The constraint is Principle I + the CONTRIBUTING doctrine ("No outbound
network connections from Stargate except those a request explicitly routes
through"). Search-merge fundamentally requires *something* to make outbound
HTTPS to N search engines on the user's behalf. If that something is
stargate's data plane, it violates Principle I (the dumb router makes no
outbound on its own behalf). If it's the control plane, it violates Principle
II's spirit (CP-side features needing outbound don't survive CP being
unreachable) and creates a privacy-leak surface (CP now knows every search
query). Both are out.

What's left is a sibling service — call it `search-fanout` for want of a
better name — that runs as another compose service and makes its outbound
requests *through* stargate's port 8881 exactly like a browser does. From
stargate's perspective, `search-fanout` is just another client on the
loopback interface. stargate's architecture is unchanged.

### Why this is interesting *next to* stargate specifically

Without stargate, multi-search is a strict privacy regression: your query
now reaches N engines instead of 1, increasing correlation surface.

With stargate, each engine's query can route through a **different anonymity
network** — Google via Tor, Bing via Nym, DuckDuckGo via I2P — so the
engines see N unrelated anonymous clients, not one user making N queries.
That collapses the correlation surface back to (or below) the single-engine
baseline. **This is the feature's reason to exist alongside stargate rather
than as a generic search aggregator.** A generic multi-search tool that
doesn't route per-engine is just a worse privacy bet than picking one engine.

### Constraints any future spec must honour

1. **Separate codebase, separate feature number, separate threat model.**
   Search-fanout lives in its own repo (or its own top-level directory with
   its own `specs/NNN-search-fanout/` if it shares the stargate repo), its
   own Constitution Check, its own `THREAT-MODEL.md` entry. It does NOT
   become a `data-plane/internal/` package. The dumb-router invariant is
   preserved by construction.
2. **Per-engine attribution is tamper-evident.** The whole value proposition
   is "see what each engine found and omitted" — so the merge must preserve
   per-engine attribution all the way to the UI. If the merge ever silently
   re-ranks, the project has invented a new biased search engine with extra
   steps. The spec names an invariant: the raw per-engine result lists are
   always viewable alongside the merge.
3. **Per-engine route selection.** Each engine's queries route through a
   distinct anonymity network (the stargate synergy above). The spec pins
   the default mapping (engine → route) and the rotation policy.
4. **Failure modes are visible, not silent.** Engines change their HTML
   constantly; scrapers break; an engine rate-limits the exit node. The UI
   surfaces "this engine's results are stale or unavailable" explicitly
   rather than silently falling back to fewer engines.

### Smells to surface in the spec, not relitigate later

- **Result-merge logic is itself a bias surface.** Deduplication, ranking,
  and presentation choices shape what the user sees. The merge algorithm is
  a content decision and needs the same Open-and-Auditable treatment as the
  FW-1 blocklist.
- **Scraping ToS.** Most engines' terms prohibit automated querying; routing
  through anonymity networks doesn't change the legal posture. The spec
  calls this out honestly and considers API-based paths where they exist
  (with the caveat that APIs require keys, which are identity tokens —
  tension with the anonymity goal).
- **Query-logging at the merge layer.** The sibling service sees every
  search the user makes. Its own logging posture must mirror stargate's
  (no per-query logs; aggregate counters only) or it becomes the very leak
  surface the user is trying to escape.

### Do not start before

- `specs/001-tor-route/` vertical slice is `done`.
- At least two distinct non-Direct routes are shipping (so per-engine route
  diversity is real, not aspirational — Tor + Direct is no diversity at all
  from the engines' perspective).
- stargate has a documented extension/client API surface that
  `search-fanout` can target as a stable consumer.

---

## Items considered and rejected

(none yet — when an item is proposed and dropped after evaluation, record it
here with the reason so the same idea isn't re-evaluated from scratch.)

---

## Maintenance

This file is updated via `docs:` commits (no ticket required — pure-doc, per
`docs/process/workflow.md §"Pure-doc commits"`). When an item moves to a
real spec, replace its full entry here with a one-line pointer to the new
spec directory and a "promoted on YYYY-MM-DD" note. When an item is rejected,
move it to §"Items considered and rejected" with the reason.

The Constitution remains authoritative. If anything here conflicts with a
Constitution principle, the Constitution wins; either this file is wrong
(fix it) or the Constitution needs an amendment through the documented
governance flow (don't paper over the conflict).
