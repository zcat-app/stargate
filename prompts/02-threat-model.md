# Prompt 02 — Write the threat model

Goal: produce `THREAT-MODEL.md` at the repo root, the document referenced by
Constitution Principle V ("Honest Threat Model") and Principle VIII (used as
input to `stargate-redteam`).

## Before you start

Read these in order:

1. `.specify/memory/constitution.md` — especially Principle V, the Non-Goals
   section, and Principle III (privacy mechanics).
2. `specs/000-architecture/spec.md` — concrete decisions (ports, profiles,
   sidecars) you will reference.

If `specs/000-architecture/spec.md` doesn't exist yet, **stop** and complete
prompt 01 first. The threat model must reference concrete architecture.

## Deliverable

Create `THREAT-MODEL.md` at the repository root. Tone is **honest, technical,
and humble** — no marketing claims, no "fully anonymous" overstatements. The
audience is a privacy-conscious user evaluating whether to trust Stargate,
plus a future security reviewer doing adversarial analysis.

### Required sections

1. **Purpose** — one paragraph: what this document is, what it isn't, how it
   relates to the constitution.
2. **Adversary classes** — the threat actors Stargate considers and their
   capabilities. At minimum: passive observer on the local link; passive
   observer on the upstream link; active network-level adversary; VPS
   provider (when applicable); hostile destination; compromised sidecar;
   malicious browser extension; OS-level attacker (out of scope). For each,
   state what they can observe and what they can manipulate.
3. **Per-deployment-mode threat models** — one subsection each for **Local**,
   **LAN**, **VPS**. For each:
   - What is protected (what observation does this mode prevent)
   - What is NOT protected
   - Trusted parties (and what they can observe)
   - Residual risks
   - Concrete attacks not mitigated
4. **Per-route threat models** — one subsection each for **Direct**,
   **Tor (onion)**, **Tor (clearnet exit)**, **I2P**, **Nym mixnet**.
   For each:
   - Anonymity property this route provides (and the academic basis)
   - Anonymity property it does NOT provide
   - Observable metadata that leaks (SNI, exit-node visibility, timing
     correlation susceptibility, etc.)
   - Side-channel concerns (latency fingerprinting, traffic shape)
5. **Cross-cutting concerns** — failure modes that span routes/modes:
   - Clock skew (Tor circuits silently fail)
   - DNS leaks (mitigated by SOCKS5h — explain mechanism)
   - WebRTC leak (mitigated by extension — explain)
   - DoH leak (mitigated by extension)
   - QUIC fallback (mitigated by extension)
   - SNI leakage to clearnet exits (inherent; ECH partial mitigation)
   - Browser fingerprinting (Stargate does not address; reference Mullvad
     Browser)
   - Sidecar compromise (each sidecar is in the privacy TCB; isolation
     mechanisms via Docker)
   - Update channel compromise (mitigated by Principle IV)
   - Per-first-party-domain stream isolation (mitigates cross-site
     correlation through shared Tor circuits)
6. **What Stargate does not protect against** — restate the Non-Goals from
   the constitution with one-paragraph elaboration each, written in the
   user's terms (not just principle language).
7. **Comparison with adjacent tools** — Tor Browser, Mullvad Browser
   standalone, raw Tor + Firefox, Nym client standalone. Honest pros/cons
   versus Stargate. Avoid "we're better" — focus on "different shape,
   different tradeoffs."
8. **Known weaknesses and open research areas** — places where we know the
   design is imperfect and accept it (e.g., timing-correlation resistance
   limits). Honest documentation prevents user over-trust.
9. **Reporting vulnerabilities** — pointer to how to report security
   issues responsibly (refer to `CONTRIBUTING.md` once it exists).

### Constraints

- **Cite sources** for any claim about Tor / I2P / Nym design properties —
  link to design papers, official docs, or published research where possible.
  Where you cannot, mark `[needs citation]` rather than asserting.
- **No claims that contradict published research.** If Tor's design paper
  says "global passive adversary can correlate," do not write "Stargate
  defeats global passive adversaries via Tor."
- **No marketing-style language.** Replace "Stargate guarantees…" with
  "Stargate routes traffic through Tor's standard SOCKS5 interface, which
  provides Tor's documented anonymity properties for that traffic class."
- **Stay aligned with the constitution's Non-Goals** — every non-goal is
  a threat we explicitly do not address.

### Definition of done

- File exists at `THREAT-MODEL.md`.
- All 9 sections present.
- Every adversary-class capability claim is testable (an auditor could
  verify or falsify it).
- Cross-cutting mitigations cite the principle that enforces them.
- Reader walks away knowing precisely what Stargate protects and doesn't.

When done, list any open questions for the user (citations you couldn't
resolve, design choices you flagged as needing review).
