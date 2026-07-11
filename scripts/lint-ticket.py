#!/usr/bin/env python3
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""
lint-ticket.py — author-time mechanical checks for stargate ticket files.

Catches the small set of authoring errors that would otherwise cost a
clarity-subagent round. NOT a general YAML validator — targeted extraction
of the load-bearing fields, mirroring the infochat scripts/lint-ticket.py
philosophy (cheap, fast, no pyyaml dependency, fail loudly on the
specific shapes that bite).

Exit codes: 0 = clean, 1 = at least one finding.

Usage:
    python3 scripts/lint-ticket.py specs/001-tor-route/tickets/T013-*.md
    python3 scripts/lint-ticket.py specs/001-tor-route/tickets/        # all
"""

import glob
import re
import sys
from pathlib import Path

VALID_STATUS = {"pending", "in-progress", "in-review", "escalated", "done", "deferred"}
VALID_COMPLEXITY = {"low", "medium", "high"}
VALID_RISK = {"low", "medium", "high"}
VALID_DEFERRED_REASON = {"", "decomposed", "blocked-on-new-ticket", "spec-amend"}
PRIVACY_KEYWORDS = re.compile(
    r"\b(DNS|routing|SOCKS5|socks5|auth|token|sidecar|contract|bind|header|leak|crypto|ed25519|Argon2)\b",
    re.IGNORECASE,
)


def extract_frontmatter(text: str) -> dict:
    """Targeted extraction of the fields this linter checks. Returns a dict
    keyed by field name; values are the raw string after the colon (comments
    stripped, surrounding quotes stripped). List-valued fields come back as
    Python lists; scalars as strings."""
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not m:
        return {"__parse_error__": "no YAML frontmatter delimiters found"}
    fm_text = m.group(1)
    out: dict = {}
    lines = fm_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        mm = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if not mm:
            i += 1
            continue
        key, rest = mm.group(1), re.sub(r"\s+#.*$", "", mm.group(2)).rstrip()
        # Inline list.
        if rest.startswith("["):
            inner = rest.strip("[]").strip()
            if not inner:
                out[key] = []
            else:
                out[key] = [v.strip().strip("'\"") for v in inner.split(",")]
        elif rest == "":
            # Block list?
            vals = []
            j = i + 1
            while j < len(lines) and re.match(r"^\s+-\s+", lines[j]):
                vals.append(re.sub(r"^\s+-\s+", "", lines[j]).strip().strip("'\""))
                j += 1
            out[key] = vals if vals else ""
        else:
            out[key] = rest.strip("'\"")
        i += 1
    return out


def lint(path: Path) -> list:
    """Return a list of findings (strings) for one ticket file."""
    text = path.read_text()
    fm = extract_frontmatter(text)
    findings = []

    if "__parse_error__" in fm:
        return [f"PARSE: {fm['__parse_error__']}"]

    # Required fields.
    required = ["id", "title", "status", "source", "phase"]
    for k in required:
        if k not in fm or fm[k] == "":
            findings.append(f"MISSING-FIELD: required field `{k}` absent or empty")

    # status ∈ valid set.
    status = fm.get("status", "")
    if status not in VALID_STATUS:
        findings.append(
            f"INVALID-STATUS: `{status}` not in {sorted(VALID_STATUS)}"
        )

    # complexity / risk ∈ valid set.
    for field, allowed in [("complexity", VALID_COMPLEXITY), ("risk", VALID_RISK)]:
        v = fm.get(field, "")
        if v not in allowed:
            findings.append(f"INVALID-{field.upper()}: `{v}` not in {sorted(allowed)}")

    # round_cap ∈ {2, 3}; 3 only allowed for high complexity or high risk.
    rc = fm.get("round_cap", "2")
    if rc not in ("2", "3"):
        findings.append(f"INVALID-ROUND-CAP: `{rc}` must be 2 or 3")
    elif rc == "3":
        if fm.get("complexity") != "high" and fm.get("risk") != "high":
            findings.append(
                "ROUND-CAP-MISMATCH: round_cap=3 requires complexity: high or risk: high"
            )

    # deferred_reason must match a known value when status=deferred.
    if fm.get("status") == "deferred":
        reason = fm.get("deferred_reason", "")
        if reason not in VALID_DEFERRED_REASON:
            findings.append(
                f"INVALID-DEFERRED-REASON: `{reason}` not in {sorted(VALID_DEFERRED_REASON - {''})}"
            )
        if not fm.get("deferred_on"):
            findings.append("DEFERRED-WITHOUT-ON: status=deferred requires deferred_on:")

    # privacy_critical heuristic cross-check: if the title or context body
    # mentions a privacy keyword but privacy_critical is false, WARN. The
    # bootstrap script's keyword scan is the authoritative initial guess; this
    # catches the case where a human flipped the flag to false on a task whose
    # body still names a privacy surface. WARN only — keyword match is not
    # proof.
    pc = fm.get("privacy_critical", "false")
    if pc == "false":
        # Re-read body (everything after frontmatter) for keyword scan.
        body_match = re.search(r"^---\n.*?\n---\n(.*)$", text, re.DOTALL)
        body = body_match.group(1) if body_match else ""
        if PRIVACY_KEYWORDS.search(body) and "Constitution" not in body:
            # Avoid firing on tasks that explicitly discuss the flag itself.
            findings.append(
                "PRIVACY-FLAG-MAYBE-MISSET: body mentions a privacy keyword "
                "(DNS/routing/auth/...) but privacy_critical: false — verify"
            )

    # Title length ≤ 70 (Constitution-style soft limit, mirrors infochat).
    title = fm.get("title", "")
    if len(title) > 70:
        findings.append(
            f"TITLE-TOO-LONG: {len(title)} chars (max 70): `{title[:60]}...`"
        )

    # blocked_by entries should reference real ticket ids (T-NNN shape).
    deps = fm.get("blocked_by", [])
    if isinstance(deps, list):
        for d in deps:
            if not re.match(r"^T\d+[a-z]?$", d):
                findings.append(
                    f"INVALID-DEP-ID: blocked_by entry `{d}` is not T-NNN shape"
                )

    # tests_first: explicit Principle-VII directed metadata (T096 / sol-review
    # M6). Each entry must be T-NNN shape. For a privacy_critical ticket, every
    # named test MUST also appear in blocked_by — otherwise the impl would be
    # runnable before its test, violating Constitution Principle VII. This is
    # the machine-checkable form of "tests-first for privacy-critical code".
    tf = fm.get("tests_first", [])
    if isinstance(tf, list) and tf:
        for t in tf:
            if not re.match(r"^T\d+[a-z]?$", t):
                findings.append(
                    f"INVALID-TESTS-FIRST-ID: tests_first entry `{t}` is not T-NNN shape"
                )
        if pc == "true":
            dep_set = set(deps) if isinstance(deps, list) else set()
            missing = [t for t in tf if re.match(r"^T\d+[a-z]?$", t) and t not in dep_set]
            if missing:
                findings.append(
                    "TESTS-FIRST-VIOLATION: privacy_critical ticket names "
                    f"tests_first {missing} but they are absent from blocked_by "
                    "— the impl would be runnable before its Principle-VII test. "
                    "Add them to blocked_by (scripts/derive-deps.sh does this)."
                )

    # Lineage cross-checks (informational when inconsistent).
    if fm.get("decomposed_from") and fm.get("status") != "deferred":
        # decomposed_from is allowed on a replacement ticket; otherwise odd.
        pass  # soft — not worth a finding on its own

    return findings


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    paths: list = []
    for arg in sys.argv[1:]:
        if Path(arg).is_dir():
            paths.extend(sorted(Path(arg).glob("T*-*.md")))
        else:
            paths.extend(sorted(Path(".").glob(arg)))

    if not paths:
        print("lint-ticket: no ticket files matched", file=sys.stderr)
        return 2

    total_findings = 0
    for p in paths:
        findings = lint(p)
        if findings:
            total_findings += len(findings)
            print(f"{p}:")
            for f in findings:
                print(f"  {f}")
        else:
            print(f"{p}: OK")

    if total_findings:
        print(f"\n{total_findings} finding(s) across {len(paths)} ticket(s).")
        return 1
    print(f"\nAll {len(paths)} ticket(s) clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
