#!/usr/bin/env python3
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""Capture and validate per-ticket tests-first evidence for Principle VII.

Usage: test-first-evidence.py red|green TNNN -- command [args...]
       test-first-evidence.py check TNNN

The red record retains the exact pre-fix diff and probe output. The green
record binds the implemented source diff. This proves the evidence belongs to
the candidate; a reviewer still judges whether the probe falsifies the spec
property and whether a failure is merely missing tooling.
"""

import hashlib
import json
import pathlib
import re
import subprocess
import sys


def fail(message):
    raise SystemExit(f"test-first-evidence: {message}")


def run(*args):
    return subprocess.check_output(args)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def paths(ticket):
    matches = list(pathlib.Path("specs").glob(f"*/tickets/{ticket}-*.md"))
    if len(matches) != 1:
        fail(f"expected one ticket for {ticket}; found {len(matches)}")
    ticket_path = matches[0]
    feature = ticket_path.parent.parent
    evidence_path = feature / "evidence" / f"{ticket}-tests-first.json"
    status_path = feature / "STATUS.md"
    return ticket_path, evidence_path, status_path


def source_patch(base, ticket_path, evidence_path, status_path):
    # The ticket status and generated board change during phase transitions.
    # Evidence cannot hash itself. All other tracked/staged source is bound.
    excluded = [ticket_path, evidence_path, status_path]
    pathspec = [".", *(f":(exclude){path}" for path in excluded)]
    # Git commits the index. A passing probe runs against the worktree, so
    # these must agree before either capture or review can claim one snapshot.
    if subprocess.run(["git", "diff", "--quiet", "--", *pathspec], check=False).returncode != 0:
        fail("staged source differs from working source")
    return run("git", "diff", "--cached", "--no-ext-diff", "--binary", base, "--", *pathspec)


def current_base(ticket):
    baseline_file = pathlib.Path("target/runs") / f"{ticket}.start-sha"
    if not baseline_file.is_file():
        fail("missing task start SHA; start through run-task.sh")
    base = baseline_file.read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", base):
        fail("invalid task start SHA")
    if run("git", "rev-parse", "HEAD").decode().strip() != base:
        fail("HEAD no longer matches the task baseline")
    return base


def read_evidence(path):
    if not path.is_file():
        fail(f"missing required evidence: {path}")
    try:
        return json.loads(path.read_text())
    except (ValueError, UnicodeDecodeError) as exc:
        fail(f"invalid evidence JSON: {exc}")


def validate_red(record, ticket, base):
    if record.get("schema") != 1 or record.get("ticket") != ticket or record.get("baseline") != base:
        fail("evidence identity or baseline mismatch")
    red = record.get("red")
    if not isinstance(red, dict):
        fail("missing red record")
    patch = red.get("patch")
    if not isinstance(patch, str) or not patch:
        fail("missing pre-fix patch")
    if digest(patch.encode(errors="surrogateescape")) != red.get("snapshot_sha256"):
        fail("pre-fix patch hash mismatch")
    if not isinstance(red.get("command"), list) or not red["command"] or not all(isinstance(arg, str) for arg in red["command"]):
        fail("missing red probe command")
    if not isinstance(red.get("exit_code"), int) or red["exit_code"] == 0:
        fail("red probe did not fail")
    if not isinstance(red.get("output"), str) or not red["output"].strip():
        fail("missing failing probe result")


def validate_green(record, patch):
    green = record.get("green")
    if not isinstance(green, dict):
        fail("missing green record")
    if green.get("snapshot_sha256") != digest(patch):
        fail("implemented source snapshot mismatch")
    if green["snapshot_sha256"] == record["red"]["snapshot_sha256"]:
        fail("red and green source snapshots are identical")
    if not isinstance(green.get("command"), list) or not green["command"] or not all(isinstance(arg, str) for arg in green["command"]):
        fail("missing green probe command")
    if green["command"] != record["red"]["command"]:
        fail("red and green probe commands differ")
    if green.get("exit_code") != 0 or not isinstance(green.get("output"), str):
        fail("green probe did not pass")


def execute(command):
    if not command or not all(isinstance(arg, str) and arg for arg in command):
        fail("command is required after --")
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    except OSError as exc:
        fail(f"probe could not execute: {exc}")
    return completed.returncode, completed.stdout.decode(errors="replace")


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in {"red", "green", "check"} or not re.fullmatch(r"T\d+[a-z]?", sys.argv[2]):
        fail("usage: red|green TNNN -- command [args...] | check TNNN")
    mode, ticket = sys.argv[1:3]
    if mode == "check":
        if len(sys.argv) != 3:
            fail("check accepts only a ticket ID")
        command = None
    else:
        if len(sys.argv) < 5 or sys.argv[3] != "--":
            fail("red/green require -- command [args...]")
        command = sys.argv[4:]
    ticket_path, evidence_path, status_path = paths(ticket)
    base = current_base(ticket)
    if mode == "check":
        if subprocess.run(["git", "ls-files", "--error-unmatch", "--", str(evidence_path)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            fail("evidence file is not staged")
        if subprocess.run(["git", "diff", "--quiet", "--", str(evidence_path)],
                          check=False).returncode != 0:
            fail("staged evidence differs from working evidence")
    patch = source_patch(base, ticket_path, evidence_path, status_path)
    if not patch:
        fail("source snapshot is empty; stage the spec-derived test first")
    if mode == "red":
        code, output = execute(command)
        if code == 0 or not output.strip():
            fail("red probe must fail with an observable property result")
        record = {"schema": 1, "ticket": ticket, "baseline": base,
                  "red": {"patch": patch.decode(errors="surrogateescape"), "snapshot_sha256": digest(patch),
                          "command": command, "exit_code": code, "output": output}}
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(record, indent=2) + "\n")
    else:
        record = read_evidence(evidence_path)
        validate_red(record, ticket, base)
        if mode == "green":
            if command != record["red"]["command"]:
                fail("green must rerun the red probe command")
            code, output = execute(command)
            if code != 0:
                fail(f"green probe failed with exit {code}: {output}")
            record["green"] = {"snapshot_sha256": digest(patch), "command": command,
                               "exit_code": code, "output": output}
            evidence_path.write_text(json.dumps(record, indent=2) + "\n")
        validate_green(record, patch)
    print(f"test-first-evidence: {ticket} {mode} OK ({evidence_path})")


if __name__ == "__main__":
    main()
