#!/usr/bin/env python3
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""go-workspace-gate.py — the discovered Go test gate for scripts/verify.sh.

WHY THIS EXISTS (T076). The old verify.sh Gate 2 hard-coded `data-plane` and
ran `go test ./...` there only. The completed proto, contract, integration,
and shared-helper Go modules could therefore regress while verify.sh stayed
green. This gate fixes that by:

  * DISCOVERY — reading `go.work`'s `use` directives for the list of
    workspace modules. A module added to go.work is gated automatically; no
    verify.sh edit is needed (T076 §Acceptance #3: discover, don't
    enumerate six fixed directories).
  * JSON SKIP ACCOUNTING — running `go test -json` and classifying each
    package PASS / FAIL / SKIP from the event stream. Plain `go test` prints
    `ok` for a package even when every test inside it called `t.Skip()`;
    that is the masquerade this gate ends (T076 §Acceptance #2: a package
    with only skipped tests is SKIP, never PASS).
  * CADENCE SEPARATION via build tags — a test file that needs Docker, the
    live network, or a release-tag build carries `//go:build docker|live|
    release`. The hermetic PR run (default) excludes those files at compile
    time, so they cannot hang or fail the PR gate; it still compile-checks
    them with `go vet -tags 'docker live release'`, so a compile regression
    in a non-hermetic suite fails the PR gate. The named job opts back in
    with `STARGATE_TEST_TAGS=docker scripts/verify.sh` — the SAME entrypoint,
    not a divergent command list (T076 §Acceptance #4 + #5).

VERDICT RULES per package (the falsifiable contract; see
tests/contract/workflow/verify_discovery_test.sh):
  build/compile failure (vet or test)     -> FAIL   (any cadence)
  a test ran and failed                   -> FAIL
  >=1 test passed, 0 failed               -> PASS
  all tests skipped / no test files       -> SKIP   (NEVER PASS — core fix)
  all skipped AND //stargate:required     -> FAIL   (FAIL-when-required branch)
  package has test files but none ran in
   the hermetic run (all //go:build out)  -> SKIP[<cadence>]  (named job owns)

CADENCE / REQUIRED MARKERS (grep-discovered, co-located with the test):
  //go:build docker|live|release   non-hermetic; excluded from default run.
  // stargate:cadence <name>       documentation of the //go:build intent.
  // stargate:required             hermetic AND must-not-all-skip: an
                                  all-skip required package is FAIL, not SKIP.

Exit status: 1 if any package/gate is FAIL, else 0. Output is plain text on
stdout (verify.sh tees it into target/verify.log); one record per line with
a stable `pass=N fail=N skip=N` suffix makes the inventory machine-auditable.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

# Build tags used for cadence separation. A *_test.go carrying any of these
# in a `//go:build` line is non-hermetic and excluded from the default run.
_CADENCE_TAGS = ("docker", "live", "release")
_BUILDTAG_RE = re.compile(
    rb"//go:build\s+.*(?<![!\w])(" + b"|".join(t.encode() for t in _CADENCE_TAGS) + rb")\b")
_REQUIRED_RE = re.compile(rb"//\s*stargate:required\b")


def say(msg: str) -> None:
    print(msg, flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def discover_modules(repo_root: str) -> list[str]:
    """Workspace module dirs from go.work `use` directives (the explicit,
    maintained list — vs. `find -name go.mod`, which would also catch
    vendor/cache dirs). Sorted for stable output.
    """
    gowork = os.path.join(repo_root, "go.work")
    if not os.path.isfile(gowork):
        return []
    modules: list[str] = []
    in_block = False
    with open(gowork, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("use (") or line == "use(":
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            if in_block:
                if line and not line.startswith("//"):
                    modules.append(line)
                continue
            m = re.match(r"use\s+(.+)$", line)
            if m and not line.startswith("//"):
                modules.append(m.group(1).strip())
    return sorted(set(os.path.normpath(m) for m in modules))


def package_meta(pkg_dir: str) -> tuple[str | None, bool, bool]:
    """Inspect a package dir's *_test.go.

    Returns (cadence_tag, required, has_any_testfile).
      cadence_tag — docker|live|release if any *_test.go carries it in a
                    //go:build line, else None.
      required    — True if a *_test.go carries `// stargate:required`.
      has_any_testfile — True if the dir has >=1 *_test.go on disk.
    """
    cadence = None
    required = False
    has_testfile = False
    try:
        entries = os.listdir(pkg_dir)
    except OSError:
        return cadence, required, has_testfile
    for name in sorted(entries):
        if not name.endswith("_test.go"):
            continue
        has_testfile = True
        try:
            with open(os.path.join(pkg_dir, name), "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if _REQUIRED_RE.search(data):
            required = True
        m = _BUILDTAG_RE.search(data)
        if m and cadence is None:
            cadence = m.group(1).decode()
    return cadence, required, has_testfile


def list_packages(module_dir: str, tags: list[str]) -> tuple[list[tuple[str, str]], str | None]:
    """Return (packages, list_error) for `go list ./...` (honouring build tags).

    packages is [(import_path, dir)]. list_error is the combined stdout+stderr
    when `go list` exits nonzero (a compile/parse failure anywhere in the
    module — e.g. a broken shared helper every package imports, or a syntax
    error in a *_test.go), else None. Surfacing the return code is what
    prevents a whole-module compile regression from silently SKIP-ing — the
    exact class T076 exists to catch.
    """
    cmd = ["go", "list", "-f", "{{.ImportPath}}\t{{.Dir}}"]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    cmd.append("./...")
    proc = run(cmd, cwd=module_dir)
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        ip, d = line.split("\t", 1)
        out.append((ip, d))
    err = None if proc.returncode == 0 else (proc.stdout + proc.stderr)
    return out, err


def classify_json(json_text: str) -> dict[str, dict]:
    """Parse `go test -json` output into per-package counters.

    `pkg_skipped` is set from a package-level `skip` event (no Test field).
    `go test -json` emits this both for a package with zero test files on
    disk AND for some internal skip signals; the caller resolves the
    distinction via package_meta's has_any_testfile. (Renamed from
    `notestfiles` so the field name does not imply a single cause.)
    """
    pkgs: dict[str, dict] = {}
    for line in json_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        action = ev.get("Action")
        pkg = ev.get("Package")
        if not pkg or not action:
            continue
        rec = pkgs.setdefault(pkg, {"pass": 0, "fail": 0, "skip": 0,
                                    "buildfail": False, "pkg_skipped": False})
        has_test = bool(ev.get("Test"))
        if has_test:
            if action == "pass":
                rec["pass"] += 1
            elif action == "fail":
                rec["fail"] += 1
            elif action == "skip":
                rec["skip"] += 1
        else:
            if action == "fail":
                rec["buildfail"] = True
            elif action == "skip":
                rec["pkg_skipped"] = True
    return pkgs


def verdict(rec: dict, required: bool, cadence: str | None,
            has_testfile: bool) -> str:
    """Apply the verdict rules. Returns PASS|FAIL|SKIP|SKIP[<cadence>].

    Granularity is per-PACKAGE (Go's `go test` unit): a mixed package whose
    hermetic tests pass is PASS even if it also carries build-tagged
    (docker/live/release) test files; those tagged files are compile-checked
    via the `go vet -tags` pass and executed only in the named job. The
    SKIP[<cadence>] annotation is therefore emitted only for a package whose
    test files are ALL tagged out (no hermetic tests), not per-tagged-file.
    """
    if rec["buildfail"]:
        return "FAIL"
    if rec["fail"] > 0:
        return "FAIL"
    if rec["pass"] > 0:
        return "PASS"
    # all-skip / no-test-files: NEVER PASS.
    if required and has_testfile and not rec["pkg_skipped"]:
        return "FAIL"  # all-skip required package did not run — regression
    # Annotate packages whose test files are all build-tagged out.
    if rec["pkg_skipped"] and has_testfile and cadence is not None:
        return f"SKIP[{cadence}]"
    return "SKIP"


def split_tags(env: str) -> list[str]:
    return [t for t in re.split(r"[,\s]+", env.strip()) if t]


def main() -> int:
    repo_root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    repo_root = os.path.abspath(repo_root)

    if not shutil.which("go"):
        say("go-workspace: SKIP — go toolchain not installed")
        return 0
    modules = discover_modules(repo_root)
    if not modules:
        say("go-workspace: SKIP — no go.work (or no `use` directives)")
        return 0

    run_tags = split_tags(os.environ.get("STARGATE_TEST_TAGS", ""))
    named_mode = bool(run_tags)
    # Tags used ONLY to compile-check (vet) non-hermetic files in the
    # default hermetic run. In named mode the test run itself compiles them.
    vet_all_tags = [] if named_mode else list(_CADENCE_TAGS)

    say(f"go-workspace: discovered {len(modules)} module(s) via go.work: "
        + ", ".join(modules))
    if named_mode:
        say(f"go-workspace: NAMED mode — STARGATE_TEST_TAGS={','.join(run_tags)} "
            "(non-hermetic suites execute)")

    failed = 0
    skipped = 0
    passed = 0

    for mod in modules:
        mod_abs = os.path.join(repo_root, mod)
        if not os.path.isfile(os.path.join(mod_abs, "go.mod")):
            say(f"  SKIP  go:{mod} — in go.work but no go.mod (use without module)")
            skipped += 1
            continue

        env = dict(os.environ)

        # 1. gofmt — module-wide, ADVISORY (WARN, not FAIL). The test
        #    modules predate this gate and carry pre-existing gofmt drift
        #    (tab-alignment); reformatting is a separate follow-up (out of
        #    T076's files_budget). Flip to FAIL once the drift is cleaned.
        fmt = run(["gofmt", "-l", "."], cwd=mod_abs, env=env)
        badfmt = [l for l in fmt.stdout.splitlines() if l.strip()]
        if badfmt:
            say(f"  WARN  gofmt:{mod} — {len(badfmt)} unformatted file(s) "
                f"(advisory; follow-up): {' '.join(badfmt)}")
        else:
            say(f"  PASS  gofmt:{mod}")

        # 2. enumerate packages + per-package meta (cadence / required).
        pkgs, list_err = list_packages(mod_abs, run_tags)
        meta: dict[str, tuple] = {ip: package_meta(d) for ip, d in pkgs}

        # 2b. INVENTORY EXHAUSTIVENESS — packages whose *_test.go are ALL
        # build-tagged out (e.g. a whole-package docker suite like tor/ or
        # sidecar-proxy/) are dropped by `go list ./...` in the hermetic run
        # and would otherwise DISAPPEAR from the inventory. T076 §Analysis
        # residue: "live/release-only tests remain explicit SKIP with a named
        # cadence and cannot disappear from the inventory." Surface them by
        # diffing the hermetic package set against the all-cadence-tags set.
        hidden: list[tuple[str, str]] = []
        hidden_err = None
        if not named_mode:
            hermetic_ips = {ip for ip, _ in pkgs}
            all_pkgs, hidden_err = list_packages(mod_abs, list(_CADENCE_TAGS))
            for ip, d in all_pkgs:
                if ip not in hermetic_ips:
                    hidden.append((ip, d))
                    meta[ip] = package_meta(d)

        # 2c. A nonzero `go list` (hermetic OR cadence-tags) means a
        # compile/parse failure anywhere in the module — a broken shared
        # helper every package imports, a go.mod/toolchain conflict, or a
        # *_test.go syntax error. This is the worst-case regression T076
        # exists to catch; it must FAIL, not silently SKIP as "go list
        # empty". (Without this check an all-broken module would fall through
        # to the `if not pkgs and not hidden: SKIP` short-circuit below.)
        list_any_err = list_err or (hidden_err if not hidden else None)
        if list_any_err:
            say(f"  FAIL  go-list:{mod} — `go list` nonzero "
                f"(compile/parse error); see target/verify.log")
            sys.stderr.write(list_any_err)
            failed += 1
            continue

        if not pkgs and not hidden:
            say(f"  SKIP  go:{mod} — `go list ./...` empty (no Go packages)")
            skipped += 1
            continue

        has_tagged_files = any(cad is not None
                               for (cad, _r, _h) in meta.values())

        # 3. go vet — hermetic compile+vet (only when hermetic packages
        #    exist, so an all-docker module does not spuriously FAIL on
        #    `go vet`'s "matched no packages" nonzero), plus a cadence-tags
        #    pass (only when tagged files exist) so a compile regression in
        #    a build-tagged suite still fails the PR gate.
        vet_failures = []
        if pkgs:
            vcmd = ["go", "vet"]
            if run_tags:
                vcmd += ["-tags", ",".join(run_tags)]
            vcmd.append("./...")
            vet1 = run(vcmd, cwd=mod_abs, env=env)
            if vet1.returncode != 0:
                vet_failures.append(vet1.stdout + vet1.stderr)
        if vet_all_tags and has_tagged_files:
            vet2 = run(["go", "vet", "-tags", ",".join(vet_all_tags), "./..."],
                       cwd=mod_abs, env=env)
            if vet2.returncode != 0:
                vet_failures.append(vet2.stdout + vet2.stderr)
        if vet_failures:
            say(f"  FAIL  go-vet:{mod} — see target/verify.log")
            for out in vet_failures:
                sys.stderr.write(out)
            failed += 1
        else:
            say(f"  PASS  go-vet:{mod}")

        # 3c. account hidden (all-tagged-out) packages as SKIP[<cadence>].
        for ip, _d in hidden:
            cad, _req, _has = meta[ip]
            tag = cad if cad else "release"
            say(f"  SKIP[{tag}]  go:{mod}:{ip}  "
                f"— named {tag} job (all files //go:build {tag})")
            skipped += 1

        # 4. run + classify the (hermetic or named-tag) packages.
        if not pkgs:
            continue
        test_cmd = ["go", "test", "-json", "-count=1"]
        if run_tags:
            test_cmd += ["-tags", ",".join(run_tags)]
        test_cmd.append("./...")
        tproc = subprocess.run(test_cmd, cwd=mod_abs, env=env,
                               capture_output=True, text=True)
        classified = classify_json(tproc.stdout)
        for ip, _d in pkgs:
            classified.setdefault(ip, {"pass": 0, "fail": 0, "skip": 0,
                                       "buildfail": False,
                                       "pkg_skipped": False})
        # Forward stderr on any nonzero (a panic, race finding, or timeout
        # can exit nonzero without "FAIL" in stdout — keep diagnostics).
        if tproc.returncode != 0:
            sys.stderr.write(tproc.stderr)

        for ip, _d in pkgs:
            rec = classified[ip]
            cadence, required, has_tf = meta[ip]
            v = verdict(rec, required, cadence, has_tf)
            # Masking guard (stargate-redteam finding): if the test run died
            # non-zero (timeout, race, panic, or a TestMain that os.Exit-ed
            # before the JSON encoder flushed a FAIL event) AND this package
            # has test files but produced zero pass/fail/skip events, it must
            # FAIL, not SKIP — otherwise a dead privacy test masks as a clean
            # SKIP and the gate is GREEN. pkg_skipped (no test files on disk)
            # is excluded: those legitimately produced no test-level events.
            if (v == "SKIP" and tproc.returncode != 0 and has_tf
                    and not rec["pkg_skipped"]
                    and rec["pass"] == 0 and rec["fail"] == 0
                    and rec["skip"] == 0):
                v = "FAIL"
            tail = (f"pass={rec['pass']} fail={rec['fail']} "
                    f"skip={rec['skip']}")
            if v == "PASS":
                say(f"  PASS  go:{mod}:{ip}  {tail}")
                passed += 1
            elif v == "FAIL":
                say(f"  FAIL  go:{mod}:{ip}  {tail}")
                failed += 1
            else:
                say(f"  {v}  go:{mod}:{ip}  {tail}")
                skipped += 1

    state = "FAIL" if failed else "GREEN"
    say(f"go-workspace: {state} — {passed} passed, {skipped} skip, "
        f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
