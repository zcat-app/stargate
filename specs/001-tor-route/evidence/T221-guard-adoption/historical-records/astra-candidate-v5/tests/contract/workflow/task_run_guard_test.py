#!/usr/bin/python3
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the opt-in task-run admission guard."""
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
GUARD = pathlib.Path(os.environ.get("TASK_RUN_GUARD", ROOT / "scripts/task-run-guard.py"))
DRIVER = pathlib.Path(os.environ.get("TASK_RUN_DRIVER", ROOT / "scripts/run-task.sh"))
REPORTS = ROOT / ".scratch/reports/2026-10-13-fresh-session/guard"


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


class GuardCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="task-run-guard-")
        self.root = pathlib.Path(self.tmp.name)
        self.script = self.root / "cmd.py"
        self.script.write_text("import os,sys\nopen(os.environ['MARKER'],'a').write('ran\\n')\n")
        self.script.chmod(0o644)
        self.policy_path = self.root / "policy.json"
        self.journal = self.root / "journal.jsonl"
        self.plan = self.root / "plan.md"
        self.plan.write_text("approved plan\n")
        self.review_a = self.root / "astra.json"
        self.review_l = self.root / "luna.json"
        self._review(self.review_a, "astra", "gpt-6-astra")
        self._review(self.review_l, "luna", "gpt-6-luna")
        self.policy = {
            "schema": "task-run-guard-policy-v1", "run_id": "fixture-run",
            "journal_path": str(self.journal), "deadline_epoch": int(time.time()) + 90,
            "maximum_attempts": 8, "maximum_failed_attempts": 3, "phase": "review",
            "plan": self._pin(self.plan),
            "reviews": [self._review_pin(self.review_a, "astra", "gpt-6-astra"),
                        self._review_pin(self.review_l, "luna", "gpt-6-luna")],
            "candidates": [self._pin(GUARD), self._pin(self.script), self._pin("/usr/bin/python3")],
            "actions": {"safe": {"phase": "review", "enabled": True, "blocked_reason": "",
                "argv": [str(pathlib.Path("/usr/bin/python3").resolve()), "-I", "-S", str(self.script)], "cwd": str(self.root),
                "env": {"PATH": "/usr/bin:/bin", "MARKER": str(self.root / "marker")},
                "timeout_seconds": 5}},
        }
        self.write_policy()

    def tearDown(self):
        self.tmp.cleanup()

    def _pin(self, path):
        st = pathlib.Path(path).stat()
        return {"path": str(pathlib.Path(path).resolve()), "sha256": digest(path), "mode": st.st_mode & 0o777}

    def _review(self, path, role, model, verdict="APPROVE", plan_hash=None):
        body = {"schema": "task-run-guard-review-v1", "role": role, "model": model,
                "effort": "high", "verdict": verdict,
                "plan_sha256": plan_hash or digest(self.plan), "findings": []}
        pathlib.Path(path).write_text(json.dumps(body, separators=(",", ":")) + "\n")

    def _review_pin(self, path, role, model):
        pin = self._pin(path)
        return {**pin, "role": role, "model": model, "effort": "high"}

    def write_policy(self):
        self.policy_path.write_text(json.dumps(self.policy, separators=(",", ":")) + "\n")

    def invoke(self, action="safe", extra=(), env=None, timeout=8):
        return subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), *extra,
                               "run", str(self.policy_path), digest(self.policy_path), action],
                              cwd=self.root, env=env or os.environ.copy(), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)

    def check(self, action="safe"):
        return subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "check",
                               str(self.policy_path), digest(self.policy_path), action],
                              cwd=self.root, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=5)

    def assert_blocked(self, mutate):
        mutate()
        self.write_policy()
        r = self.check()
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))
        self.assertFalse((self.root / "marker").exists())

    def test_allowed_exact_child_runs_once(self):
        r = self.invoke()
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertEqual((self.root / "marker").read_text(), "ran\n")
        direct = subprocess.run([str(GUARD), "check", str(self.policy_path), digest(self.policy_path), "safe"],
                                cwd=self.root, text=True, capture_output=True, timeout=5)
        self.assertEqual(direct.returncode, 0, (direct.stdout, direct.stderr))

    def test_disabled_phase_review_and_pin_fail_closed(self):
        self.assert_blocked(lambda: self.policy.update(phase="implement"))
        self.policy["phase"] = "review"
        self.assert_blocked(lambda: self.policy["actions"]["safe"].update(enabled=False, blocked_reason="blocked"))
        self.policy["actions"]["safe"].update(enabled=True, blocked_reason="")
        self.assert_blocked(lambda: self.policy["reviews"].pop())

    def test_review_identity_verdict_plan_and_candidate_changes_block(self):
        self.review_l.write_text(self.review_l.read_text().replace('"verdict":"APPROVE"', '"verdict":"REWORK"'))
        self.assertEqual(self.check().returncode, 78, "changed review bytes escaped the original pin")
        self._review(self.review_l, "luna", "gpt-6-luna", verdict="REWORK")
        self.policy["reviews"][1] = self._review_pin(self.review_l, "luna", "gpt-6-luna")
        self.write_policy()
        self.assertEqual(self.check().returncode, 78)
        self._review(self.review_l, "astra", "gpt-6-astra")
        self.policy["reviews"][1] = self._review_pin(self.review_l, "astra", "gpt-6-astra")
        self.write_policy()
        self.assertEqual(self.check().returncode, 78)
        self._review(self.review_l, "luna", "gpt-6-luna", plan_hash="f" * 64)
        self.policy["reviews"][1] = self._review_pin(self.review_l, "luna", "gpt-6-luna")
        self.write_policy()
        self.assertEqual(self.check().returncode, 78)
        self._review(self.review_l, "luna", "gpt-6-luna")
        self.policy["reviews"][1] = self._review_pin(self.review_l, "luna", "gpt-6-luna")
        self.write_policy()
        self.plan.write_text("changed approved plan\n")
        self.assertEqual(self.check().returncode, 78)
        self.plan.write_text("approved plan\n")
        self.script.write_text("changed candidate\n")
        self.assertEqual(self.check().returncode, 78)

    def test_mode_and_unknown_fields_are_rejected(self):
        self.plan.chmod(0o600)
        self.assertEqual(self.check().returncode, 78)
        self.plan.chmod(0o644)
        self.policy["unknown"] = True
        self.write_policy()
        self.assertEqual(self.check().returncode, 78)

    def test_argv_script_input_must_have_a_pin(self):
        self.policy["candidates"] = [self.policy["candidates"][0], self.policy["candidates"][2]]
        self.write_policy()
        r = self.check()
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))

    def test_fifo_policy_refuses_without_blocking(self):
        fifo = self.root / "policy.fifo"
        os.mkfifo(fifo)
        proc = subprocess.Popen(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "check",
            str(fifo), "0" * 64, "safe"], cwd=self.root, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        try:
            out, err = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=1)
            self.fail("guard blocked opening a FIFO policy")
        self.assertEqual(proc.returncode, 78, (out, err))

    def test_postcondition_pin_change_is_sticky(self):
        self.script.write_text(f"from pathlib import Path\nPath({str(self.plan)!r}).write_text('changed')\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.write_policy()
        self.assertEqual(self.invoke().returncode, 78)
        self.plan.write_text("approved plan\n")
        r = self.check()
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))

    def test_sigterm_stops_child_group_and_records_sticky_attempt(self):
        marker = self.root / "child.pid"
        self.script.write_text(f"import os,time\nopen({str(marker)!r},'w').write(str(os.getpid()))\ntime.sleep(30)\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.policy["actions"]["safe"]["timeout_seconds"] = 20
        self.write_policy()
        guard = subprocess.Popen(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "run",
            str(self.policy_path), digest(self.policy_path), "safe"], cwd=self.root,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(.01)
        self.assertTrue(marker.exists(), "child did not start")
        child_pid = int(marker.read_text())
        guard.send_signal(signal.SIGTERM)
        guard.wait(timeout=3)
        remains = True
        try:
            os.killpg(child_pid, 0)
        except ProcessLookupError:
            remains = False
        if remains:
            try:
                os.killpg(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.assertEqual(guard.returncode, 130)
        self.assertFalse(remains, "child process group survived guard interruption")
        self.assertEqual(self.check().returncode, 78, "interrupted attempt did not remain sticky in journal")

    def test_deadline_uses_monotonic_budget_after_spawn(self):
        self.script.write_text("import time\ntime.sleep(3)\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.policy["deadline_epoch"] = int(time.time()) + 2
        self.policy["actions"]["safe"]["timeout_seconds"] = 15
        self.write_policy()
        wrapper = self.root / "clock-wrapper.py"
        wrapper.write_text("""import importlib.util, os, sys, time
spec=importlib.util.spec_from_file_location('guard', os.environ['TASK_RUN_GUARD_MODULE'])
guard=importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)
real_pin=guard.pin; real_time=time.time; count=0
def shifted_pin(*args, **kwargs):
    global count
    result=real_pin(*args, **kwargs); count+=1
    if count == 6: guard.time.time=lambda: real_time()-3600
    return result
guard.pin=shifted_pin
sys.exit(guard.main(['run', sys.argv[1], sys.argv[2], sys.argv[3]]))
""")
        env = os.environ.copy()
        env.setdefault("TASK_RUN_GUARD_MODULE", str(GUARD))
        started = time.monotonic()
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(wrapper), str(self.policy_path),
                            digest(self.policy_path), "safe"], cwd=self.root, env=env,
                           text=True, capture_output=True, timeout=5)
        self.assertEqual(r.returncode, 124, (r.stdout, r.stderr))
        self.assertLess(time.monotonic() - started, 4)

    def test_late_postcondition_cannot_return_success(self):
        self.script.write_text("pass\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.policy["actions"]["safe"]["timeout_seconds"] = 3
        self.write_policy()
        wrapper = self.root / "slow-validation-wrapper.py"
        wrapper.write_text("""import importlib.util, os, sys, time
spec=importlib.util.spec_from_file_location('guard', os.environ['TASK_RUN_GUARD_MODULE'])
guard=importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)
real_validate=guard.validate; count=0
def slow_validate(*args, **kwargs):
    global count
    result=real_validate(*args, **kwargs); count+=1
    print('VALIDATE_'+str(count), file=sys.stderr)
    if count == 2: time.sleep(3.2)
    return result
guard.validate=slow_validate
sys.exit(guard.main(['run', sys.argv[1], sys.argv[2], sys.argv[3]]))
""")
        env = os.environ.copy()
        env.setdefault("TASK_RUN_GUARD_MODULE", str(GUARD))
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(wrapper), str(self.policy_path),
                            digest(self.policy_path), "safe"], cwd=self.root, env=env,
                           text=True, capture_output=True, timeout=7)
        self.assertEqual(r.returncode, 124, (r.stdout, r.stderr))
        journal = self.check()
        self.assertEqual(journal.returncode, 78)
        self.assertIn("previous command completion is uncertain", journal.stderr)
        self.assertIn("VALIDATE_2", r.stderr)

    def test_policy_hash_duplicate_json_and_file_mode_are_checked(self):
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "check",
                            str(self.policy_path), "0" * 64, "safe"], text=True, capture_output=True)
        self.assertEqual(r.returncode, 78)
        self.policy_path.write_text('{"x":1,"x":2}')
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "check",
                            str(self.policy_path), digest(self.policy_path), "safe"], text=True, capture_output=True)
        self.assertEqual(r.returncode, 78)
        self.policy_path.write_text('{"schema":')
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "check",
                            str(self.policy_path), digest(self.policy_path), "safe"], text=True, capture_output=True)
        self.assertEqual(r.returncode, 78)

    def test_expired_deadline_and_driver_argument_mismatch_block(self):
        self.assert_blocked(lambda: self.policy.update(deadline_epoch=int(time.time()) - 1))

    def test_timeout_stops_child_and_consumes_attempt_without_retry(self):
        self.script.write_text("import time\ntime.sleep(30)\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.policy["actions"]["safe"]["timeout_seconds"] = 1
        self.write_policy()
        r = self.invoke(timeout=4)
        self.assertEqual(r.returncode, 124, (r.stdout, r.stderr))
        r2 = self.invoke(timeout=4)
        self.assertEqual(r2.returncode, 78, (r2.stdout, r2.stderr))

    def test_nonzero_failure_cap_survives_policy_filename_change(self):
        self.script.write_text("raise SystemExit(9)\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.policy["maximum_attempts"] = 5
        self.policy["maximum_failed_attempts"] = 2
        self.write_policy()
        for _ in range(2):
            self.assertEqual(self.invoke().returncode, 9)
        other = self.root / "renamed-policy.json"
        shutil.copyfile(self.policy_path, other)
        self.policy_path = other
        r = self.invoke()
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))

    def test_dangling_journal_and_nonregular_policy_refuse(self):
        self.journal.write_text('{"type":"attempt","attempt":1}\n')
        self.assertEqual(self.check().returncode, 78)
        self.journal.unlink()
        link = self.root / "policy-link.json"
        link.symlink_to(self.policy_path)
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "check",
                            str(link), digest(self.policy_path), "safe"], capture_output=True)
        self.assertEqual(r.returncode, 78)

    def test_journal_terminal_exit_and_attempt_types_are_consistent(self):
        identity = {"type":"identity", "run_id":self.policy["run_id"],
            "deadline_epoch":self.policy["deadline_epoch"], "maximum_attempts":self.policy["maximum_attempts"],
            "maximum_failed_attempts":self.policy["maximum_failed_attempts"]}
        attempt = {"type":"attempt", "number":1, "action":"safe"}
        for result, exit_code in (("ok", 7), ("failed", 0), ("ok", True)):
            rows = [identity, attempt, {"type":"result", "attempt":1, "result":result, "exit":exit_code}]
            self.journal.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))
            r = self.check()
            self.assertEqual(r.returncode, 78, (result, exit_code, r.stdout, r.stderr))
        bad_attempt = {"type":"attempt", "number":True, "action":"safe"}
        self.journal.write_text(json.dumps(identity)+"\n"+json.dumps(bad_attempt)+"\n")
        self.assertEqual(self.check().returncode, 78)

    def test_policy_mutated_by_child_prevents_success(self):
        self.script.write_text(f"from pathlib import Path\nPath({str(self.plan)!r}).write_text('mutated')\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.write_policy()
        r = self.invoke()
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))

    def test_concurrent_writer_is_refused(self):
        self.script.write_text("import time\ntime.sleep(2)\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.write_policy()
        first = subprocess.Popen(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "run",
            str(self.policy_path), digest(self.policy_path), "safe"], cwd=self.root,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not self.journal.exists():
            time.sleep(.01)
        second = self.invoke(timeout=4)
        self.assertEqual(second.returncode, 78, (second.stdout, second.stderr))
        self.assertEqual(first.wait(timeout=5), 0)

    def test_group_leftover_is_stopped_and_pipe_holder_cannot_hang(self):
        self.script.write_text("import subprocess,sys\nsubprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'])\n")
        self.policy["candidates"][1] = self._pin(self.script)
        self.write_policy()
        started = time.monotonic()
        r = self.invoke(timeout=4)
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))
        self.assertLess(time.monotonic() - started, 3)

    def test_hook_partial_environment_and_hostile_path_are_blocked(self):
        with tempfile.TemporaryDirectory(prefix="guard-hook-") as td:
            root = pathlib.Path(td)
            (root / "scripts").mkdir()
            (root / ".specify").mkdir()
            ticket_dir = root / "specs/001-test/tickets"
            ticket_dir.mkdir(parents=True)
            driver = root / "scripts/run-task.sh"
            shutil.copy2(DRIVER, driver)
            guard = root / "scripts/task-run-guard.py"
            shutil.copy2(GUARD, guard)
            (root / "scripts/review-matrix.json").write_text('{"reviewers":[]}\n')
            (root / ".specify/feature.json").write_text('{"feature_directory":"specs/001-test"}\n')
            (ticket_dir / "T900-fixture.md").write_text("---\nid: T900\ntitle: 'guarded fixture'\nstatus: in-progress\ncreated: 2026-10-13\nlast_updated: 2026-10-13\nsource: tasks.md#T900\nphase: \"1: Setup\"\nstory: '-'\nblocked_by: []\nparallel: false\nfiles_budget: 8\nprivacy_critical: false\ntest_for: []\ncomplexity: low\nrisk: low\nround_cap: 2\nspec_refs: []\ndecision_refs: []\nreviews: {}\noverrides: []\naborted_attempts: []\nreopens: []\nredteam_findings: []\nclarity_check: {}\n---\n\n# T900: guarded fixture\n\n## Context\nThis disposable ticket exercises blocked admission.\n\n## Acceptance\n- The driver blocks before handoff.\n\n## Out-of-scope\nNo production changes.\n")
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "fixture"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            marker = root / "hostile-ran"
            bash_env = root / "bash-env.sh"
            bash_env.write_text(f"echo bash-startup >> {marker}\nif declare -F imported_probe >/dev/null; then echo imported-function >> {marker}; fi\n")
            (root / "sitecustomize.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('python startup ran')\n")
            evil = root / "evil"
            evil.mkdir()
            for name in ("bash", "python3", "readlink"):
                shim = evil / name
                shim.write_text(f"#!/bin/sh\necho {name} >> {marker}\nexit 99\n")
                shim.chmod(0o755)
            for explicit in (False, True):
                args = [str(driver), "T900"] if explicit else [str(driver), "T900"]
                pp = root / f"policy-{explicit}.json"
                plan = root / "plan.md"; plan.write_text("plan\n")
                def pin(path):
                    st = pathlib.Path(path).stat()
                    return {"path":str(pathlib.Path(path).resolve()), "sha256":digest(path), "mode":st.st_mode & 0o777}
                plan_hash = digest(plan)
                reviews = []
                for role, model in (("astra","gpt-6-astra"),("luna","gpt-6-luna")):
                    rp = root / f"{role}-{explicit}.json"
                    rp.write_text(json.dumps({"schema":"task-run-guard-review-v1","role":role,"model":model,
                        "effort":"high","verdict":"APPROVE","plan_sha256":plan_hash,"findings":[]})+"\n")
                    reviews.append({**pin(rp),"role":role,"model":model,"effort":"high"})
                driver_args = ["/usr/bin/bash", "-p", str(driver.resolve()), "T900"]
                policy = {"schema":"task-run-guard-policy-v1","run_id":f"hook-{explicit}",
                    "journal_path":str(root / f"journal-{explicit}.jsonl"),"deadline_epoch":int(time.time())+60,
                    "maximum_attempts":3,"maximum_failed_attempts":2,"phase":"implement","plan":pin(plan),
                    "reviews":reviews,"candidates":[pin(guard),pin(driver),pin("/usr/bin/bash"),pin("/usr/bin/python3"),pin("/usr/bin/readlink")],
                    "actions":{"implement":{"phase":"implement","enabled":False,"blocked_reason":"blocked implementation",
                        "argv":driver_args,"cwd":str(root),"env":{},"timeout_seconds":10}}}
                pp.write_text(json.dumps(policy,separators=(",",":"))+"\n")
                env = os.environ.copy()
                env.update(STARGATE_GUARD_POLICY=str(pp), STARGATE_GUARD_SHA256=digest(pp), STARGATE_GUARD_ACTION="implement",
                           PATH=str(evil), PYTHONPATH=str(root), BASH_ENV=str(bash_env))
                env["BASH_FUNC_imported_probe%%"] = "() { :; }"
                invocation = ["/usr/bin/bash", "-p", str(driver), "T900"] if explicit else [str(driver), "T900"]
                r = subprocess.run(invocation,cwd=root,env=env,text=True,capture_output=True,timeout=8)
                self.assertEqual(r.returncode,78,(r.stdout,r.stderr))
                self.assertFalse(marker.exists())
            partial = os.environ.copy()
            partial.update(STARGATE_GUARD_POLICY="x", PATH=str(evil))
            r = subprocess.run([str(driver),"T900"],cwd=root,env=partial,text=True,capture_output=True,timeout=5)
            self.assertEqual(r.returncode,78)
            self.assertFalse(marker.exists())


class RepairRegressions(GuardCase):
    def test_deadline_expiring_during_validation_never_dispatches(self):
        self.policy["deadline_epoch"] = int(time.time()) + 1
        self.write_policy()
        wrapper = self.root / "slow-admission.py"
        wrapper.write_text("""import importlib.util,os,sys,time
spec=importlib.util.spec_from_file_location('guard',os.environ['TASK_RUN_GUARD_MODULE'])
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
real_state=g.journal_state; real_popen=g.subprocess.Popen
marker=os.environ['DISPATCH_MARKER']
def slow(*a,**k):
 time.sleep(1.4); return real_state(*a,**k)
def tracked(*a,**k):
 open(marker,'w').write('Popen reached')
 return real_popen(*a,**k)
g.journal_state=slow; g.subprocess.Popen=tracked
try: sys.exit(g.main(['run',sys.argv[1],sys.argv[2],sys.argv[3]]))
except g.Refuse as e: print('REFUSED:'+str(e),file=sys.stderr);sys.exit(78)
""")
        env=os.environ.copy(); env['TASK_RUN_GUARD_MODULE']=str(GUARD); env['DISPATCH_MARKER']=str(self.root/'dispatch-marker')
        r=subprocess.run(['/usr/bin/python3','-B','-I','-S',str(wrapper),str(self.policy_path),digest(self.policy_path),'safe'],cwd=self.root,env=env,text=True,capture_output=True,timeout=5)
        self.assertFalse((self.root/'dispatch-marker').exists(),(r.returncode,r.stdout,r.stderr))

    def test_fifo_script_input_refuses_before_dispatch(self):
        fifo=self.root/'script.fifo'; os.mkfifo(fifo)
        self.policy['actions']['safe']['argv']=[str(pathlib.Path('/usr/bin/python3').resolve()),str(fifo)]
        self.write_policy()
        payload = f"import os;open({str(self.root/'marker')!r},'w').write('ran')"
        writer_code = "import sys;open(sys.argv[1],'w').write(" + repr(payload) + ")"
        writer=subprocess.Popen(['/usr/bin/python3','-c',writer_code,str(fifo)])
        try:
            r=self.invoke(timeout=4)
        finally:
            if writer.poll() is None:
                writer.kill(); writer.wait(timeout=2)
        self.assertEqual(r.returncode,78,(r.stdout,r.stderr))
        self.assertFalse((self.root/'marker').exists())

    def test_policy_malformed_field_types_refuse_with_78(self):
        cases = ("role", "overflow", "hugeint", "reason", "bad_env")
        for case in cases:
            self.tearDown(); self.setUp()
            if case == "role":
                self.policy['reviews'][0]['role'] = []
                self.write_policy()
            elif case == "overflow":
                raw=self.policy_path.read_text().replace('"timeout_seconds":5', '"timeout_seconds":1e999')
                self.policy_path.write_text(raw)
            elif case == "hugeint":
                raw=self.policy_path.read_text().replace('"maximum_attempts":8', '"maximum_attempts":' + ('9' * 5000))
                self.policy_path.write_text(raw)
            elif case == "bad_env":
                self.policy['actions']['safe']['env']['BAD=KEY'] = 'value'
                self.write_policy()
            else:
                self.policy['actions']['safe'].update(enabled=False,blocked_reason=7)
                self.write_policy()
            r=self.check()
            self.assertEqual(r.returncode,78,(case,r.stdout,r.stderr))
            self.assertFalse(self.journal.exists())
        self.tearDown(); self.setUp()

    def test_attempt_record_short_write_never_dispatches(self):
        wrapper=self.root/'short-write.py'
        wrapper.write_text("""import importlib.util,os,sys
spec=importlib.util.spec_from_file_location('guard',os.environ['TASK_RUN_GUARD_MODULE'])
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
real=g.os.write; count=0
def short(fd,data):
 global count
 count+=1
 if count==2:
  real(fd,data[:max(1,len(data)//2)]); return 0
 return real(fd,data)
g.os.write=short
try: sys.exit(g.main(['run',sys.argv[1],sys.argv[2],sys.argv[3]]))
except g.Refuse as e: print('REFUSED:'+str(e),file=sys.stderr);sys.exit(78)
""")
        env=os.environ.copy();env['TASK_RUN_GUARD_MODULE']=str(GUARD)
        r=subprocess.run(['/usr/bin/python3','-B','-I','-S',str(wrapper),str(self.policy_path),digest(self.policy_path),'safe'],cwd=self.root,env=env,text=True,capture_output=True,timeout=5)
        self.assertEqual(r.returncode,78,(r.stdout,r.stderr))
        self.assertFalse((self.root/'marker').exists())

    def test_identity_or_attempt_write_error_refuses_without_dispatch(self):
        for fail_on in (1, 2):
            self.tearDown(); self.setUp()
            wrapper=self.root/'write-error.py'
            wrapper.write_text("""import importlib.util,os,sys
spec=importlib.util.spec_from_file_location('guard',os.environ['TASK_RUN_GUARD_MODULE'])
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
real=g.os.write;count=0;fail_on=int(os.environ['FAIL_ON'])
def broken(fd,data):
 global count
 count+=1
 if count==fail_on:
  real(fd,data[:max(1,len(data)//2)])
  raise OSError('injected bounded write failure after prefix')
 return real(fd,data)
g.os.write=broken
try: sys.exit(g.main(['run',sys.argv[1],sys.argv[2],sys.argv[3]]))
except g.Refuse as e: print('REFUSED:'+str(e),file=sys.stderr);sys.exit(78)
""")
            env=os.environ.copy();env['TASK_RUN_GUARD_MODULE']=str(GUARD);env['FAIL_ON']=str(fail_on)
            r=subprocess.run(['/usr/bin/python3','-B','-I','-S',str(wrapper),str(self.policy_path),digest(self.policy_path),'safe'],cwd=self.root,env=env,text=True,capture_output=True,timeout=5)
            self.assertEqual(r.returncode,78,(fail_on,r.stdout,r.stderr))
            self.assertFalse((self.root/'marker').exists())
        self.tearDown(); self.setUp()

    def test_attempt_record_short_write_completes_before_dispatch(self):
        wrapper=self.root/'short-positive.py'
        wrapper.write_text("""import importlib.util,os,sys
spec=importlib.util.spec_from_file_location('guard',os.environ['TASK_RUN_GUARD_MODULE'])
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
real=g.os.write;count=0
def short(fd,data):
 global count
 count+=1
 if count==2:
  n=max(1,len(data)//2);real(fd,data[:n]);return n
 return real(fd,data)
g.os.write=short
sys.exit(g.main(['run',sys.argv[1],sys.argv[2],sys.argv[3]]))
""")
        env=os.environ.copy();env['TASK_RUN_GUARD_MODULE']=str(GUARD)
        r=subprocess.run(['/usr/bin/python3','-B','-I','-S',str(wrapper),str(self.policy_path),digest(self.policy_path),'safe'],cwd=self.root,env=env,text=True,capture_output=True,timeout=5)
        self.assertEqual(r.returncode,0,(r.stdout,r.stderr))
        self.assertTrue((self.root/'marker').exists())

    def test_driver_argument_binding_uses_correct_run_argv_position(self):
        driver=self.root/'driver.sh'; driver.write_text('#!/usr/bin/bash -p\nexit 0\n'); driver.chmod(0o755)
        pins=[self._pin(GUARD),self._pin('/usr/bin/python3'),self._pin('/usr/bin/bash'),self._pin('/usr/bin/readlink'),self._pin(driver)]
        self.policy['candidates']=pins
        self.policy['actions']['safe']['argv']=['/usr/bin/bash','-p',str(driver),'T900']
        self.write_policy()
        base=['/usr/bin/python3','-B','-I','-S',str(GUARD),'run',str(self.policy_path),digest(self.policy_path),'safe']
        mismatch=subprocess.run(base+['--driver',str(driver),'--','wrong'],cwd=self.root,text=True,capture_output=True)
        self.assertEqual(mismatch.returncode,78,(mismatch.stdout,mismatch.stderr))
        self.assertIn('arguments do not match',mismatch.stderr)
        self.assertFalse(self.journal.exists())
        healthy=subprocess.run(base+['--driver',str(driver),'--','T900'],cwd=self.root,text=True,capture_output=True,timeout=5)
        self.assertEqual(healthy.returncode,0,(healthy.stdout,healthy.stderr))



    def _program_action(self, argv, extra_pins=()):
        pins = {item["path"]: item for item in self.policy["candidates"]}
        for path in extra_pins:
            item = self._pin(path)
            pins[item["path"]] = item
        self.policy["candidates"] = list(pins.values())
        self.policy["actions"]["safe"]["argv"] = [str(x) for x in argv]
        self.write_policy()

    def _run_program_stdin(self, data=b""):
        return subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(GUARD), "run",
            str(self.policy_path), digest(self.policy_path), "safe"], cwd=self.root,
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)

    def _healthy_python_control(self):
        healthy = self.root / "healthy.py"
        healthy.write_text("import os,sys\nopen(os.environ['MARKER'],'w').write('healthy')\nprint(sys.flags.no_site)\n")
        healthy.chmod(0o644)
        py = str(pathlib.Path("/usr/bin/python3").resolve())
        self._program_action([py, "-I", "-S", str(healthy)], (healthy, py))
        r = self._run_program_stdin()
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertEqual(r.stdout.decode().strip(), "1")
        self.assertEqual((self.root / "marker").read_text(), "healthy")
        (self.root / "marker").unlink()
        return py

    def _healthy_bash_control(self):
        healthy = self.root / "healthy.sh"
        healthy.write_text(f"printf healthy > {str(self.root / 'marker')!r}\n")
        healthy.chmod(0o644)
        bash = str(pathlib.Path("/usr/bin/bash").resolve())
        self._program_action([bash, "-p", str(healthy)], (healthy, bash))
        r = self._run_program_stdin()
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertEqual((self.root / "marker").read_text(), "healthy")
        (self.root / "marker").unlink()
        return bash

    def test_unpinned_python_directory_main_is_refused(self):
        py = self._healthy_python_control()
        package = self.root / "unapproved-package"
        package.mkdir()
        (package / "__main__.py").write_text("import os\nopen(os.environ['MARKER'],'w').write('directory source ran')\n")
        self._program_action([py, str(package)], (py,))
        r = self._run_program_stdin()
        self.assertFalse((self.root / "marker").exists(), "unpinned directory __main__.py actually executed; marker proves admission")
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))
        self.assertFalse((self.root / "marker").exists(), "unpinned directory __main__.py executed")

    def test_python_stdin_source_is_refused(self):
        py = self._healthy_python_control()
        self._program_action([py, "-"], (py,))
        source = f"open({str(self.root / 'marker')!r},'w').write('stdin source ran')\n".encode()
        r = self._run_program_stdin(source)
        self.assertFalse((self.root / "marker").exists(), "caller stdin actually executed as Python source; marker proves admission")
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))
        self.assertFalse((self.root / "marker").exists(), "caller stdin executed as Python source")

    def test_bash_stdin_source_is_refused(self):
        bash = self._healthy_bash_control()
        self._program_action([bash, "-p", "-s"], (bash,))
        source = f"printf ran > {str(self.root / 'marker')!r}\n".encode()
        r = self._run_program_stdin(source)
        self.assertFalse((self.root / "marker").exists(), "caller stdin actually executed as Bash source; marker proves admission")
        self.assertEqual(r.returncode, 78, (r.stdout, r.stderr))
        self.assertFalse((self.root / "marker").exists(), "caller stdin executed as Bash source")

    def test_opaque_pinned_command_receives_eof_not_caller_source(self):
        cat = str(pathlib.Path("/usr/bin/cat").resolve())
        self._program_action([cat], (cat,))
        empty = self._run_program_stdin()
        self.assertEqual(empty.returncode, 0, (empty.stdout, empty.stderr))
        self.assertEqual(empty.stdout, b"")
        source = b"opaque caller-fed source\n"
        r = self._run_program_stdin(source)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertEqual(r.stdout, b"", "opaque pinned child received caller-controlled stdin")

    def test_python_isolated_without_no_site_is_not_admitted(self):
        py = self._healthy_python_control()
        script = self.root / "site-flag.py"
        script.write_text("import os,sys\nopen(os.environ['MARKER'],'w').write('executed')\nprint(sys.flags.no_site)\n")
        script.chmod(0o644)
        journal_before = self.journal.read_bytes()
        self._program_action([py, "-I", str(script)], (script, py))
        r = self._run_program_stdin()
        observed = (r.returncode, r.stdout.decode(), (self.root / "marker").exists(),
                    self.journal.read_bytes() != journal_before)
        expected = (78, "", False, False)
        self.assertEqual(observed, expected,
                         "-I-only must refuse before site-enabled script execution or journal mutation")

    def test_interpreter_modes_are_closed_and_script_arguments_remain_literal(self):
        py = self._healthy_python_control()
        bash = self._healthy_bash_control()
        py_script = self.root / "literal-args.py"
        py_script.write_text("import json,sys\nprint(json.dumps(sys.argv[1:]))\n")
        py_script.chmod(0o644)
        bash_script = self.root / "literal-args.sh"
        bash_script.write_text("printf '%s\\n' \"$@\"\n")
        bash_script.chmod(0o644)
        self._program_action([py, "-I", "-S", str(py_script), "-m", "-", "-c"], (py_script, py))
        r = self._run_program_stdin()
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertEqual(json.loads(r.stdout), ["-m", "-", "-c"])

        self._program_action([bash, "-p", "--", str(bash_script), "-s", "-", "-c"], (bash_script, bash))
        r = self._run_program_stdin()
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertEqual(r.stdout.decode().splitlines(), ["-s", "-", "-c"])

        for argv in ([py, "-I", "-S", "-c", "pass"], [py, "-I", "-S", "-m", "json"],
                     [py, "-I", "-S", "-W", "ignore", str(py_script)],
                     [bash, "-s"], [bash, "-p", "-c", "true"], [bash, "-pl", str(bash_script)]):
            before = self.journal.read_bytes()
            self._program_action(argv, (py_script, bash_script, py, bash))
            refused = self._run_program_stdin(b"source must not execute\n")
            self.assertEqual(refused.returncode, 78, (argv, refused.stdout, refused.stderr))
            self.assertEqual(self.journal.read_bytes(), before, argv)

    def _assert_fifo_script_argument_refused(self, interpreter):
        if interpreter == "python":
            executable = self._healthy_python_control()
            script = self.root / "fifo-argument.py"
            script.write_text("import os\nopen(os.environ['MARKER'],'w').write('python ran')\n")
            script.chmod(0o644)
            mode = ["-I", "-S"]
        else:
            executable = self._healthy_bash_control()
            script = self.root / "fifo-argument.sh"
            script.write_text(f"printf 'bash ran' > {str(self.root / 'marker')!r}\n")
            script.chmod(0o644)
            mode = ["-p"]
        fifo = self.root / "argument.fifo"
        os.mkfifo(fifo)
        pins = (executable, script)

        self._program_action([executable, *mode, str(script), "--literal"], pins)
        healthy = self._run_program_stdin()
        self.assertEqual(healthy.returncode, 0, (healthy.stdout, healthy.stderr))
        self.assertTrue((self.root / "marker").exists(), "literal nonpath script argument should remain valid")
        (self.root / "marker").unlink()

        before = self.journal.read_bytes()
        self._program_action([executable, *mode, str(script), str(fifo)], pins)
        refused = self._run_program_stdin()
        observed = (refused.returncode, (self.root / "marker").exists(),
                    self.journal.read_bytes() != before)
        self.assertEqual(observed, (78, False, False),
                         f"special FIFO script argument must refuse before dispatch: {observed}")

    def test_python_script_arguments_reject_special_paths(self):
        self._assert_fifo_script_argument_refused("python")

    def test_bash_script_arguments_reject_special_paths(self):
        self._assert_fifo_script_argument_refused("bash")

    def test_python_dash_sentinel_is_not_a_pinned_script(self):
        py = self._healthy_python_control()
        dash_script = self.root / "-"
        dash_script.write_text("import os\nopen(os.environ['MARKER'],'w').write('dash file ran')\n")
        dash_script.chmod(0o644)

        self._program_action([py, "-I", "-S", "./-"], (py, dash_script))
        control = self._run_program_stdin()
        self.assertEqual(control.returncode, 0, (control.stdout, control.stderr))
        self.assertEqual((self.root / "marker").read_text(), "dash file ran")
        (self.root / "marker").unlink()

        before = self.journal.read_bytes()
        self._program_action([py, "-I", "-S", "--", "-"], (py, dash_script))
        refused = self._run_program_stdin()
        observed = (refused.returncode, (self.root / "marker").exists(),
                    self.journal.read_bytes() != before)
        self.assertEqual(observed, (78, False, False),
                         f"Python '-' stdin sentinel must refuse before dispatch: {observed}")


class DriverAdmissionBaseline(unittest.TestCase):
    def test_driver_guard_baseline(self):
        """Prove the opt-in hook blocks a valid in-progress ticket and policy."""
        with tempfile.TemporaryDirectory(prefix="guard-driver-baseline-") as td:
            root = pathlib.Path(td)
            (root / "scripts").mkdir()
            (root / ".specify").mkdir()
            tickets = root / "specs/001-test/tickets"
            tickets.mkdir(parents=True)
            shutil.copy2(DRIVER, root / "scripts/run-task.sh")
            shutil.copy2(ROOT / "scripts/review-matrix.json", root / "scripts/review-matrix.json")
            shutil.copy2(ROOT / "scripts/task-run-guard.py", root / "scripts/task-run-guard.py")
            (root / ".specify/feature.json").write_text('{"feature_directory":"specs/001-test"}\n')
            (root / ".gitignore").write_text("target/\n")
            (tickets / "T900-fixture.md").write_text("---\nid: T900\ntitle: 'guarded fixture'\nstatus: in-progress\ncreated: 2026-10-13\nlast_updated: 2026-10-13\nsource: tasks.md#T900\nphase: \"1: Setup\"\nstory: '-'\nblocked_by: []\nparallel: false\nfiles_budget: 8\nprivacy_critical: false\ntest_for: []\ncomplexity: low\nrisk: low\nround_cap: 2\nspec_refs: []\ndecision_refs: []\nreviews: {}\noverrides: []\naborted_attempts: []\nreopens: []\nredteam_findings: []\nclarity_check: {}\n---\n\n# T900: guarded fixture\n\n## Context\nThis disposable ticket exercises blocked admission.\n\n## Acceptance\n- The driver blocks before handoff.\n\n## Out-of-scope\nNo production changes.\n")
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "fixture"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            plan = root / "plan.md"
            plan.write_text("approved plan\n")
            plan_hash = digest(plan)
            def pin(path):
                st = pathlib.Path(path).stat()
                return {"path": str(pathlib.Path(path).resolve()), "sha256": digest(path), "mode": st.st_mode & 0o777}
            reviews = []
            for role, model in (("astra", "gpt-6-astra"), ("luna", "gpt-6-luna")):
                rp = root / f"{role}.json"
                rp.write_text(json.dumps({"schema":"task-run-guard-review-v1", "role":role, "model":model,
                    "effort":"high", "verdict":"APPROVE", "plan_sha256":plan_hash, "findings":[]}) + "\n")
                reviews.append({**pin(rp), "role":role, "model":model, "effort":"high"})
            policy = {
                "schema":"task-run-guard-policy-v1", "run_id":"baseline", "journal_path":str(root / "journal.jsonl"),
                "deadline_epoch":int(time.time()) + 120, "maximum_attempts":4, "maximum_failed_attempts":2,
                "phase":"implement", "plan":pin(plan), "reviews":reviews,
                "candidates":[pin(root / "scripts/task-run-guard.py"), pin(root / "scripts/run-task.sh"), pin("/usr/bin/bash"), pin("/usr/bin/python3"), pin("/usr/bin/readlink")],
                "actions":{"implement":{"phase":"implement", "enabled":False,
                    "blocked_reason":"implementation is blocked pending approved completion contract",
                    "argv":["/usr/bin/bash", "-p", str((root / "scripts/run-task.sh").resolve()), "T900"],
                    "cwd":str(root), "env":{}, "timeout_seconds":30}},
            }
            pp = root / "blocked-policy.json"
            pp.write_text(json.dumps(policy, separators=(",", ":")) + "\n")
            env = os.environ.copy()
            env.update(STARGATE_GUARD_POLICY=str(pp), STARGATE_GUARD_SHA256=digest(pp), STARGATE_GUARD_ACTION="implement")
            r = subprocess.run([str(root / "scripts/run-task.sh"), "T900"], cwd=root, env=env,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            REPORTS.mkdir(parents=True, exist_ok=True)
            (REPORTS / "baseline-driver-green-v2.json").write_text(json.dumps({
                "command": [str(root / "scripts/run-task.sh"), "T900"], "environment_policy_sha256":digest(pp), "returncode": r.returncode,
                "stdout": r.stdout, "stderr": r.stderr,
                "driver_sha256": digest(root / "scripts/run-task.sh"),
                "driver_bytes_hex": (root / "scripts/run-task.sh").read_bytes().hex()}, indent=2) + "\n")
            self.assertEqual(r.returncode, 78, f"expected admission refusal; got {r.returncode}: {r.stdout}\n{r.stderr}")
            self.assertNotIn("IMPLEMENT", r.stdout)




if __name__ == "__main__":
    unittest.main()
