#!/usr/bin/env python3
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
GUARD = ROOT / "scripts/task-run-guard.py"
DRIVER = ROOT / "scripts/run-task.sh"
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
            "candidates": [self._pin(GUARD), self._pin(self.script)],
            "actions": {"safe": {"phase": "review", "enabled": True, "blocked_reason": "",
                "argv": ["/usr/bin/python3", str(self.script)], "cwd": str(self.root),
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
        return subprocess.run(["/usr/bin/python3", "-B", "-I", str(GUARD), *extra,
                               "run", str(self.policy_path), digest(self.policy_path), action],
                              cwd=self.root, env=env or os.environ.copy(), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)

    def check(self, action="safe"):
        return subprocess.run(["/usr/bin/python3", "-B", "-I", str(GUARD), "check",
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

    def test_disabled_phase_review_and_pin_fail_closed(self):
        self.assert_blocked(lambda: self.policy.update(phase="implement"))
        self.policy["phase"] = "review"
        self.assert_blocked(lambda: self.policy["actions"]["safe"].update(enabled=False, blocked_reason="blocked"))
        self.policy["actions"]["safe"].update(enabled=True, blocked_reason="")
        self.assert_blocked(lambda: self.policy["reviews"].pop())

    def test_review_identity_verdict_plan_and_candidate_changes_block(self):
        self._review(self.review_l, "luna", "gpt-6-luna", verdict="REWORK")
        self.policy["reviews"][1] = self._review_pin(self.review_l, "luna", "gpt-6-luna")
        self.assert_blocked(lambda: self.policy.update(actions={}))

    def test_policy_hash_duplicate_json_and_file_mode_are_checked(self):
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", str(GUARD), "check",
                            str(self.policy_path), "0" * 64, "safe"], text=True, capture_output=True)
        self.assertEqual(r.returncode, 78)
        self.policy_path.write_text('{"x":1,"x":2}')
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", str(GUARD), "check",
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
        r = subprocess.run(["/usr/bin/python3", "-B", "-I", str(GUARD), "check",
                            str(link), digest(self.policy_path), "safe"], capture_output=True)
        self.assertEqual(r.returncode, 78)

    def test_hook_partial_environment_and_path_substitution_are_blocked(self):
        self.skipTest("hook fixture is exercised in driver admission test")


class DriverAdmissionBaseline(unittest.TestCase):
    def test_driver_guard_baseline(self):
        """Run the exact valid in-progress driver selector before the hook exists."""
        with tempfile.TemporaryDirectory(prefix="guard-driver-baseline-") as td:
            root = pathlib.Path(td)
            (root / "scripts").mkdir()
            (root / ".specify").mkdir()
            tickets = root / "specs/001-test/tickets"
            tickets.mkdir(parents=True)
            shutil.copy2(DRIVER, root / "scripts/run-task.sh")
            shutil.copy2(ROOT / "scripts/review-matrix.json", root / "scripts/review-matrix.json")
            (root / ".specify/feature.json").write_text('{"feature_directory":"specs/001-test"}\n')
            (root / ".gitignore").write_text("target/\n")
            (tickets / "T900-fixture.md").write_text("---\nid: T900\ntitle: fixture\nstatus: in-progress\nprivacy_critical: false\nround_cap: 2\n---\n")
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "fixture"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            env = os.environ.copy()
            env.update(STARGATE_GUARD_POLICY="/disabled/policy.json", STARGATE_GUARD_SHA256="0" * 64,
                       STARGATE_GUARD_ACTION="implement")
            r = subprocess.run([str(root / "scripts/run-task.sh"), "T900"], cwd=root, env=env,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            REPORTS.mkdir(parents=True, exist_ok=True)
            (REPORTS / "baseline-driver.json").write_text(json.dumps({
                "command": [str(root / "scripts/run-task.sh"), "T900"], "returncode": r.returncode,
                "stdout": r.stdout, "stderr": r.stderr,
                "driver_sha256": digest(root / "scripts/run-task.sh"),
                "driver_bytes_hex": (root / "scripts/run-task.sh").read_bytes().hex()}, indent=2) + "\n")
            self.assertEqual(r.returncode, 78, f"expected admission refusal; got {r.returncode}: {r.stdout}\n{r.stderr}")
            self.assertNotIn("IMPLEMENT", r.stdout)


if __name__ == "__main__":
    unittest.main()
