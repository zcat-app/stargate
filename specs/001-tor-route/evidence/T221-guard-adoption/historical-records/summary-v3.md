# Task-run guard source v3

Implemented the approved closed interpreter-input contract. The guard recognizes resolved system Python and Bash identities, admits only directly pinned regular script forms (`-I` plus `-S` for Python; `-p` for Bash), refuses inline/module/stdin/directory/unsupported interpreter modes before journaling, and sends EOF to every child. The driver bootstrap uses `/usr/bin/python3 -IBS`; documentation records the protected invocation boundaries and limits.

The same five preserved `RepairRegressions` selectors that produced actual behavioral REDs against unchanged source v2 all passed after the fix. Their exact commands and per-selector stdout/stderr logs are in `input-green-evidence-v3.json`; the original RED logs and classification remain in `input-program-red-evidence-v3.json`. A separate table regression covers unsupported Python/Bash modes and literal option-like arguments after a pinned script.

The affected suite passed: 54 tests, 0 failures, 0 skips. Command: `/usr/bin/python3 -B -I tests/contract/workflow/task_run_guard_test.py`. No broad verification or unrelated suite was run. Final file hashes and modes are recorded in `evidence-v3.json`.

Historical implementation evidence gaps remain unresolved. This does not activate a T218 policy, complete T218, or establish a sandbox/containment guarantee. The source freeze is limited to the four approved files.
