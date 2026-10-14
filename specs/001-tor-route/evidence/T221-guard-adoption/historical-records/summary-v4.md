# Task-run guard source v4

The FIFO trailing-argument regression came from skipping the existing path-argument checks after a recognized Python or Bash script. The guard now applies those existing checks to every argument after the pinned script while keeping interpreter mode parsing closed and literal nonpath script arguments valid.

Both focused selectors that failed against unchanged v3 now pass: `RepairRegressions.test_python_script_arguments_reject_special_paths` and `RepairRegressions.test_bash_script_arguments_reject_special_paths`. The five original program-input selectors also pass. Commands and per-selector logs are in `input-green-evidence-v4.json`; prior actual RED evidence remains in the v3 FIFO evidence files.

The affected suite passed 56 tests, 0 failures, 0 skips using `/usr/bin/python3 -B -I tests/contract/workflow/task_run_guard_test.py`. Final hashes and modes are in `evidence-v4.json`. Only the guard and its contract test changed in this narrow repair; no driver or documentation changes were made.

Historical evidence gaps remain unresolved. This work does not activate policy or establish a sandbox or process-containment guarantee.
