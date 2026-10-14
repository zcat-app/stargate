<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Task-run guard

`scripts/task-run-guard.py` admits one exact, named local command from a pinned JSON policy. `scripts/run-task.sh` has an opt-in entry hook: if any of `STARGATE_GUARD_POLICY`, `STARGATE_GUARD_SHA256`, or `STARGATE_GUARD_ACTION` is present, all three must be nonempty and the guard runs before the driver reads Git state, parses its arguments, or creates transient state. With no guard variables, the existing workflow continues unchanged. This is an invocation guard, not universal enforcement: calls that bypass the hook, collaboration tools, and unrestricted same-UID/root actions remain outside its boundary.

Use an absolute policy path, its SHA-256 over the exact file bytes, and a named action. The protected driver entry forms are the executable shebang (`scripts/run-task.sh ...`) and the explicit `/usr/bin/bash -p scripts/run-task.sh ...`; `-p` suppresses inherited Bash startup files and imported shell functions before the hook runs. An ordinary explicit `bash scripts/run-task.sh ...` is outside the protected contract because Bash can execute `BASH_ENV` before reading the script, which script code cannot undo. The direct guard entry uses `/usr/bin/python3 -IBS`; explicit calls must use `/usr/bin/python3 -B -I -S`. Ordinary Python invocation without isolated and no-site startup is outside the protected startup contract. These are caller/runtime preconditions, not a sandbox or universal enforcement boundary.

```sh
scripts/task-run-guard.py check /absolute/policy.json POLICY_SHA256 action-name
scripts/task-run-guard.py run /absolute/policy.json POLICY_SHA256 action-name
STARGATE_GUARD_POLICY=/absolute/policy.json \
STARGATE_GUARD_SHA256=POLICY_SHA256 \
STARGATE_GUARD_ACTION=action-name \
  /usr/bin/bash -p scripts/run-task.sh T123
```

`check` validates policy, review and candidate pins and inspects an existing journal without creating it or launching a child. `run` repeats admission, locks the journal, records an attempt before spawn, runs only the action's exact argv with its exact environment, and records the result. The driver hook additionally binds argv to `/usr/bin/bash -p`, the resolved driver path, and every original driver argument. The hook uses `/usr/bin/readlink` and `/usr/bin/python3 -IBS`; those OS-managed bootstrap inputs, Bash and the readlink binary are trusted. Their candidate paths must be pinned in the policy. The three guard variables are not passed to the child.

Interpreter actions use closed forms. Python is recognized by the resolved identity of the running system interpreter and must have `-I` (or its grouped equivalent) and `-S`, followed by an optional `--`, one directly pinned regular script, and then literal script arguments. Bash is recognized by its resolved system identity and requires `-p`, an optional `--`, one directly pinned regular script, and literal script arguments. Inline code, module execution, stdin source, directory entrypoints, unsupported interpreter options, and option-value modes are refused. Every child receives EOF on stdin; caller input is never forwarded. This checks the selected executable and explicitly pinned script bytes. It does not discover or pin arbitrary runtime dependencies, analyze opaque programs, or contain same-UID processes.

The closed `task-run-guard-policy-v1` JSON object has these fields:

| Field | Meaning |
|---|---|
| `schema`, `run_id` | Exact schema name and stable run identity. |
| `journal_path` | Absolute path to the single append-only JSONL attempt journal. |
| `deadline_epoch` | Absolute Unix deadline, fixed by the journal's first record. |
| `maximum_attempts`, `maximum_failed_attempts` | Positive total-attempt cap (at most 1000) and cumulative ordinary-failure cap (at most 3). |
| `phase` | Current phase. Every action's phase must match it. |
| `plan` | `{path, sha256, mode}` pin for the exact approved plan. |
| `reviews` | Exactly two pinned structured approvals: role `astra`, model `gpt-6-astra`, effort `high`; role `luna`, model `gpt-6-luna`, effort `high`. Report paths must differ. |
| `candidates` | Nonempty list of `{path, sha256, mode}` pins for source and executable inputs. |
| `actions` | Nonempty map of action names to `{phase, enabled, blocked_reason, argv, cwd, env, timeout_seconds}`. |

All pins use absolute paths to regular, non-symlink files and include the exact mode and SHA-256. Reviews use schema `task-run-guard-review-v1`, the matching role/model/effort, `verdict: "APPROVE"`, and `plan_sha256` equal to the plan pin. JSON is a structured record, not backend identity attestation. Unknown keys, duplicate JSON keys, malformed numbers, changed pins, partial hook configuration, disabled actions and phase mismatch refuse admission with exit 78. A timeout exits 124; an ordinary child failure returns its exit status. No command can be added or changed at the CLI.

The journal uses a nonblocking exclusive `flock` from admission through child completion. Its first record fixes run identity, deadline and attempt caps. Attempts are written before spawn, numbered in order, and followed by one result. A dangling attempt, malformed/truncated record, changed fixed metadata, unknown result, attempt/failure cap, timeout, interruption, or uncertain process cleanup prevents another launch. There is no reset operation. Renaming a policy does not create a new journal identity. An operator with unrestricted same-UID access can delete or rewrite the journal; this is outside the guard's security boundary and the journal is not tamperproof.

The child inherits stdout and stderr directly, runs in its own process group, and is bounded by the smaller of the action timeout and remaining wall deadline. After launch, timeout uses monotonic elapsed time. The guard sends TERM, waits at most 0.25 seconds, then KILLs and waits at most one second for the exact child. A successful leader that leaves process-group members is stopped and recorded as uncertain. These controls are best effort for ordinary schedulable local processes. They cannot prove interruption of kernel calls, stop escaped descendants or daemon work, or guarantee hard real-time cleanup. Do not use this tool for native protected-policy commands or as a substitute for filesystem/process containment.

For the T218 readiness situation, an implementation action must remain disabled with the unresolved completion-contract reason until the prerequisite is resolved and the relevant approval is recorded. A plan approval is not source approval. This guard does not authorize code-writing actions that mutate pinned inputs; a successful action is returned only if all pins still match afterward. The integration policy may allow harmless workflow handoffs or read-only commands, but it does not turn the T218 readiness gap into completion evidence.
