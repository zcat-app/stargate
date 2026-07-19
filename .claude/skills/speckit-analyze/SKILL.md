---
name: "speckit-analyze"
description: "Perform a non-destructive cross-artifact consistency and quality analysis across spec.md, plan.md, and tasks.md after task generation."
argument-hint: "Optional focus areas for analysis"
compatibility: "Requires spec-kit project structure with .specify/ directory"
metadata:
  author: "github-spec-kit"
  source: "templates/commands/analyze.md"
user-invocable: true
disable-model-invocation: false
---


## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Pre-Execution Checks

**Check for extension hooks (before analysis)**:
- Check if `.specify/extensions.yml` exists in the project root.
- If it exists, read it and look for entries under the `hooks.before_analyze` key
- If the YAML cannot be parsed or is invalid, skip hook checking silently and continue normally
- Filter out hooks where `enabled` is explicitly `false`. Treat hooks without an `enabled` field as enabled by default.
- For each remaining hook, do **not** attempt to interpret or evaluate hook `condition` expressions:
  - If the hook has no `condition` field, or it is null/empty, treat the hook as executable
  - If the hook defines a non-empty `condition`, skip the hook and leave condition evaluation to the HookExecutor implementation
- When constructing slash commands from hook command names, replace dots (`.`) with hyphens (`-`). For example, `speckit.git.commit` → `/speckit-git-commit`.
- For each executable hook, output the following based on its `optional` flag:
  - **Optional hook** (`optional: true`):
    ```
    ## Extension Hooks

    **Optional Pre-Hook**: {extension}
    Command: `/{command}`
    Description: {description}

    Prompt: {prompt}
    To execute: `/{command}`
    ```
  - **Mandatory hook** (`optional: false`):
    ```
    ## Extension Hooks

    **Automatic Pre-Hook**: {extension}
    Executing: `/{command}`
    EXECUTE_COMMAND: {command}

    Wait for the result of the hook command before proceeding to the Goal.
    ```
- If no hooks are registered or `.specify/extensions.yml` does not exist, skip silently

## Goal

Identify inconsistencies, duplications, ambiguities, and underspecified items across the spec / plan / tasks / supporting artefacts and the constitution before implementation, **with zero raw-artefact load on the main session's context window** so the analyse → remediate cycle can fit in a single user-facing flow.

This command MUST run only after `/speckit-tasks` has successfully produced a complete `tasks.md`.

## Operating Constraints

**STRICTLY READ-ONLY** for the spec / plan / tasks / contracts / data-model / research / quickstart / constitution. The only file this command may write is the findings report at `{FEATURE_DIR}/analysis/{TODAY}-findings.md` (Step 2 below), and only if the user has not asked for in-conversation-only output.

**Constitution Authority**: The project constitution (`.specify/memory/constitution.md`) is **non-negotiable** within this analysis scope. Constitution conflicts are automatically CRITICAL and require adjustment of the spec, plan, or tasks — not dilution, reinterpretation, or silent ignoring of the principle. If a principle itself needs to change, that must occur in a separate, explicit constitution update outside `/speckit-analyze`.

## Execution Steps

### 1. Initialize Analysis Context

Run `.specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks` once from repo root and parse JSON for `FEATURE_DIR` and `AVAILABLE_DOCS`. Derive:

- `FEATURE_DIR` — absolute path
- `TODAY` — ISO date for the audit-trail filename (run `date +%Y-%m-%d`)

Abort with an error message if any required file is missing (instruct the user to run the missing prerequisite command).

For single quotes in args like "I'm Groot", use escape syntax: e.g `'I'\''m Groot'` (or double-quote if possible: `"I'm Groot"`).

### 2. Delegate full-corpus analysis to a sub-agent

The artefact corpus (typically 3,000–5,000 lines for a mature feature spec) is too large to load into the main conversation's context window — doing so leaves no headroom for remediation, re-analysis, or follow-on work in the same session. Instead, delegate the read + inventory + detection work to a sub-agent whose context window is independent of the main session's.

**a. Check for prior findings (for ID stability across runs):**

```bash
ls "${FEATURE_DIR}/analysis"/*-findings.md 2>/dev/null | sort | tail -1
```

If a prior findings file exists, read it once and extract its `### Findings` table. This lets the sub-agent reuse stable IDs for findings that are still open and assign new IDs only to genuinely new findings — the user can then diff across runs and track which findings the last remediation actually closed.

**b. Choose sub-agent type:**

Use **`general-purpose`** — it has full Read access. Do **NOT** use `Explore` — it samples / reads excerpts past its read window, which is exactly the failure mode this skill exists to prevent.

**c. Spawn the sub-agent with the prompt assembled from §"Sub-Agent Prompt Template" below**, substituting:

- `{FEATURE_DIR}` — absolute path from Step 1
- `{CONSTITUTION_PATH}` — `.specify/memory/constitution.md`
- `{USER_ARGUMENTS}` — the `$ARGUMENTS` value (focus areas, if any); empty string if none
- `{TODAY}` — the ISO date from Step 1
- `{PRIOR_FINDINGS_TABLE}` — the prior findings table verbatim if you found one in step (a), otherwise the literal string `(no prior findings file in {FEATURE_DIR}/analysis/)`

Run the sub-agent in **foreground** — the main agent needs the findings before Step 3.

The sub-agent returns a structured findings report in the format specified by the template (~5–15k tokens). The main agent's context never sees the raw artefacts (~100k tokens).

**d. Write the report to disk** at `{FEATURE_DIR}/analysis/{TODAY}-findings.md`, unless the user explicitly asked for in-conversation-only output. The on-disk file is the handoff artefact for a fresh remediation session; without it, every remediation cycle would need to re-spawn the sub-agent.

If `{FEATURE_DIR}/analysis/` does not exist, create it first.

**e. Sanity-check the audit trail.** The sub-agent's output starts with an audit trail (file × line count). If any line count looks suspiciously low relative to the actual file (cross-check with `wc -l` for one or two artefacts you're unsure about), flag the anomaly to the user in Step 3 — it may indicate the sub-agent partially read despite the mandate.

### 3. Present findings and offer remediation

The sub-agent's report is now in your context. Pass it through to the user largely verbatim — it is already in the required format. Light commentary is appropriate:

- Flag the CRITICAL count (if any) and call out specifically that the constitution conflict may require a governance-flow amendment vs spec tightening (the maintainer's choice — surface the choice, don't make it).
- Note whether this run found materially more / fewer findings than the prior round (if one was referenced in Step 2(a)) — meaningful drift either direction is worth flagging.
- Surface any audit-trail anomalies you spotted in Step 2(e).
- If you wrote the report to disk in Step 2(d), name the path so the user can hand it to a fresh session for remediation.

**Next Actions block** (concise, at the end of the report):

- If CRITICAL issues exist: recommend resolving before `/speckit-implement`. For constitution conflicts, explicitly surface the amend-vs-tighten decision (governance flow per constitution §Governance vs. amending the spec / plan / tasks to conform).
- If only LOW/MEDIUM: user may proceed to `/speckit-implement`, but provide improvement suggestions.
- Suggest concrete commands where they apply: `/speckit-specify` (refine spec), `/speckit-plan` (adjust architecture), manual edits to `tasks.md` (add coverage).

**Offer remediation**: ask "Would you like me to suggest concrete remediation edits for the top N issues, or should I leave this for a fresh session?" Do NOT apply edits automatically. For multi-finding remediation, recommend the fresh-session path — the analyse run consumed sub-agent budget but the main session is still light; whether it's worth doing remediation now vs. in a fresh session is the user's call.

### 4. Check for after_analyze extension hooks

After reporting, check if `.specify/extensions.yml` exists in the project root.
- If it exists, read it and look for entries under the `hooks.after_analyze` key
- If the YAML cannot be parsed or is invalid, skip hook checking silently and continue normally
- Filter out hooks where `enabled` is explicitly `false`. Treat hooks without an `enabled` field as enabled by default.
- For each remaining hook, do **not** attempt to interpret or evaluate hook `condition` expressions:
  - If the hook has no `condition` field, or it is null/empty, treat the hook as executable
  - If the hook defines a non-empty `condition`, skip the hook and leave condition evaluation to the HookExecutor implementation
- When constructing slash commands from hook command names, replace dots (`.`) with hyphens (`-`). For example, `speckit.git.commit` → `/speckit-git-commit`.
- For each executable hook, output the following based on its `optional` flag:
  - **Optional hook** (`optional: true`):
    ```
    ## Extension Hooks

    **Optional Hook**: {extension}
    Command: `/{command}`
    Description: {description}

    Prompt: {prompt}
    To execute: `/{command}`
    ```
  - **Mandatory hook** (`optional: false`):
    ```
    ## Extension Hooks

    **Automatic Hook**: {extension}
    Executing: `/{command}`
    EXECUTE_COMMAND: {command}
    ```
- If no hooks are registered or `.specify/extensions.yml` does not exist, skip silently

## Sub-Agent Prompt Template

When spawning the sub-agent in Step 2, pass the text between the `=== BEGIN ===` and `=== END ===` markers verbatim, with the substitutions performed. The template is self-contained — the sub-agent does not see the parent conversation's context, so the prompt must carry every directive the analysis needs.

```
=== BEGIN SUB-AGENT PROMPT ===

You are performing an exhaustive cross-artefact consistency and quality analysis on the spec-kit feature at {FEATURE_DIR}, ahead of `/speckit-implement`.

User's focus areas (may be empty — interpret an empty string as "all categories"): {USER_ARGUMENTS}

## Mandate

Read every artefact listed below in full at least once. Do not skim, sample, or load partial sections. Your context window is fresh and the cost of one missed inconsistency is days of rework or a shipped privacy bug; the cost of reading a few thousand extra lines is negligible by comparison.

Underreporting is the failure mode this analysis exists to prevent. The main agent that spawned you has no other source of findings — if you miss something, the user implements on a broken spec.

## Artefacts to read in full

**Core** (always read):

- `{FEATURE_DIR}/spec.md` — overview, functional requirements (FR-###), success criteria (SC-###), user stories, edge cases
- `{FEATURE_DIR}/plan.md` — architecture, stack, phases, technical constraints, project-structure tree, performance goals, constitution check
- `{FEATURE_DIR}/tasks.md` — every task ID, description, phase grouping, parallel markers `[P]`, referenced file paths
- `{CONSTITUTION_PATH}` — every principle, every MUST / SHOULD statement, governance section

**First-class supporting artefacts** (read in full if present — these carry byte-level invariants and drive most consistency findings):

- `{FEATURE_DIR}/data-model.md` — entities, state machines, storage layout, named invariants
- `{FEATURE_DIR}/research.md` — decisions and rationale, open questions, deferred items
- `{FEATURE_DIR}/quickstart.md` — operator-visible behaviour, canonical strings, step references
- `{FEATURE_DIR}/contracts/*.md` — every file in this directory is authoritative for the invariants it declares. Drift between a contract and the spec / tasks / plan is a finding.

If an artefact is referenced from another but does not exist, that is itself a finding.

**Verify section-number citations.** When a section like `arch §X.Y` is cited, grep the target document to confirm the section exists. Citation drift to non-existent subsections is a HIGH-severity finding (it propagates downstream when readers try to follow the reference and fail).

For tasks.md (often the largest file), if `Read` reports the file exceeds its token budget, read it in chunks via offset/limit — do NOT skip portions.

## Prior findings (for ID stability)

A prior `/speckit-analyze` run on this feature produced these findings:

{PRIOR_FINDINGS_TABLE}

For findings in that table that are **still open** in the current artefacts, reuse the prior ID exactly. Assign new IDs only to genuinely new findings. This lets the user diff runs and track which findings persist across remediation cycles.

If the prior-findings string above is literally `(no prior findings file in ...)`, ignore this section and start IDs fresh.

## Detection passes (exhaustive — no cap)

Report every substantiated finding. If two findings share a root cause, cluster them under one ID with sub-points. Do NOT drop findings to fit a budget. Do NOT cap the count.

**A. Duplication** — near-duplicate requirements; lower-quality phrasing to consolidate. Cross-references to a single source of truth are NOT duplication; literal restatement of the same invariant in multiple places (with drift risk) IS.

**B. Ambiguity** — vague adjectives (fast, scalable, secure, intuitive, robust) lacking measurable criteria; unresolved placeholders (TODO, TKTK, ???, `<placeholder>`); requirements where multiple reasonable interpretations exist.

**C. Underspecification** — verbs missing object/measurable outcome; user stories missing acceptance criteria alignment; tasks referencing files or components not defined in spec/plan; behaviour pinned for happy path but not for error/edge cases.

**D. Constitution alignment** — any requirement, plan element, or task conflicting with a MUST principle; missing mandated sections or quality gates. **Constitution conflicts are automatically CRITICAL** — the constitution is non-negotiable in this scope. Walk each principle systematically: for each MUST in the constitution, ask "does the feature uphold this, and which task or contract verifies it?"

**E. Coverage gaps** — requirements with zero associated tasks; tasks with no mapped requirement/story; Success Criteria requiring buildable work not reflected in tasks; constitution principles with no enforcing task or contract.

**F. Inconsistency** — terminology drift; data entities referenced in plan but absent in spec (or vice versa); task ordering contradictions (e.g., integration tasks before foundational setup tasks); conflicting requirements; **section-number citation drift** (cited section does not exist in the target document); stale wording where one artefact lags another on a load-bearing fact.

## Severity

- **CRITICAL** — violates a constitution MUST; missing core spec artefact; requirement with zero coverage blocking baseline functionality.
- **HIGH** — duplicate or conflicting requirement; ambiguous security/performance attribute; untestable acceptance criterion; stale wording that contradicts other artefacts on a load-bearing fact; citation drift that misleads downstream readers.
- **MEDIUM** — terminology drift; missing non-functional task coverage; underspecified edge case.
- **LOW** — style/wording improvements; minor redundancy not affecting execution order.

## "Zero findings" is a hypothesis to falsify, not a conclusion

If your detection passes produce zero findings, do NOT emit a clean report yet. Run a **second adversarial pass**: pick the three most load-bearing claims in `spec.md` (the ones a privacy bug or implementation-blocker would most likely hide behind) and actively try to find a counterexample in the contracts, the constitution, the data-model, or the task list.

Load-bearing claim categories to look hardest at: privacy invariants, byte-level wire-protocol shapes, atomic-swap / state-machine transitions, constitution-MUST mappings, "exactly these" / "byte-for-byte" assertions, cross-artefact vocabulary closure (closed enums and named constants).

Only emit a 0-findings report after that second pass also returns empty. If the second pass surfaces a finding, add it to the report. State in the audit trail that the falsification pass ran (and what it tried).

## Output format

Return a single Markdown document with this exact structure. No preamble, no closing sign-off, no commentary outside these sections.

### Audit trail (proof of completeness)

| Artefact | Lines | Status |
|----------|-------|--------|
| `spec.md` | N | full |
| `plan.md` | N | full |
| ... | | |
| **Total** | **~N** | |

If you skipped or partially read something, say why explicitly. If you ran the falsification pass (§"Zero findings is a hypothesis to falsify"), state what you tried.

### Findings

Group visually by severity. For each severity tier with at least one finding, emit a separate table:

#### CRITICAL

| ID | Category | Severity | Location(s) | Summary | Recommendation |
|----|----------|----------|-------------|---------|----------------|

#### HIGH

(... same shape ...)

#### MEDIUM

(... same shape ...)

#### LOW

(... same shape ...)

Stable IDs: category-letter + integer (D1, F1, I1, C1, …). Reuse prior IDs where applicable (per the "Prior findings" section above).

For each finding, cite specific file + line numbers in the Location column ("spec.md L294-301" beats "the hardening section"). Do NOT paste raw artefact excerpts into the Summary / Recommendation columns — cite by reference; the main agent will read the artefact directly if remediation is requested.

### Coverage summary

| Requirement | Has Task? | Task IDs | Notes |
|-------------|-----------|----------|-------|

One row per FR-### and per buildable SC-### (exclude post-launch outcome metrics and business KPIs).

### Constitution alignment issues

(List separately from the main findings tables, for visibility. If none, write "None — every constitution principle has at least one upholding task or contract.")

### Unmapped tasks

(Tasks with no derivable FR / SC / principle. If none, write "None.")

### Metrics

- Total Requirements: ###
- Total Tasks: ###
- Coverage % (requirements with ≥1 task): ###
- Ambiguity Count: ###
- Duplication Count: ###
- Critical Issues Count: ###

### Suggested fix sequence

Ordered list of findings to address, grouped by severity tier. For each finding, one-line rationale for the position in the sequence. CRITICAL findings come first; within HIGH/MEDIUM/LOW, order by remediation cheapness (single-edit findings first, multi-artefact-coordination findings later) unless there's a dependency reason to swap (e.g., a HIGH finding that touches the same artefact as several LOW findings — group them so the artefact is edited once).

## Constraints

- **Strictly read-only** — do not modify any files. The main agent may write your output to disk; you do not.
- **No raw artefact excerpts** in the output — cite by file + line, do not paste content. Your output goes back to the main agent (~5–15k tokens budget); pasted excerpts would defeat the context-saving purpose of the sub-agent delegation.
- **Cite specific instances** — every finding's Location column must name file + line. "spec.md L294-301" beats "the hardening section".
- **Be exhaustive** — if you are tempted to cap your finding count, or merge two distinct findings into one for brevity, resist. The main agent and the user can handle a long list; they cannot handle missed findings.

=== END SUB-AGENT PROMPT ===
```

## Operating Principles

### Completeness

- **Exhaustiveness over brevity**: completeness is the goal; sub-agent API cost is acceptable. The downstream cost of a missed finding (rework, shipped privacy bug) dwarfs the cost of one sub-agent invocation per analyse cycle.
- **Sub-agent isolation**: the main agent's context never holds raw artefacts. All reading happens in the sub-agent's fresh window. This is what makes the analyse → remediate cycle fit in a single user-facing flow.
- **No finding cap**: report every substantiated finding. Cluster duplicates under one ID; do not silently drop.
- **Stable IDs across runs**: pass prior findings into the sub-agent so IDs persist; the user can then diff runs and track which findings the last remediation actually closed.
- **Audit trail is mandatory**: the sub-agent's output must list every artefact read with its line count. The main agent should glance at this; if line counts look low relative to the actual files (use `wc -l` to verify if anything seems off), surface the anomaly to the user.

### Analysis Guidelines

- **NEVER modify the spec / plan / tasks / contracts / data-model / research / quickstart / constitution** (this is read-only analysis; the only writeable artefact is the findings report itself)
- **NEVER hallucinate missing sections** (if absent, report them accurately — the audit trail is the verification)
- **Prioritize constitution violations** (these are always CRITICAL)
- **Use examples over exhaustive rules** (cite specific instances, not generic patterns)
- **Report zero issues gracefully** — but only after the falsification pass (see Sub-Agent Prompt Template §"Zero findings is a hypothesis to falsify")

## Context

$ARGUMENTS
