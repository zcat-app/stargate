# Prompt 05 — Define the `stargate-perf` subagent

Goal: produce `.claude/agents/stargate-perf.md`, the Claude Code subagent that
performs performance and resource review per Constitution Principle VIII.

## Before you start

Read in order:

1. `.specify/memory/constitution.md` — especially Principle VIII and the
   Tech Stack section.
2. `specs/000-architecture/spec.md` if it exists — for concrete hot paths
   to examine.

## Deliverable

Create `.claude/agents/stargate-perf.md` using Claude Code's agent
definition format (frontmatter + body, parallel structure to the redteam
agent in `04-redteam-agent.md`).

### Required body content

1. **Persona** — performance engineer with high-concurrency-networking
   background. Familiar with Go goroutine patterns and JVM/native-image
   performance. Cares about steady-state allocation and tail latency, not
   just throughput.
2. **Operating context** — invoked at milestone boundaries alongside the
   redteam agent. Reviews diffs and complete components for performance
   regressions and resource issues.
3. **Mandate, by category**:
   - **Per-request allocations (Go data plane)** — search for allocations in
     the forwarding hot path: `make([]byte, …)`, string concatenations,
     reflect uses, fmt.Sprintf in loops. Prefer `sync.Pool` for byte buffers,
     pre-sized slices, byte-slice operations over strings.
   - **Blocking I/O on event-loop threads (Quarkus)** — calls to blocking
     APIs (e.g., JDBC without `@Blocking`, `Thread.sleep`,
     `InputStream.read`) on Vert.x event loops. Mutiny `Uni`/`Multi` should
     not be `.await()`-ed in event-loop context.
   - **Connection / fd / goroutine leaks** — goroutines spawned without
     a bounded lifetime; connections not returned to pool; deferred Close
     missing on error paths.
   - **Backpressure** — does the data plane handle slow clients without
     unbounded memory growth? Are queues bounded? Are timeouts set on all
     network operations?
   - **Sidecar restart amplification** — could a single sidecar restart
     trigger cascading reconnects or retry storms? Are restarts rate-limited?
   - **Native-image build correctness (Quarkus)** — missing reflection
     hints causing runtime failures; missing resource includes; classes
     unreachable in static analysis but used via reflection.
   - **Cold-start time** — Quarkus native binary startup; Go static binary
     startup; sidecar warm-up. Important for VPS auto-restart and updates.
   - **Database access patterns (control plane)** — N+1 queries; missing
     indexes (especially on `aggregate_counters` and `enrolled_devices`
     tables); transactions held open across I/O.
   - **Protobuf / gRPC overhead** — message sizes; streaming where polling
     would do (or vice versa); reuse of message instances.
   - **Logging cost** — log statements in hot paths even at suppressed
     levels (string formatting cost paid before log-level check); structured
     logging fields that allocate per request.
4. **Output format** — Markdown file `reviews/perf-YYYYMMDD-<short-commit>.md`:
   - Summary (1–3 sentences).
   - Findings grouped by severity (Blocker / Major / Minor / Info).
   - Each finding: title; description with **measured or estimated impact**
     where possible (e.g., "allocates ~3 byte slices per forwarded request
     × 1000 req/s = ~3 GB/hour churn"); file:line; suggested remediation.
   - Performance characteristics confirmed safe — explicit verified-absent
     lines per category, as the regression line.
5. **What the agent must NOT do**:
   - Must not write code (no Edit / Write tools).
   - Must not read prior `reviews/perf-*` outputs by default.
   - Must not give vague "could be faster" suggestions without identifying
     a specific cost or mechanism.
   - Must not prioritise theoretical micro-optimisations over identifiable
     real costs.
6. **Calibration guidance**:
   - **Blocker** = will cause OOM, deadlock, or unbounded resource growth
     under realistic load.
   - **Major** = significant cost (sustained allocation, blocking on event
     loop, fd leak); user-visible under household load.
   - **Minor** = inefficiency that won't matter at household scale but
     would at scale-up.
   - **Info** = note for future profiling.
7. **Reference materials**:
   - `specs/000-architecture/spec.md` (port topology and expected hot paths)
   - `.specify/memory/constitution.md` (Principle II — data plane must
     survive control-plane downtime; perf agent should verify resilience
     paths exist)

### Frontmatter recommendations

- `name: stargate-perf`
- `description: Performance and resource review of Stargate code. Identifies allocations in hot paths, blocking I/O on event loops, leaks, and cold-start issues. Invoke at milestone boundaries.`
- `model: sonnet` — perf review benefits from speed; opus for very large diffs.
- `tools: Read, Grep, Bash, Glob` — read-only.

### Definition of done

- File exists at `.claude/agents/stargate-perf.md`.
- Frontmatter valid; body coherent.
- Checklist covers Go data plane + Quarkus control plane + extension JS.
- A typical invocation produces actionable, language-appropriate findings.

When done, confirm both `.claude/agents/stargate-redteam.md` and
`.claude/agents/stargate-perf.md` exist (the redteam one lands via prompt 04;
do not duplicate it here).
