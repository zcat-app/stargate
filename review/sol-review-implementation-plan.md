# sol-review implementation priority

This is a temporary priority override for feature 001. Until the exit gate
below is met, invoke tickets by explicit ID; do not use the normal
lowest-runnable-ID selection from `scripts/next-task.sh`.

The order is based on three rules:

1. Repair the workflow and green gate before trusting later ticket outcomes.
2. Amend binding contracts before tests and implementations that consume them.
3. Avoid rework by finishing Tor topology/build changes before repairing init.

## Priority queue

### Wave 0 — trustworthy delivery machinery

Execute serially:

1. **T096** — enforce branch, review, red-team, commit, and dependency rules.
2. **T076** — make `scripts/verify.sh` execute and account for every module.
3. **T102** — add bearer-token secret scanning to local and CI/history gates.
4. **T101** — consolidate the privacy log scanner before new auth/IPC code.

No behavior ticket below is considered safely reviewable until T096 and T076
are done.

### Wave 1 — binding design amendments

5. **Start T091 immediately** — open the Principle III browser-hardening
   amendment and its mandatory 7-day comment/red-team process. Its waiting
   period may overlap steps 6–14, but T091 is not `done` until governance
   completes.
6. **T090** — remove CP-driven request-admission gating (Principle II).
7. **T095** — pin the authenticated/versioned inter-plane wire contract that
   consumes T090's semantics.
8. **T089** — amend the Tor startup contract so safe static config exists
   before entrypoint.
9. **T087** — implement and test the amended Tor config, DataDirectory, and
   healthcheck.
10. **T099** — pin immutable Tor package/build inputs while the Tor image
    surface is already in review.
11. **T092** — amend token verification, generation, persistence, and
    failure semantics.
12. **T093** — land the tests-first HMAC/lifecycle/RSS contract.
13. **T100** — strengthen schema and repository tests against T092's model.

T090 → T095, T089 → T087 → T099, and T092 → T093 → T100 are strict chains.
The three chains are independent, but the serial order above is the default
when only one ticket is active.

### Wave 2 — deployed local-stack remediation

14. **T094** — remove generic Docker API access, split networks, restrict
    egress, and harden containers. Requires T089 and T090.
15. **T088** — repair init/Compose identity, ownership, health discovery, and
    quickstart commands against the final T087/T094/T095/T099 contracts.
16. **T103** — add the scoped shell gate and fix remaining shell findings
    after T096 and T088 stabilize the scripts.

### Governance lane completion

17. **Finish T091** after the comment window and passing red-team review. As
    part of T091, refine T034b/T051/T054/T055 to the accepted enforcement
    boundary, but leave their implementation to normal numeric selection.

If T091 is rejected or materially changed during governance, stop this lane;
do not refine or start the dependent extension tickets against an unaccepted
boundary.

## Exit gate — resume normal ticket numbers

Resume `scripts/next-task.sh` lowest-ID selection only when:

- T076, T087–T096, and T099–T103 are `done`;
- T091 governance is complete and T034b/T051/T055/T054 have been refined to
  the accepted boundary;
- `scripts/verify.sh` is green on the unchanged tree; and
- `specs/001-tor-route/STATUS.md` has been regenerated.

After that point, normal numeric selection will safely encounter the refined
test tickets before their blocked implementations. The affected extension
sequence will naturally be T034b → T051 → T055 → T054 because of the recorded
dependencies. Release-cadence work
T075b → T097, T098, T081, T082, and final T078/T079 remains mandatory before
tagging but is not on the immediate vertical-slice implementation critical
path.
