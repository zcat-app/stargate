# T137 red/green evidence

This is a **retrospective reconstruction**, created during review round 2 after
the original tests-first Maven output had been overwritten by later green
Surefire reports. It is not presented as recovered historical output and does
not erase that preservation mistake. It makes the final regressions and the
pre-fix behavior independently inspectable on identified source snapshots.

The raw terminal transcript is
[`red-green-replay.typescript`](red-green-replay.typescript), SHA-256
`e30ff0abbcfe4358889cd779eec47d457547525aa41f73a9b903f017089db02e`.
Each `script` header records the exact Maven command and each footer records its
exit code.

## Source identities

The red replay used detached worktree commit
`ec5b3d07240c2bdfc93fda1cd6da8b336a798566` with only the final two regression
test files copied into it. The matching test hashes demonstrate that the red
and green runs used unchanged assertions:

- `ReloadTokensClient.java`
  - base: `04e0f5343db75e44b708340b0e4a60fbe79d15bbd1865ae9559815696a6cdff5`
  - repaired: `5d9ec783ec5e32b4c02ba220234a16da8bdcf586ed160ab571465c04da9212ec`
- `InterPlaneWireTest.java`
  - base and repaired: `abfdfb9365067a8e2006dd299a2203806d8f25fe78de683a70bd0afc89690803`
- `StargateControlPlaneTest.java`
  - base and repaired: `5095a6da3330efee69c91d24000ba4946778b1591505a69bcf1e06687b50d0ab`

## Outcomes

1. On base production, `reloadClientGetsFullDeadlineAfterIdlingPastConstructionDeadline`
   exited 1: the RPC began after its retained deadline had expired by
   `1.117239919` seconds.
2. On base production, `staleReconciliationGetsFreshDeadlineForTheNextAttempt`
   exited 1: generation 6 inherited only `3.630359552` seconds, returned
   `DEADLINE_EXCEEDED`, and the completed-generation assertion saw `[1]`
   instead of `[1, 6]`.
3. On the repaired candidate, both unchanged tests ran together and exited 0.

These are the ticket's intended behavioral falsifiers, not tooling failures.
The repository-wide `scripts/verify.sh` result remains the driver-owned green
gate for the complete candidate.
