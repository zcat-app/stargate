# T161 Tor live-validation evidence

T161 revalidates the exact content-pinned Tor 0.4.9.12 candidate prepared by T160.
It does not deploy or publish the image, and it does not replace T126/T155's integrated
data-plane isolation evidence or T134/T138's topology and observer-authority work.

## Candidate identity

Validation started from source commit `40c1f6a2af274e0525f7ef118d53fd09ae808c29`,
after T139's lifecycle housekeeping. Its `sidecars/tor` tree and the T032/T058/T058a
live-test blobs are byte-identical to T160's reviewed delivery commit
`55c567783a084354ba6321b6ecd0f7b88651f574`.

The local validation build is image ID
`sha256:ceb3ba3d6aa1e73f5b1848ce3a3697d6664fdc9575414beaa69455506b9bbcb8`
on `linux/amd64`, running as UID/GID 5103. It contains Tor
`0.4.9.12-1~d12.bookworm+1`; `/usr/bin/tor` hashes to
`545238fd854875ee02adaf29134496255689bc73bceb6e700420f78406887cb2`, and
`/etc/tor/torrc` hashes to
`54bb4222c6a447f09511ccba4e6ddc1ee839bfc1f5bdd72f3261e79c04024d51`.
This identifies the actual local build and installed package, not a published image manifest
or native arm64 execution.

The host was Linux x86_64 with Docker Engine/CLI 29.1.3 and Compose 5.1.4. Host and
container UTC clocks agreed within one second. Each run recorded below began without its
compose project or named volume. The harnesses registered their ordinary cleanup and removed
their projects and volumes afterward; no state or key was preseeded.

## Current cold results

All commands used the existing deadlines, targets, assertions and production compose topology.

- T058 cold run 1 started at 23:40:07 UTC and passed in 126.10 seconds. Bootstrap
  reached 100% in 6.21 seconds. Same-target streams 50/56, carrying distinct credentials,
  attached to circuits 11/16. The first onion rendezvous took 102.69 seconds, within the
  unchanged two-minute bound.
- T032 cold configuration started at 23:42:50 UTC and passed in 14.95 seconds. Bootstrap,
  healthy state, image-baked bytes, the cookie path and every `GETCONF` invariant passed.
- T062 cold control started at 23:43:13 UTC and passed in 15.97 seconds. Cookie authentication,
  `GETCONF`, bootstrap, built-circuit parsing and redacted invalid-auth handling passed.
- T058a cold behavior/control started at 23:43:36 UTC and passed in 68.48 seconds. Two NO_AUTH
  streams fused on circuit 17; the same observer then distinguished username-bearing circuits
  23/19.
- T058 cold run 2 started at 23:45:01 UTC and passed in 11.02 seconds. Bootstrap reached 100%
  in 6.33 seconds. Same-target streams 50/53, carrying distinct credentials, attached to
  circuits 12/14.

T058a supplies the positive fusion control: its observation path reported one shared circuit
for two username-less streams before reporting two distinct circuits for distinct usernames.
The shared result describes current native Tor behavior only. Within-partition single-circuit
reuse is not a constitutional guarantee and a native sidecar probe does not prove that the DP
forwards the correct client/profile/site partition.

A separate cold observational start used the same image, one fresh state volume and the
production Tor network attachments. It moved through bootstrap phases
0/5/10/14/15/20/25/30/40/45/50%, remained at descriptor loading for about 130 seconds, then
advanced through 55/62/69/75/90/95/100% and became healthy. This demonstrates material
cold-network variability without increasing a deadline or turning the observation into a warm
readiness claim.

## Preserved failures and conclusion

T160's two cold T058 failures remain unchanged in `target/T160/live-torrc.log` and
`target/T160/live-isolation-retry.log`, with their original hashes retained in T160 evidence.
They stopped at 54%/53% descriptor loading and produced EOF/REP=6 before any circuit comparison.
They remain failures and establish neither an isolation leak nor a root cause.

The unchanged candidate and unchanged T058 harness passed twice from cold state, while independent
cold configuration/control probes and a fusion-sensitive behavior control also passed. A third
cold bootstrap showed a much longer descriptor-loading interval but completed within the existing
window. Together these results provide current evidence for the required Tor-side configuration,
control and distinct-credential same-target isolation behavior and rule out a deterministic
0.4.9.12 or harness failure in this environment. They do not identify the cause of T160's two
timeouts, exclude future public-network failures, prove native arm64 behavior, or close any
integrated DP/foundation obligation.

Machine-readable identities, commands, outcomes and hashes of the ignored raw logs are retained
in [evidence.json](evidence.json).
