<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# T124 implementation and live-run evidence

## Candidate

- Baseline: `ddcac2a4f933c5e33cda577b80385eb97886df13` (after the separately reviewed T177 Tor security-package promotion).
- Disposable-host source archive SHA-256: `40adce83bac6c4b84de12cbdf69738d5eb9be33cf7e80d2edf64a11f3ec9f43e`, verified on host and guest. It contains the staged executable candidate before this final report and the green tests-first record. T124 did not change the Tor Dockerfile or package hash lock.
- The installer default is a single 300-second window after Compose startup. Its deterministic tests retain authenticated observer READY and cover delayed READY, explicit timeouts, missing/rejected cookies, unavailable replies and failed observer execution. See `specs/001-tor-route/evidence/T124-tests-first.json` for the red/green probe record.

## Fresh-volume Local attempts, 2026-09-26

The disposable Ubuntu VM ran Linux `6.8.0-139-generic`, Docker `29.1.3`, Compose `2.40.3`, four virtual CPUs and 6 GiB memory. Each project below had zero project volumes before `bash scripts/stargate init`; no Tor state was preseeded and `STARGATE_HEALTHCHECK_TIMEOUT` was unset. The VM uses QEMU software emulation. Runs used the supported Local Compose topology and separate project names and env directories. Finite installer output was retained locally under the guest's `/home/ubuntu/t124-run*/init.out`; raw Tor logs were not collected.

1. **`t124-cold26`, before T177:** the first run started at `18:26:23 UTC` and exited at `18:38:04 UTC` with code **30**. The installer provisioned the observer identity and pinned its image, then reported `docker compose up failed` during build/start. It never entered the READY wait. A direct build identified the blocker: the Tor Project package index no longer offered the then-pinned `0.4.9.12-1~d12.bookworm+1`. This attempt is not readiness evidence. T177 subsequently verified and promoted the security release `0.4.9.13-1~d12.bookworm+1` under its own ticket and review.
2. **`t124-cold27`, after T177:** the new archive was extracted to `/home/ubuntu/t124-src-after-t177`. The run started at `20:38:13 UTC` and exited at `20:56:01 UTC` with code **30**, again before readiness. The Tor and data-plane images built, but the control-plane build failed. A direct in-VM build reached Maven's `api` Java compiler and exited 1 without a source diagnostic; guest memory and disk had ample free space. The same source then compiled successfully with the native BuildKit worker (`BUILD SUCCESS`, 2026-09-26 `21:09:45 UTC`). The emulated build failure is not evidence of an application compile defect or Tor readiness.
3. **`t124-cold28`, after T177, with native BuildKit:** the archive above was used unchanged. `BUILDX_BUILDER=t165-native` selected the native builder for the observer and ordinary Compose `up --build`; Compose deployment and the readiness check ran in the guest. `STARGATE_PROJECT=t124-cold28`, `STARGATE_ENV_DIR=/home/ubuntu/t124-run3`, and `STARGATE_ENV_FILE=/home/ubuntu/t124-run3/local.env` scoped the run. It started at `21:11:04 UTC` and ended at `21:15:35 UTC` with **exit 0**. Finite output entered `waiting up to 300s for Tor readiness`, then reported the Tor route reachable at loopback `127.0.0.1:8881` and the Tor observer **READY — authenticated current Tor bootstrap**. A separate `docker compose exec -T tor-observer /opt/stargate/tor-observer --check-ready` returned **0** after init. All four services (`stargate-control`, `stargate-dp`, `tor`, `tor-observer`) were running; the project had ten volumes after the run.

The successful run establishes cold-stack compatibility for this candidate under the supported Local topology and the tested network conditions. It does not make five minutes a Tor bootstrap guarantee or explain the historical T160/T161 descriptor-loading failures. The installer still returns 40 without success if authenticated READY is absent at the end of its configured window.

## Verification coverage

`bash scripts/verify.sh` exited 0 on the T124 candidate: `RESULT: GREEN`, `PASS=33`, `SKIP=2`, `FAIL=0`. The skipped gates were the Docker-tagged `contract:operational_logs_test.sh` and release-cadence reproducibility; the executed gates included the Go workspace, Maven reactor, installer/readiness contracts, Tor package integrity and workflow checks. The full local result is in `target/runs/T124.verify.log`.
