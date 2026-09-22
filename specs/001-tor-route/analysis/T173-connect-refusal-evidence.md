<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# T173 HTTP refusal evidence and coverage migration

## Scope and state

The candidate removes HTTP CONNECT admission from Tor port 8881. First byte `C`
closes without reading headers, consulting authentication, counting a request or
opening an upstream connection. SOCKS keeps its deadlines, bearer verification,
opaque username forwarding, empty upstream password and hostname target.

Runtime implementation, local socket verification and the Local Compose stop/restart
probe passed on the candidate identified below. This record does not transfer
historical T163/T165 circuit evidence or replace the independent review gate.
The external human release review gate and T126/T155 browser/circuit obligations
remain unchanged. This repair implements the already reviewed refusal boundary;
it introduces no route, cryptographic identity scheme or deployment exposure.

## Red before green

Baseline HEAD: `3dec02cdb6b94a0044d81c084d1d8615946aeb98`.
Before production edits, `TestHTTPConnectSameDestinationDistinctFirstPartyRefused`
was added to the process-level contract suite. Its SHA-256 is
`92095346c30e4397083fa6e7d756849f2313a59cb57a010124229e1954618dbb`.
The same source bytes ran red and green:

```sh
cd tests/contract
go test ./socks5 -run '^TestHTTPConnectSameDestinationDistinctFirstPartyRefused$' -count=1 -v
```

Red: all four authenticated SOCKS controls passed, preserving distinct synthetic
site/profile/device identities, empty upstream passwords, hostname-form target
and early opaque bytes. Each valid HTTP probe admitted an upstream socket,
returned response bytes and incremented requests by one. Missing/malformed/invalid
HTTP credentials returned bytes; pipelined payload admitted upstream traffic;
first-byte-only input timed out instead of closing. This is a behavioral red,
not a disconnected fixture or missing tool.

Green: the unchanged regression passed all four SOCKS controls and all HTTP
variants, with zero HTTP response bytes, actual close, unchanged request/byte
counters and zero additional raw upstream accepts. Listener seam tests separately
assert zero verifier, audit and forward calls, including a verifier that accepts.
Fake Tor observations prove transport framing, not real Tor circuit separation.

Local artifacts under `target/runs/T173-evidence/`: `red.log`, `red.patch`,
`red-sources.sha256`, `green.log`, `green-sources.sha256`. The pre-fix and candidate
production images are built from the checked-in Dockerfile and isolated source
contexts (`build-context-before.tar`, `build-context.tar`); identities and live
results are recorded separately below. Development credentials are synthetic;
no bearer values, keys or application response bytes are published here.

## Every changed/deleted test: invariant mapping

| Previous test / family | Replacement or preserved assertion |
|---|---|
| Listener `TestConnect_Success_Exact200_VerbatimTarget`, `HeaderNameCaseInsensitive` | HTTP is unconditionally refused; named process regression observes zero accepts/bytes/counts for valid credentials and identity hints. SOCKS controls preserve exact target/identity and bytes; no HTTP status is supported. |
| `TestConnect_EarlyTunnelBytesNotSwallowed` | Named regression appends opaque payload to the SOCKS request in one write, checks exact zero-BND success followed by byte-identical echo. |
| `TestConnect_AuthMissing_407_NoAuthNoCounter`, `AuthMalformed_407_Indistinguishable`, `AuthVerifyFail_407_NoCounter`, `LookalikeHeader_407` | HTTP refusal is independent of credentials/headers; process regression plus `TestHTTPRefusalDoesNotConsultVerifier` proves no auth/audit/forward calls. Existing SOCKS auth-failure tests and 100-attempt counter burst remain; renderer-only AUTH_REQUIRED retains its format. |
| `TestConnect_FramingGarbage_SilentClose`, `OversizedHeaders_SilentClose` | First `C` alone closes immediately; oversized/pipelined cases observe real socket close without bytes or upstream effects. Remaining header grammar has no semantic role. Unknown-first-byte demux refusal remains. |
| `TestConnect_RouteError_Template` | Existing `TestRequestPhase_RouteError_ZeroedBND` and forward unreachable/refused/timeout tests retain fixed SOCKS classifications; no HTTP route template is reachable. T071 owns unimplemented positive renderer codes. |
| `TestConnect_PipeError_NoInjectedBytes` | `TestSOCKSAuthSuccessSurvivesCPOutageAndUpstreamClose` exchanges destination bytes through real sockets, cuts upstream, asserts EOF with no extra bytes and no additional accepted upstream connections. |
| `TestDemux_ConnectRouted`, contract `Demux_HTTPConnectFirstByte` | Immediate `C` refusal; unit seam checks zero auth/audit/forward effects. All SOCKS method/request/deadline tests retained. |
| `TestDialNoUsernameOffersNoAuthAndBridges` | Removed with its `Tor.Dial`/`Pipe` production seam. Named regression's four distinct SOCKS controls prove upstream USERPASS, intact username, empty password, target and bytes; HTTP never dials. Existing Forward tests retain hostname/deadline/counting/relay assertions. |
| `TestHTTPConnectAuthSuccess` | Named refusal regression plus `TestSOCKSAuthSuccessSurvivesCPOutageAndUpstreamClose`: no HEALTHY admission prerequisite; existing and new SOCKS requests forward after CP endpoint/stream removal, with exact bytes and log allowlist/corpus checks. |
| `TestLongLivedBidirectionalCONNECT/HTTPConnect` | Second authenticated SOCKS partition runs the same 30s+ schedule concurrently: small/large/asymmetric/interleaved/idle traffic and exact bytes. Both usernames must be observed upstream; journal allowlist, timestamps and corpus assertions retained. Client close remains exercised; separate upstream-close test covers peer initiation. |
| `TestAuthFailureCounterSideChannelResistance` family | Same 100 SOCKS failures, 100 HTTP variants, empty-generation cases and GetStatus no-traffic sandwich. HTTP expects zero-byte close instead of 407; exact zero request/byte deltas retained. |
| `TestAuthPassedCounterIncrements` / former HTTP success helper | All 100 requests use authenticated SOCKS with synthetic complete partition usernames. Exact N requests, 2B×N bytes, adjacent-hour handling, payload integrity, silence and log/corpus assertions retained. |
| Renderer `TestAUTHRequired`, `TestHeaderSet/AUTH_REQUIRED` | Direct calls to the production renderer via testdata subprocess; build/exec failure is fatal. Preserve status, body regex, exact reference-ID mask, fresh IDs, four-header order/absence/length and leak scans. No ingress claim. |
| `TestHeaderSet/ROUTE_DOWN/REFUSED/TIMEOUT` | Former missing-feature skips removed. `TestUnsupportedRouteRenderers` and `TestWriteFailureRouteCodesWriteNothing` require explicit renderer error and zero bytes. Positive format assertions are transferred to T071, not claimed covered by negative tests. |
| `render_test.go` type imports | Renderer-owned vocabulary replaces removed listener types; shape/freshness/variable-slot/unsupported-code assertions unchanged. |
| Control gRPC harness comment | SOCKS-only scope corrected; reload, snapshot/cold-start, advisory-event and transport suites retained and executed unchanged. |

Unchanged positive controls include SOCKS auth-required, userpass, leak and log
suites; integration fake-Tor relay; DNS/onion/isolation/smoke tests. Their live
cadence and unexecuted release obligations remain explicit; fake controls cannot
establish browser fallback or real same-target circuit separation.

## Renderer refinement and future work

The maintainer authorized the refinement after evaluation: T173 migrates active
AUTH_REQUIRED coverage and unsupported-code behavior. T071 owns all positive
four-code renderer assertions, including T068 body and T069 reference-ID tests,
as one atomic red-before-green implementation. T068/T069 are superseded/deferred;
T072/T078/T079 depend on T071 without waiting on those deferred predecessors.
The graph is acyclic. T172's original approval record is retained; the current
contract and T173 acceptance explicitly supersede only its renderer inventory row.

## Local deployment and verification

**PASS, 2026-09-22:** the actual Local Compose deployment refused valid, missing
and malformed HTTP credentials with claimed identity, with zero response bytes
and zero observed DP-to-Tor connects. A subsequent authenticated SOCKS request
through the same listener returned destination HTTP bytes through real Tor.
The old process's established pipe closed and its listener refused connections
after stop. The repaired process started while CP remained stopped and used the
unchanged persisted authentication snapshot. No compatibility switch, schema
migration, Direct fallback or production-setting override was used.

Environment: disposable Ubuntu 24.04 VM, kernel `6.8.0-139-generic`, QEMU 11.1.1
TCG with CPU model `max`, two vCPUs and 6 GiB RAM. `scripts/stargate init` installed
the actual Local topology from baseline HEAD; pinned images were built on a native
BuildKit worker and loaded into the guest. Firmware/package refresh jobs in this
disposable VM were stopped and host verification ran separately from the live
probe to avoid emulation contention. Production auth, IPC, protocol timeouts,
AppArmor, confinement and Compose networking were unchanged.

Reproduction, as root in the initialized disposable VM:

```sh
STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1 \
STARGATE_PROJECT=t173 \
STARGATE_ENV_FILE=/home/ubuntu/t173-before/target/t173-resume/local.env \
STARGATE_EVIDENCE_DIR=/home/ubuntu/t173-before/target/t173-resume/probe \
STARGATE_CANDIDATE_IMAGE=sha256:1b80a895f8354ceda6ea922edfb3f14390de7a439a3d2b7621e1e8f2001c6110 \
python3 -B tests/live-e2e/local-topology/connect_refusal.py
```

Measured identity and provenance:

| Item | Value |
|---|---|
| Baseline image | `sha256:a546268d453ad06dd1185212a714b1ca244415ae8c37e94301757d4e42bebe26` |
| Candidate deployed image | `sha256:1b80a895f8354ceda6ea922edfb3f14390de7a439a3d2b7621e1e8f2001c6110` |
| Candidate host image before import | `sha256:6760d6d0c59e1cedc182cf2e2acd420df644a892dcf3366f41b4f229f42ef1da` |
| Candidate binary SHA-256, host and guest | `fe169a9eee367f52924826b555bd4fa15f9d629b537d7b8fa4ab0db0f9cd7ad9` |
| Baseline binary SHA-256 | `4679b0891a49e6b41e06712b2d4f205139ead3e6df2b9a32aa37124bf20338a8` |
| Candidate container | `4b4052abac97f84b9fb326316c000f98ff1c9c71a3aeb6720c9dcc907bf7358d` |
| Candidate DP PID / AppArmor | `12761` / `stargate-dp` |
| DP and guest-host network namespace | both `net:[4026531840]` |
| Probe source SHA-256 | `91a2ccb3efbb1fa0194a7419eb2813484db6fcf87d06fda0a5a3fd0f40b2e7e1` |
| Unchanged Compose SHA-256 | `3413358f1d8c030117da7b6cfe64ccf2154f51b11fa3453845c8795b70f4320a` |

The guest's containerd-backed store assigned an imported image identity different
from the host's legacy store; extracted binary bytes matched, including the
running candidate's `/proc/12761/exe` hash. The source Dockerfile and build flags
were unchanged.

The dedicated kernel trace records endpoint paths only. During all three HTTP
probes its buffer contained zero events. The following SOCKS control recorded:

```text
stargate-proxy-12821 [001] ... t173_connect: path="/run/stargate-tor/tor-socks.sock" task="stargate-proxy"
```

It also recorded one unrelated fixed CP-socket reconnect. All 12 per-CPU loss
counters across the two capture windows were zero, as was kprobe missed-event
accounting. The sole deployed DP process was checked before capture; the thread
ID above is from that process. Missing positive controls, path-fetch faults and
lost trace evidence fail the probe. No auth or application buffers are traced.
The finite windows prove these probes' observed boundary behavior, not arbitrary
future traffic, browser fallback behavior or actual circuit separation. LAN/VPS
and T126/T155's browser/circuit obligations remain open.

### Failed setup and recovery

The first four-vCPU `qemu64` run overlapped host verification and failed before
migration: three CP starts never established authenticated Tor access. Diagnostics
included a ReloadTokens deadline and later SQLite acquisition timeouts. Its
`live-failed.tar` artifact remains preserved; it is not counted as a PASS.
On the replacement VM, an initial short-setup probe was interrupted for diagnosis.
The default JVM took 160 seconds merely to start Quarkus in one observed boot,
leaving little of the old 180-second harness budget for IPC/token initialization.
A subsequent negotiation-only diagnostic accepted the credential (`01 00`).

The probe now gives each setup attempt 600 seconds, separately from its unchanged
protocol deadlines. In the complete rerun, the first CP startup attempt established
the authenticated Tor control and every migration/refusal assertion passed. No
application deadline was increased, DP authentication snapshots were never written by the harness,
and no CP/JVM runtime flag was changed. This records environment/harness recovery;
it does not claim a new CP recovery mechanism or fix for unrelated startup defects.

Artifacts under `target/runs/T173-evidence/`: `live-pass.tar` contains whitelisted
init/probe logs, result JSON and both complete traces; `live-failed.tar` preserves
the unsuccessful setup. Credential configuration and key files are excluded.
`build-final.log`, `build-context.tar` and `binary.sha256` bind the source build.
The earlier failed disposable stack/VM was removed; the successful environment is
retained only until review/cleanup, in a separate overlay over the read-only base.

Affected SOCKS, renderer and control-gRPC suites passed (`contracts.log`), including
the unchanged named red/green regression and migrated outage/long-lived/counter
assertions. The five trace-verdict selftests passed. All seven edited tickets lint
clean; the 205-ticket graph is acyclic and no active consumer depends on T068/T069.
The 42-path implementation/refinement inventory is within 44. Fresh verification
and the independent reviewer set bind the final staged candidate via the driver;
release-only reproducibility and external human release review remain separate.
