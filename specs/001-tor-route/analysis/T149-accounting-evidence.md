# T149 byte-accounting evidence

Contract: data-model.md §3, spec FR-007/FR-008 and Constitution I/III/VII.
The counted boundary remains the post-handshake upstream connection: successful
upstream reads plus writes, including nonzero results returned with an error.
This repair changes when that total is finalized, not what bytes it counts.

## Tests before implementation

Added `data-plane/internal/forward/accounting_test.go` before editing `tor.go`.
Against the original implementation, ran:

```sh
go test ./data-plane/internal/forward \
  -run 'TestConcurrentCloseWaitsForAccounting|TestBridgeCancelsBlockedIOBeforeJoining' \
  -count=1 -timeout=20s
```

Both read and write interleavings failed with `premature flush: calls=1 bytes=0`
and `final flush: calls=1 bytes=0, want 1 and 5`. The blocked-client-write case
also failed its two-second shutdown bound. Full local output is retained at
`target/runs/T149-red.log` (gitignored).

The regression wraps real `net.Pipe` endpoints and pauses after successful underlying
I/O, before the accounting wrapper receives the result. It then terminates the opposite
pump, observes underlying socket closure, releases the paused operation and requires
one final five-byte flush. Channels control the interleaving; no sleep chooses the race.
Separate probes exercise blocked client/upstream reads and writes without an idle timeout.

## Passing evidence and limits

After implementation, `go test -race ./data-plane/internal/forward
./data-plane/internal/audit -count=1 -timeout=60s` passed. These include existing
real TCP/Unix SOCKS handshake and bidirectional forwarding tests as well as the
new deterministic concurrency probes. Output: `target/runs/T149-green.log`.

Both new regressions also passed 100 repetitions under `-race`. The unchanged
SOCKS and control-gRPC contract suites passed with `-count=1 -timeout=180s`
(`target/runs/T149-contract.log`), covering real production DP socket forwarding,
authenticated byte totals, failure counters and log/leak checks.

The first full `scripts/verify.sh` run reported 26 PASS, 1 release-cadence
reproducibility SKIP and zero failures. A subsequent pre-review run failed the
existing `TestSOCKS5LeakInvariants/SlotInvariance_N4_ConstantTimeAcrossList`
timing band (slot 3 median 161.801 µs versus overall 107.509 µs). Its measurement
ends at authentication, before forwarding. The unchanged subtest then passed
three isolated repetitions. Preserve this observation as timing variability, not
a waived check; a fresh full green gate is still required before review/commit.
Local logs: `target/runs/T149-pre-review-failed.log` and `T149-timing-recheck.log`
in the same directory. No authentication or timing-test code was changed.

The shutdown deadline applies only once a pump terminates. It unblocks client I/O
before the join without transferring client Close ownership from the listener.
The forwarder still emits no error bytes after tunnel establishment and adds no logs.

This is local transport/accounting evidence, not a live Tor, deployment or browser
privacy claim. The aggregate schema and request-count policy are unchanged. T158
still owns completed-hour publication and clock-regression handling; this repair does
not establish compliance for the existing current-hour Snapshot/GetStatus surface.
No trust boundary, cryptographic identity, route or deployment exposure is added;
the ordinary independent ticket reviews apply, with release/milestone obligations retained.
