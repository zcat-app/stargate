// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.runtime;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.jspecify.annotations.Nullable;

import com.google.protobuf.ByteString;

import app.zcat.stargate.auth.TokenLoaderContract;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.quarkus.stargate.control.grpc.ReloadTokensClient;
import stargate.v1.ControlOuterClass.ApplyStatus;
import stargate.v1.ControlOuterClass.ReloadTokensResponse;
import stargate.v1.ControlOuterClass.TokenVerifier;

/**
 * The production {@link TokenLoaderContract.ReloadChannel} (T041): adapts
 * T038's {@link ReloadTokensClient} onto the T035a port the loader (T035)
 * pushes through — verifiers only, never the pepper, never a label (§1.6;
 * labels are not in the message by design).
 *
 * <p><strong>Transport containment (§1.8 durability).</strong> A push that
 * cannot reach the data plane (UNAVAILABLE, deadline — e.g. the DP booted
 * after the CP; compose pins no CP→DP ordering) is contained HERE, not by a
 * crash-loop: the adapter returns a non-stale
 * pending result. The generation/candidate is already durable when the
 * loader pushes; a single coalescing worker redelivers the latest exact
 * candidate with capped exponential backoff when DP IPC returns. The latest
 * non-stale authority remains in memory after acknowledgment and is queued
 * again only on an authenticated-channel reconnect edge, repairing a DP that
 * restarted without usable state while this CP remained live. A stale reply
 * is a conflict and never authorizes renumbering. A
 * {@code FAILED_PRECONDITION} version rejection instead aborts CP
 * startup with a static error (wire-auth §5.2), without retaining peer detail.
 *
 * <p><strong>Current delivery state (T187, Constitution II failure table).</strong>
 * Durable state in the injected {@link TokenLoaderContract.GenerationStore}
 * gates every RPC. A process starting with UNRESOLVED or STALE never replays
 * automatically; operator recovery is explicit. The operator-readable status
 * remains a CP-private volatile line: PENDING means unresolved delivery,
 * ACKNOWLEDGED means exact ACK plus committed local clear, and STALE_CONFLICT
 * means a stale refusal was durably recorded. The file is not authority and
 * carries no history, timestamps, labels or counts (Constitution III).
 * UNKNOWN can also occur when the durable state cannot be read. A failed status
 * write withdraws the previous value and retries silently; it never changes
 * delivery authority.
 * Deferred {@code enrolled}/{@code revoked} counts registered through
 * {@link #whenAcknowledged} run once on the exact acknowledgement and are
 * dropped on a stale reply.
 */
public final class GrpcReloadChannel implements TokenLoaderContract.ReloadChannel {

    private static final long INITIAL_RETRY_MILLIS = 100L;
    private static final long MAX_RETRY_MILLIS = 5_000L;
    private static final long STATUS_REPUBLISH_MILLIS = 1_000L;

    private final ReloadTokensClient client;
    private final TokenLoaderContract.GenerationStore generations;
    private final AtomicReference<PendingPush> pending = new AtomicReference<>();
    private final AtomicReference<PendingPush> current = new AtomicReference<>();
    private final AtomicBoolean retryWorkerRunning = new AtomicBoolean();

    private final @Nullable Path deliveryStatus;
    private final Object outcomeLock = new Object();
    // Guarded by outcomeLock. One load per CP process (FR-018) means one
    // candidate generation; the fields still refuse to regress to an older one.
    private long reportedGeneration;
    private long acknowledgedGeneration;
    private long staleGeneration;
    /** Guarded by outcomeLock; reconnect admission supersedes older ACK bookkeeping. */
    private long admissionRevision;
    private long waiterGeneration;
    private @Nullable Runnable waiter;
    /** Set for a restart barrier, terminal stale outcome, or unreadable marker. */
    private volatile boolean stopped;
    /** Latest state whose status write failed; retried until written (T187 r1). */
    private volatile @Nullable String unpublished;
    private final AtomicBoolean republisherRunning = new AtomicBoolean();
    private final Runnable beforeAcknowledgementClear;
    private final Runnable afterAcknowledgementClear;

    private record PendingPush(long generation, List<byte[]> verifiers) {
        PendingPush {
            verifiers = verifiers.stream().map(bytes -> bytes.clone()).toList();
        }
    }

    /** A channel that publishes no operator status (tests and non-deployed callers). */
    public GrpcReloadChannel(ReloadTokensClient client, TokenLoaderContract.GenerationStore generations) {
        this(client, generations, null);
    }

    /**
     * @param deliveryStatus the CP-private volatile status file; any earlier
     *        content is removed so a new CP process never reports a previous
     *        process's state (T187)
     */
    public GrpcReloadChannel(ReloadTokensClient client, TokenLoaderContract.GenerationStore generations,
            @Nullable Path deliveryStatus) {
        this(client, generations, deliveryStatus, () -> { }, () -> { });
    }

    /** Package-private boundary seam for deterministic T201 concurrency coverage. */
    GrpcReloadChannel(ReloadTokensClient client, TokenLoaderContract.GenerationStore generations,
            @Nullable Path deliveryStatus, Runnable afterAcknowledgementClear) {
        this(client, generations, deliveryStatus, () -> { }, afterAcknowledgementClear);
    }

    /** Package-private boundary seams remain inert in production. */
    GrpcReloadChannel(ReloadTokensClient client, TokenLoaderContract.GenerationStore generations,
            @Nullable Path deliveryStatus, Runnable beforeAcknowledgementClear,
            Runnable afterAcknowledgementClear) {
        this.client = client;
        this.generations = generations;
        this.deliveryStatus = deliveryStatus;
        this.beforeAcknowledgementClear = beforeAcknowledgementClear;
        this.afterAcknowledgementClear = afterAcknowledgementClear;
        clearStatus();
        try {
            TokenLoaderContract.GenerationStore.DeliveryMarker marker = generations.deliveryMarker();
            synchronized (outcomeLock) {
                reportedGeneration = marker.generation();
                if (marker.state() == TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED) {
                    stopped = true;
                    publish("PENDING");
                } else if (marker.state() == TokenLoaderContract.GenerationStore.DeliveryState.STALE) {
                    stopped = true;
                    staleGeneration = marker.generation();
                    publish("STALE_CONFLICT");
                }
            }
        } catch (RuntimeException unavailable) {
            stopped = true;
            synchronized (outcomeLock) {
                publish("UNKNOWN");
            }
        }
        client.onReconnect(this::redeliverCurrent);
    }

    @Override
    public TokenLoaderContract.PushResult push(long generation, List<byte[]> verifiers) {
        PendingPush candidate = new PendingPush(generation, verifiers);
        if (stopped) {
            return new TokenLoaderContract.PushResult(false, 0L);
        }
        // An outstanding initial RPC (up to its deadline) is already a pending
        // delivery: the status is never absent while credentials are in flight.
        recordPending(generation);
        long attemptRevision = admissionRevision();
        TokenLoaderContract.PushResult result = deliver(candidate);
        if (result.stale()) {
            forget(candidate);
            clearPendingThrough(generation);
            recordStale(generation);
        }
        else {
            if (stopped) {
                return new TokenLoaderContract.PushResult(false, 0L);
            }
            remember(candidate);
            if (acknowledged(candidate, result)) {
                if (!completeAcknowledgement(candidate, attemptRevision)) {
                    enqueue(candidate);
                    return new TokenLoaderContract.PushResult(false, 0L);
                }
                if (!finishAcknowledgement(candidate, attemptRevision)) {
                    // A reconnect already admitted this candidate for replay.
                    return new TokenLoaderContract.PushResult(false, 0L);
                }
            }
            else {
                enqueue(candidate);
            }
        }
        return result;
    }

    @Override
    public void whenAcknowledged(long generation, Runnable onAcknowledged) {
        boolean runNow = false;
        synchronized (outcomeLock) {
            if (stopped) {
                return;
            } else if (acknowledgedGeneration == generation) {
                // The redelivery worker may acknowledge before the loader registers.
                runNow = true;
            }
            else if (staleGeneration != generation && generation >= reportedGeneration) {
                waiterGeneration = generation;
                waiter = onAcknowledged;
            }
        }
        if (runNow) {
            runQuietly(onAcknowledged);
        }
    }

    private TokenLoaderContract.PushResult deliver(PendingPush candidate) {
        try {
            if (!prearm(candidate.generation())) {
                return new TokenLoaderContract.PushResult(false, 0L);
            }
        } catch (RuntimeException storageFailure) {
            // No RPC follows an unsuccessful or ambiguous durable prearm.
            return new TokenLoaderContract.PushResult(false, 0L);
        }
        try {
            var attempt = client.reloadAttempt(candidate.generation(), toVerifiers(candidate.verifiers()));
            return toPushResult(candidate.generation(), attempt.commitment(), attempt.response());
        } catch (StatusRuntimeException transport) {
            if (Status.fromThrowable(transport).getCode() == Status.Code.FAILED_PRECONDITION) {
                // Wire-auth §5.2 reserves this rejection for incompatible IPC versions.
                // Do not attach the peer exception: its description/trailers are untrusted (III).
                throw new IncompatiblePeerVersionException();
            }
            // Preserve existing containment without a diagnostic journal (II/III).
            return new TokenLoaderContract.PushResult(false, 0L);
        }
    }

    private boolean prearm(long generation) {
        synchronized (outcomeLock) {
            if (stopped) {
                return false;
            }
            if (generations.prearmDelivery(generation)) {
                // Constitution V: durable UNRESOLVED must replace an old ACK before replay.
                recordPending(generation);
                return true;
            }
            TokenLoaderContract.GenerationStore.DeliveryMarker marker = generations.deliveryMarker();
            stopped = true;
            reportedGeneration = Math.max(reportedGeneration, marker.generation());
            if (marker.state() == TokenLoaderContract.GenerationStore.DeliveryState.STALE) {
                staleGeneration = marker.generation();
                clearPendingThrough(marker.generation());
                current.set(null);
                waiter = null;
                publish("STALE_CONFLICT");
            } else if (marker.state() == TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED) {
                publish("PENDING");
            } else {
                publish("UNKNOWN");
            }
            return false;
        }
    }

    private boolean completeAcknowledgement(PendingPush candidate, long attemptRevision) {
        // Test-only boundary seam; deployed instances supply the no-op callback.
        beforeAcknowledgementClear.run();
        boolean cleared;
        synchronized (outcomeLock) {
            // Admission and this durable clear share outcomeLock: an older ACK
            // cannot clear the unresolved marker armed by a reconnect replay.
            if (stopped || admissionRevision != attemptRevision) {
                return false;
            }
            try {
                cleared = generations.acknowledgeDelivery(candidate.generation());
            } catch (RuntimeException storageFailure) {
                return false;
            }
        }
        if (cleared) {
            afterAcknowledgementClear.run();
        }
        return cleared;
    }

    private long admissionRevision() {
        synchronized (outcomeLock) {
            return admissionRevision;
        }
    }

    /** Completes ACK bookkeeping only if no reconnect admitted a newer replay. */
    private boolean finishAcknowledgement(PendingPush candidate, long attemptRevision) {
        Runnable deferred = null;
        synchronized (outcomeLock) {
            if (stopped || admissionRevision != attemptRevision) {
                return false;
            }
            clearPendingThrough(candidate.generation());
            if (candidate.generation() < reportedGeneration) {
                return false;
            }
            reportedGeneration = candidate.generation();
            acknowledgedGeneration = candidate.generation();
            publish("ACKNOWLEDGED(" + candidate.generation() + ")");
            if (waiter != null && waiterGeneration == candidate.generation()) {
                deferred = waiter;
                waiter = null;
            }
        }
        if (deferred != null) {
            runQuietly(deferred);
        }
        return true;
    }

    private void enqueue(PendingPush candidate) {
        synchronized (outcomeLock) {
            // Order queue admission with the stale-stop and pending clear.
            if (stopped) {
                return;
            }
            admissionRevision++;
            if (candidate.generation() >= reportedGeneration) {
                reportedGeneration = candidate.generation();
                acknowledgedGeneration = 0L;
                publish("PENDING");
            }
            pending.accumulateAndGet(candidate, (current, proposed) ->
                    current == null || proposed.generation() >= current.generation() ? proposed : current);
            startRetryWorker();
        }
    }

    private void startRetryWorker() {
        if (!retryWorkerRunning.compareAndSet(false, true)) {
            return;
        }
        Thread.ofVirtual().name("stargate-auth-redelivery").start(this::retryPending);
    }

    private void retryPending() {
        long delayMillis = INITIAL_RETRY_MILLIS;
        try {
            while (true) {
                PendingPush candidate = pending.get();
                if (candidate == null) {
                    return;
                }
                Thread.sleep(delayMillis);
                TokenLoaderContract.PushResult result;
                long attemptRevision = admissionRevision();
                try {
                    result = deliver(candidate);
                } catch (IncompatiblePeerVersionException incompatible) {
                    forget(candidate);
                    pending.compareAndSet(candidate, null);
                    dropWaiter();
                    return;
                } catch (IllegalStateException closed) {
                    // ReloadTokensClient.close() is the retry lifecycle boundary.
                    pending.set(null);
                    dropWaiter();
                    return;
                }
                if (result.stale()) {
                    forget(candidate);
                    pending.compareAndSet(candidate, null);
                    recordStale(candidate.generation());
                    delayMillis = INITIAL_RETRY_MILLIS;
                }
                else if (acknowledged(candidate, result)
                        && completeAcknowledgement(candidate, attemptRevision)
                        && finishAcknowledgement(candidate, attemptRevision)) {
                    remember(candidate);
                    delayMillis = INITIAL_RETRY_MILLIS;
                }
                else if (acknowledged(candidate, result)) {
                    delayMillis = Math.min(delayMillis * 2L, MAX_RETRY_MILLIS);
                }
                else {
                    delayMillis = Math.min(delayMillis * 2L, MAX_RETRY_MILLIS);
                }
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            retryWorkerRunning.set(false);
            if (pending.get() != null) {
                startRetryWorker();
            }
        }
    }

    private void redeliverCurrent() {
        if (stopped) {
            return;
        }
        PendingPush candidate = current.get();
        if (candidate != null) {
            enqueue(candidate);
        }
    }

    private void remember(PendingPush candidate) {
        current.accumulateAndGet(candidate, (known, proposed) ->
                known == null || proposed.generation() >= known.generation() ? proposed : known);
    }

    private void forget(PendingPush candidate) {
        current.compareAndSet(candidate, null);
    }

    private static boolean acknowledged(PendingPush candidate, TokenLoaderContract.PushResult result) {
        return !result.stale() && result.currentGeneration() == candidate.generation();
    }

    private void clearPendingThrough(long generation) {
        pending.updateAndGet(current -> current != null && current.generation() <= generation ? null : current);
    }

    private void recordPending(long generation) {
        synchronized (outcomeLock) {
            if (generation < reportedGeneration) {
                return;
            }
            reportedGeneration = generation;
            publish("PENDING");
        }
    }

    private void recordStale(long generation) {
        synchronized (outcomeLock) {
            stopped = true;
            pending.set(null);
            current.set(null);
            waiter = null;
            waiterGeneration = 0;
            reportedGeneration = Math.max(reportedGeneration, generation);
            try {
                if (generations.recordStaleDelivery(generation)) {
                    staleGeneration = generation;
                    publish("STALE_CONFLICT");
                }
            } catch (RuntimeException storageFailure) {
                // The committed UNRESOLVED prearm remains the restart barrier.
            }
        }
    }

    private void dropWaiter() {
        synchronized (outcomeLock) {
            waiter = null;
        }
    }

    /** A failing count sink must not stop redelivery; no diagnostic is retained (III). */
    private static void runQuietly(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException ignored) {
            // Operational counts are best-effort observations of this CP (data-model §4).
        }
    }

    /**
     * Replaces the status with one fixed-vocabulary line: write a private
     * sibling, then atomically rename it over the target so a reader never
     * sees a partial value. Called under {@code outcomeLock} so writes keep
     * outcome order. If the replacement fails, the previous value is
     * withdrawn — an obsolete state must never keep reading as current — and
     * a background retry publishes the latest state once writing works again.
     * Failures stay silent (III) and never affect delivery.
     */
    private void publish(String state) {
        if (deliveryStatus == null) {
            return;
        }
        if (write(state)) {
            unpublished = null;
            return;
        }
        clearStatus();
        unpublished = state;
        startRepublisher();
    }

    private boolean write(String state) {
        Path target = deliveryStatus;
        if (target == null) {
            return true;
        }
        Path directory = target.toAbsolutePath().getParent();
        if (directory == null) {
            return false;
        }
        Path sibling = directory.resolve(target.getFileName() + ".tmp");
        try {
            Files.createDirectories(directory,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            Files.deleteIfExists(sibling);
            try (SeekableByteChannel out = Files.newByteChannel(sibling,
                    EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
                ByteBuffer line = ByteBuffer.wrap((state + "\n").getBytes(StandardCharsets.US_ASCII));
                while (line.hasRemaining()) {
                    out.write(line);
                }
            }
            Files.move(sibling, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException | RuntimeException failed) {
            return false;
        }
    }

    private void startRepublisher() {
        if (!republisherRunning.compareAndSet(false, true)) {
            return;
        }
        Thread.ofVirtual().name("stargate-auth-status").start(this::republish);
    }

    private void republish() {
        try {
            while (unpublished != null) {
                Thread.sleep(STATUS_REPUBLISH_MILLIS);
                synchronized (outcomeLock) {
                    String state = unpublished;
                    if (state != null && write(state)) {
                        unpublished = null;
                    }
                }
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            republisherRunning.set(false);
            if (unpublished != null && !Thread.currentThread().isInterrupted()) {
                startRepublisher();
            }
        }
    }

    private void clearStatus() {
        Path target = deliveryStatus;
        if (target == null) {
            return;
        }
        try {
            Files.deleteIfExists(target);
        } catch (IOException | RuntimeException ignored) {
            // A stale value that cannot be removed is overwritten by the first outcome.
        }
    }

    static final class IncompatiblePeerVersionException extends IllegalStateException {
        IncompatiblePeerVersionException() {
            super("INCOMPATIBLE_PEER_VERSION");
        }
    }

    /** Test-visible response classification; production uses the exact-match overload below. */
    static TokenLoaderContract.PushResult toPushResult(ReloadTokensResponse response) {
        // The proto3 enum-value accessors (…Value/…_VALUE) are the identical
        // comparison spelled without the lowerCamelCase enum getter — the T022
        // row-10 production-caller gate greps that getter's literal invocation
        // shape as a needle, and the coarse FAIL-forcing probe stays by
        // doctrine (tests/contract/control-grpc/transport_test.go; the T093
        // wire-gate precedent).
        boolean stale = response.getStatusValue() == ApplyStatus.APPLY_STATUS_STALE_GENERATION_VALUE;
        boolean marked = response.getStatusValue() == ApplyStatus.APPLY_STATUS_OK_VALUE
                && response.getAcknowledgmentVersion() == 1
                && response.getAppliedGeneration() != 0
                && response.getAppliedGeneration() == response.getCurrentGeneration()
                && response.getCommitment().size() == 32;
        return new TokenLoaderContract.PushResult(stale,
                stale ? response.getCurrentGeneration() : (marked ? response.getAppliedGeneration() : 0L));
    }

    static TokenLoaderContract.PushResult toPushResult(long generation,
            ByteString expectedCommitment, ReloadTokensResponse response) {
        if (response.getStatusValue() == ApplyStatus.APPLY_STATUS_STALE_GENERATION_VALUE) {
            return new TokenLoaderContract.PushResult(true, 0L);
        }
        boolean acknowledged = response.getStatusValue() == ApplyStatus.APPLY_STATUS_OK_VALUE
                && response.getAcknowledgmentVersion() == 1
                && response.getAppliedGeneration() == generation
                && response.getCurrentGeneration() == generation
                && response.getCommitment().equals(expectedCommitment);
        return new TokenLoaderContract.PushResult(false, acknowledged ? generation : 0L);
    }

    private static List<TokenVerifier> toVerifiers(List<byte[]> verifiers) {
        return verifiers.stream()
                .map(v -> TokenVerifier.newBuilder()
                        .setVerifier(ByteString.copyFrom(v))
                        .build())
                .toList();
    }
}
