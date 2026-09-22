// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.persistence;

import java.time.Clock;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import app.zcat.stargate.auth.TokenLoaderContract;
import io.quarkus.narayana.jta.QuarkusTransaction;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Singleton;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Status;
import jakarta.transaction.Synchronization;
import jakarta.transaction.TransactionSynchronizationRegistry;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jspecify.annotations.Nullable;

/**
 * Constitution III / data-model §4: transaction-committed counts remain volatile until
 * their UTC hour closes. Neither caller labels nor details are retained, even in memory.
 * The legacy three-argument sink is retained only as an in-process compatibility seam.
 */
@Singleton
public class AuditLogService implements TokenLoaderContract.AuditSink {
    public static final String ACTION_ENROLLED = "enrolled";
    public static final String ACTION_REVOKED = "revoked";
    public static final String ACTION_CONFIG_ERROR = "config_error";
    public static final String ACTION_SIDECAR_HEALTHY = "sidecar_healthy";
    public static final String ACTION_SIDECAR_UNHEALTHY = "sidecar_unhealthy";
    private static final String[] CATEGORIES = { ACTION_ENROLLED, ACTION_REVOKED,
            ACTION_CONFIG_ERROR, ACTION_SIDECAR_HEALTHY, ACTION_SIDECAR_UNHEALTHY };
    private static final long HOUR = 3600;
    private static final long RETENTION = 7 * 86400;
    private final EntityManager em;
    private final TransactionSynchronizationRegistry transactions;
    private final Map<Long, long[]> pending = new TreeMap<>();
    private Clock clock = Clock.systemUTC();
    private long closedThrough;
    private long latestSecond;
    private boolean retain;
    private @Nullable ScheduledExecutorService worker;
    private @Nullable ScheduledFuture<?> scheduled;

    @ConfigProperty(name = "stargate.operational.retention-enabled", defaultValue = "true")
    boolean retentionEnabled;

    AuditLogService(EntityManager em, TransactionSynchronizationRegistry transactions) {
        this.em = em;
        this.transactions = transactions;
    }

    @PostConstruct
    void start() {
        initialize(Clock.systemUTC(), retentionEnabled);
        worker = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "operational-aggregates");
            thread.setDaemon(true);
            return thread;
        });
        scheduled = worker.scheduleWithFixedDelay(() -> {
            try {
                flush();
            } catch (RuntimeException unavailable) {
                // A failed persistence attempt retains bounded, finalized counters for retry.
                // It cannot become a diagnostic journal or interfere with routing (II/III).
            }
        }, 1, 1, TimeUnit.SECONDS);
    }

    /** Also used by storage tests to exercise restart/clock policy without sleeping an hour. */
    synchronized void initialize(Clock time, boolean enabled) {
        clock = time;
        retain = enabled;
        pending.clear();
        latestSecond = clock.instant().getEpochSecond();
        long persisted = QuarkusTransaction.requiringNew().call(() -> ((Number) em
                .createNativeQuery("SELECT COALESCE(MAX(hour_bucket), -3600) FROM operational_aggregates")
                .getSingleResult()).longValue());
        closedThrough = Math.max(hour(latestSecond) - HOUR, persisted);
        latestSecond = Math.max(latestSecond, persisted + HOUR);
        flush();
    }

    @Override
    public void write(String action, String target, String detailJson) {
        int category = switch (action) {
            case ACTION_ENROLLED -> 0;
            case ACTION_REVOKED -> 1;
            case ACTION_CONFIG_ERROR -> 2;
            case ACTION_SIDECAR_HEALTHY -> 3;
            case ACTION_SIDECAR_UNHEALTHY -> 4;
            default -> throw new IllegalArgumentException("unsupported operational category");
        };
        int transactionStatus = transactions.getTransactionStatus();
        if (transactionStatus == Status.STATUS_ACTIVE) {
            // Only a fixed-size vector enters transaction-local state. Completion time owns
            // the bucket: a transaction may outlive the hour in which it began.
            long[] counts = (long[]) transactions.getResource(this);
            if (counts == null) {
                counts = new long[CATEGORIES.length];
                transactions.putResource(this, counts);
                long[] committed = counts;
                transactions.registerInterposedSynchronization(new Synchronization() {
                    @Override public void beforeCompletion() { }
                    @Override public void afterCompletion(int status) {
                        if (status == Status.STATUS_COMMITTED) increment(committed);
                    }
                });
            }
            counts[category] = add(counts[category], 1);
        } else if (transactionStatus == Status.STATUS_NO_TRANSACTION) {
            long[] counts = new long[CATEGORIES.length];
            counts[category] = 1;
            increment(counts);
        }
    }

    private synchronized void increment(long[] counts) {
        long now = clock.instant().getEpochSecond();
        long bucket = hour(now);
        // Conservative clock policy: never shift events into a future hour or reopen one.
        if (!retain || now < latestSecond || bucket <= closedThrough) return;
        latestSecond = now;
        expirePending();
        long[] current = pending.computeIfAbsent(bucket, ignored -> new long[CATEGORIES.length]);
        for (int i = 0; i < counts.length; i++) current[i] = add(current[i], counts[i]);
    }

    /** Finalizes and expires on the worker and before any future export/read surface. */
    synchronized void flush() {
        latestSecond = Math.max(latestSecond, clock.instant().getEpochSecond());
        closedThrough = Math.max(closedThrough, hour(latestSecond) - HOUR);
        expirePending();
        // Keep a truthful zero enrollment counter for the latest closed hour even
        // when there were no events. It preserves the restart clock boundary after
        // older nonzero buckets expire, without another metadata field/category.
        if (retain && closedThrough >= 0) pending.computeIfAbsent(closedThrough,
                ignored -> new long[CATEGORIES.length]);
        QuarkusTransaction.requiringNew().run(() -> {
            if (!retain) {
                em.createNativeQuery("DELETE FROM operational_aggregates").executeUpdate();
                return;
            }
            for (var entry : pending.entrySet()) {
                if (entry.getKey() > closedThrough) continue;
                for (int i = 0; i < CATEGORIES.length; i++) {
                    if (entry.getValue()[i] == 0 && i != 0) continue;
                    // Retry is idempotent, including an ambiguous commit result; a completed
                    // row is never updated or combined with a later process's observations.
                    em.createNativeQuery("INSERT OR IGNORE INTO operational_aggregates "
                            + "(hour_bucket, category, count) VALUES (?1, ?2, ?3)")
                            .setParameter(1, entry.getKey()).setParameter(2, CATEGORIES[i])
                            .setParameter(3, entry.getValue()[i]).executeUpdate();
                }
            }
            em.createNativeQuery("DELETE FROM operational_aggregates WHERE hour_bucket <= ?1")
                    .setParameter(1, latestSecond - HOUR - RETENTION).executeUpdate();
        });
        pending.keySet().removeIf(bucket -> bucket <= closedThrough);
        if (!retain) pending.clear();
    }

    private void expirePending() {
        pending.keySet().removeIf(bucket -> bucket + HOUR + RETENTION <= latestSecond);
    }
    private static long hour(long second) { return Math.floorDiv(second, HOUR) * HOUR; }
    private static long add(long value, long increment) {
        return value > Long.MAX_VALUE - increment ? Long.MAX_VALUE : value + increment;
    }
    @PreDestroy
    synchronized void close() {
        if (scheduled != null) scheduled.cancel(false);
        scheduled = null;
        if (worker != null) worker.shutdownNow();
        worker = null;
        // Do not flush the current hour at shutdown: completion, not process exit, permits retention.
    }
}
