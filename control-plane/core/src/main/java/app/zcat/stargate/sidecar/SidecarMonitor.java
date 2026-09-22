// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.sidecar;

import java.time.Duration;
import java.time.Instant;
import java.util.function.LongSupplier;


/**
 * Advisory Tor health-to-event reducer. T138 forbids treating an unavailable
 * observer as proof that Tor exited or restarted. This class has no cookie,
 * ControlPort address, or raw Tor command path (Constitution II/III).
 */
public final class SidecarMonitor implements AutoCloseable {


    public static final String SIDECAR_TOR = "tor";
    public static final String DETAIL_CONTAINER_START = "container_start";
    public static final String DETAIL_HEALTHCHECK_PASS = "healthcheck_pass";
    public static final String DETAIL_HEALTHCHECK_FAIL = "healthcheck_fail";
    public static final String ACTION_SIDECAR_HEALTHY = "sidecar_healthy";
    public static final String ACTION_SIDECAR_UNHEALTHY = "sidecar_unhealthy";
    public static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(10);

    // The enum retains the closed wire vocabulary. The health observer emits
    // only STARTED, HEALTHY and UNHEALTHY; no Tor lifecycle claim is inferred.
    public enum Kind { STARTED, HEALTHY, UNHEALTHY, STOPPED, CRASHED, RESTARTED }
    public enum Health { READY, NOT_READY, UNAVAILABLE }

    public record Event(Instant ts, String sidecar, Kind kind, String detail) {
    }

    @FunctionalInterface
    public interface HealthProbe {
        Health sample();
    }

    @FunctionalInterface
    public interface EventSink {
        void publish(Event event);
    }

    @FunctionalInterface
    public interface AuditSink {
        void write(String action, String target, String detailJson);
    }

    private final HealthProbe probe;
    private final Duration pollInterval;
    private final LongSupplier generation;
    private final EventSink events;
    private final AuditSink audit;
    private final Thread loop;
    private volatile boolean running;
    private Health previous = Health.UNAVAILABLE;
    private boolean everValid;
    private boolean pendingHealthyAudit;

    public SidecarMonitor(HealthProbe probe, Duration pollInterval, LongSupplier generation,
            EventSink events, AuditSink audit) {
        this.probe = probe;
        this.pollInterval = pollInterval;
        this.generation = generation;
        this.events = events;
        this.audit = audit;
        this.loop = new Thread(this::loop, "sidecar-monitor-tor");
        this.loop.setDaemon(true);
    }

    public synchronized void start() {
        if (running) {
            throw new IllegalStateException("sidecar monitor already started");
        }
        running = true;
        loop.start();
    }

    private void loop() {
        while (running) {
            runOnce();
            try {
                Thread.sleep(pollInterval.toMillis());
            } catch (InterruptedException e) {
                break;
            }
        }
    }

    /** One complete advisory sample; package scope permits deterministic tests. */
    void runOnce() {
        Health current;
        try {
            current = probe.sample();
        } catch (RuntimeException failure) {
            // A failed health channel cannot stop CP boot or DP routing.
            current = Health.UNAVAILABLE;
        }
        if (!everValid && current != Health.UNAVAILABLE) {
            everValid = true;
            emit(Kind.STARTED, DETAIL_CONTAINER_START);
        }
        if (current == Health.READY && previous != Health.READY) {
            emit(Kind.HEALTHY, DETAIL_HEALTHCHECK_PASS);
            pendingHealthyAudit = true;
        } else if (previous == Health.READY && current != Health.READY) {
            emit(Kind.UNHEALTHY, DETAIL_HEALTHCHECK_FAIL);
            try {
                audit.write(ACTION_SIDECAR_UNHEALTHY, SIDECAR_TOR, "{\"kind\":\"UNHEALTHY\"}");
            } catch (RuntimeException failure) {
                // Preserve advisory availability without a diagnostic journal (II/III).
            }
        }
        previous = current;
        if (current == Health.READY && pendingHealthyAudit) {
            try {
                audit.write(ACTION_SIDECAR_HEALTHY, SIDECAR_TOR,
                        "{\"generation\":" + generation.getAsLong() + "}");
                pendingHealthyAudit = false;
            } catch (RuntimeException failure) {
                // Preserve advisory availability without a diagnostic journal (II/III).
            }
        }
    }

    private void emit(Kind kind, String detail) {
        try {
            events.publish(new Event(Instant.now(), SIDECAR_TOR, kind, detail));
        } catch (RuntimeException failure) {
                // Preserve advisory availability without a diagnostic journal (II/III).
        }
    }

    @Override
    public synchronized void close() {
        running = false;
        loop.interrupt();
        try {
            loop.join(7_000); // CP's observer call has a six-second cap.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
