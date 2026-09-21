// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import app.zcat.stargate.auth.HmacVerifierMinter;
import app.zcat.stargate.auth.TokenLoader;
import app.zcat.stargate.auth.TokenLoaderContract;
import app.zcat.stargate.persistence.AuditLogService;
import app.zcat.stargate.persistence.SqliteTokenState;
import app.zcat.stargate.sidecar.ObserverHealthClient;
import app.zcat.stargate.sidecar.SidecarMonitor;
import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import io.quarkus.stargate.control.grpc.ControlGrpcService;
import io.quarkus.stargate.control.grpc.ReloadTokensClient;
import jakarta.inject.Inject;
import stargate.v1.EventsOuterClass.EventKind;
import stargate.v1.EventsOuterClass.SidecarEvent;

/**
 * The control plane's entry point and production boot sequence (T041) — the
 * runnable Quarkus application aggregating api / core / persistence / ui.
 *
 * <p><strong>Startup sequence (tasks.md T041, as amended).</strong> The
 * verbatim body ordered torrc-render → monitor → token load → push; the T089
 * amendment REMOVED the render step (the static slice bakes the safe
 * {@code torrc} into the Tor image, T087 — the CP never writes
 * {@code stargate-tor-config}), and the T092 amendment wired the pepper
 * (§1.7) into the verifier mint. What ships:
 *
 * <ol>
 *   <li>read the 32-byte install-time pepper (§1.7; fail fast on missing or
 *       wrong-length — a CP that cannot mint verifiers cannot fulfill its one
 *       token function, the same fail-fast class as the §2.1 key-file
 *       errors);</li>
 *   <li>bind the CP's WatchEvents server on {@code control.sock} (T038) —
 *       the inter-plane surface exists before any push (UDS only, mode 0660,
 *       §"Socket topology");</li>
 *   <li>start the {@code SidecarMonitor} against the authenticated observer
 *       health socket; its samples are advisory to the data plane;</li>
 *   <li>load {@code tokens.yaml} once (T035; FR-018) — the loader persists
 *       the diff, bumps the §1.8 generation, and pushes
 *       {@code ReloadTokens} (T038) strictly last. A missing, unreadable, or
 *       invalid file warns and does NOT push (the DP keeps its last-known
 *       list and keeps serving — Principle II; only a successfully-parsed
 *       explicit {@code tokens: []} is the revoke-all path). A broken store
 *       (infrastructure, not configuration) is contained with a loud error:
 *       the CP stays up degraded rather than crash-looping, which the
 *       operator could not distinguish from a DP outage.</li>
 * </ol>
 *
 * <p><strong>Pepper discipline (T092 a/b).</strong> The pepper crosses
 * exactly one edge here: {@code pepper.key} → the
 * {@link HmacVerifierMinter}. It is never logged (the fail-fast messages
 * name the path and the expected length, never bytes), never persisted (the
 * CP writes no snapshot — verifiers only ever reach the store and the wire,
 * §1.6), and never leaves the process over any channel.
 *
 * <p>Shutdown is the reverse of startup (monitor → client → server) after
 * {@code Quarkus.waitForExit()} releases on SIGTERM; compose's
 * {@code restart: unless-stopped} then owns restarts.
 */
@QuarkusMain
public class StargateControlPlane implements QuarkusApplication {

    private static final Logger LOG = Logger.getLogger(StargateControlPlane.class);

    @Inject
    AuditLogService auditService;

    @Inject
    SqliteTokenState tokenState;

    // The production topology (FR-017/§1.7/control-grpc §"Socket topology";
    // plan.md DB path). Values live in application.properties — the compose
    // contract, not call-site literals.
    @ConfigProperty(name = "stargate.tokens-path")
    String tokensPath;

    @ConfigProperty(name = "stargate.pepper-path")
    String pepperPath;

    @ConfigProperty(name = "stargate.keys-dir")
    String keysDir;

    @ConfigProperty(name = "stargate.control-sock")
    String controlSock;

    @ConfigProperty(name = "stargate.dp-sock")
    String dpSock;

    @ConfigProperty(name = "stargate.tor-observer-sock")
    String torObserverSock;

    @ConfigProperty(name = "stargate.monitor-poll")
    Duration monitorPoll;

    public static void main(String[] args) {
        Quarkus.run(StargateControlPlane.class, args);
    }

    @Override
    public int run(String... args) throws Exception {
        BootConfig cfg = new BootConfig(Path.of(tokensPath), Path.of(pepperPath), Path.of(keysDir),
                Path.of(controlSock), Path.of(dpSock), Path.of(torObserverSock),
                monitorPoll);
        try (BootHandle handle = bootstrap(cfg, auditService, tokenState, tokenState)) {
            Quarkus.waitForExit();
        }
        return 0;
    }

    /** Immutable boot topology — one place the paths/topology enter the sequence. */
    record BootConfig(Path tokensYaml, Path pepperFile, Path keysDir, Path controlSock,
            Path dpSock, Path observerSock, Duration pollInterval) {
    }

    /** The started surfaces, closed in reverse start order. */
    static final class BootHandle implements AutoCloseable {

        private final ControlGrpcService.BoundServer server;
        private final SidecarMonitor monitor;
        private final ReloadTokensClient client;

        BootHandle(ControlGrpcService.BoundServer server, SidecarMonitor monitor,
                ReloadTokensClient client) {
            this.server = server;
            this.monitor = monitor;
            this.client = client;
        }

        @Override
        public void close() {
            monitor.close();
            client.close();
            server.close();
        }
    }

    /**
     * The boot sequence above, exactly. Package-private static so the test
     * suite drives the SAME code path the production {@code run()} does — the
     * store/audit/generation collaborators arrive through the T035a seams,
     * everything else is the production construction.
     */
    static BootHandle bootstrap(BootConfig cfg, TokenLoaderContract.AuditSink audit,
            TokenLoaderContract.ConfiguredTokenStore store, TokenLoaderContract.GenerationStore generations)
            throws IOException {
        byte[] pepper = readPepper(cfg.pepperFile());

        ControlGrpcService events = new ControlGrpcService();
        ControlGrpcService.BoundServer server = events.startServer(cfg.controlSock(),
                cfg.keysDir().resolve("cp.priv"), cfg.keysDir().resolve("cp.pub"),
                cfg.keysDir().resolve("dp.pub"));
        ReloadTokensClient client = null;
        SidecarMonitor monitor = null;
        try {
            // §2.1 startup errors (key derivation) propagate — the CP fails fast.
            client = ReloadTokensClient.create(cfg.keysDir(), cfg.dpSock());

            // Advisory observation starts before the load: the monitor's poll
            // loop runs on its own thread and is never blocked by the push.
            // The monitor declares its own (identical-shape) audit port —
            // T039's seam predates the T035a contract's availability here —
            // so the production sink adapts by shape.
            monitor = new SidecarMonitor(new ObserverHealthClient(cfg.observerSock(),
                    cfg.keysDir().resolve("cp.priv"), cfg.keysDir().resolve("observer.pub")),
                    cfg.pollInterval(), generations::lastGeneration, eventSink(events),
                    audit::write);
            monitor.start();

            TokenLoader loader = new TokenLoader(cfg.tokensYaml(), pepper, store, generations,
                    audit, new GrpcReloadChannel(client), new HmacVerifierMinter(pepper));
            try {
                loader.load(); // never throws on file input (FR-018); push happens inside, §1.7 last
            } catch (RuntimeException brokenInfrastructure) {
                LOG.errorf(brokenInfrastructure, "tokens.yaml load failed on infrastructure (%s) — "
                        + "the control plane continues degraded and the data plane keeps its "
                        + "last-known token list (Principle II; the next boot's §1.8 read re-syncs)",
                        brokenInfrastructure.getClass().getSimpleName());
            }
            return new BootHandle(server, monitor, client);
        } catch (RuntimeException failure) {
            // reverse-order teardown of whatever started before the failure
            if (monitor != null) {
                monitor.close();
            }
            if (client != null) {
                client.close();
            }
            server.close();
            throw failure;
        }
    }

    /**
     * §1.7 edge validation: the pepper must exist and be exactly 32 bytes.
     * Provisioning is {@code scripts/stargate init}'s job (T088) — a boot
     * that reaches for a missing pepper is a deployment error, surfaced
     * fail-fast with the path and the expected length (never the bytes).
     */
    static byte[] readPepper(Path pepperFile) {
        byte[] pepper;
        try {
            pepper = Files.readAllBytes(pepperFile);
        } catch (NoSuchFileException e) {
            throw new IllegalStateException("pepper file missing at " + pepperFile
                + " — provision it with scripts/stargate init (data-model.md §1.7)", e);
        } catch (IOException e) {
            throw new IllegalStateException("pepper file at " + pepperFile + " is unreadable ("
                + e.getClass().getSimpleName() + ") (data-model.md §1.7)", e);
        }
        if (pepper.length != HmacVerifierMinter.PEPPER_LEN) {
            throw new IllegalStateException("pepper file at " + pepperFile + " must be exactly "
                + HmacVerifierMinter.PEPPER_LEN + " bytes, got " + pepper.length + " (§1.7)");
        }
        return pepper;
    }

    /** The production monitor→WatchEvents adapter: T039's neutral Event onto the proto. */
    static SidecarMonitor.EventSink eventSink(ControlGrpcService events) {
        return event -> events.publish(toProto(event));
    }

    /** Fixed-vocabulary passthrough (control-grpc §"WatchEvents"; data-model §2). */
    static SidecarEvent toProto(SidecarMonitor.Event event) {
        return SidecarEvent.newBuilder()
                .setTs(com.google.protobuf.Timestamp.newBuilder()
                        .setSeconds(event.ts().getEpochSecond())
                        .setNanos(event.ts().getNano())
                        .build())
                .setSidecar(event.sidecar())
                .setKind(kindOf(event.kind()))
                .setDetail(event.detail())
                .build();
    }

    private static EventKind kindOf(SidecarMonitor.Kind kind) {
        return switch (kind) {
            case STARTED -> EventKind.EVENT_KIND_STARTED;
            case HEALTHY -> EventKind.EVENT_KIND_HEALTHY;
            case UNHEALTHY -> EventKind.EVENT_KIND_UNHEALTHY;
            case STOPPED -> EventKind.EVENT_KIND_STOPPED;
            case CRASHED -> EventKind.EVENT_KIND_CRASHED;
            case RESTARTED -> EventKind.EVENT_KIND_RESTARTED;
        };
    }
}
