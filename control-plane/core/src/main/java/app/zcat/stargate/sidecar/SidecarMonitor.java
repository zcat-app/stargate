// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.sidecar;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.function.LongSupplier;

import org.jboss.logging.Logger;

/**
 * The Tor sidecar lifecycle monitor (T039) — observes Tor through its
 * cookie-authenticated ControlPort ({@code tor:9051} over the compose-
 * internal {@code stargate-cp-tor} network) and emits {@code STARTED} +
 * {@code HEALTHY} events into the injected {@link EventSink} (T041 adapts
 * this to {@code ControlGrpcService.publish} on the WatchEvents stream),
 * writing a §4 {@code sidecar_healthy} audit row through {@link AuditSink}
 * (T036's {@code AuditLogService}) on each transition into HEALTHY.
 * UNHEALTHY/STOPPED/CRASHED/RESTARTED transitions are T074's extension.
 *
 * <p><strong>Observation channel (T094a amendment).</strong> The CP
 * authenticates with the COOKIE method only: {@code AUTHENTICATE} carries
 * the lowercase hex of the control cookie, which compose mounts into the CP
 * as a single read-only file (volume {@code subpath} of
 * {@code stargate-tor-state:control_auth_cookie}; the tor image pins
 * UID/GID 5103 and the CP holds that group, satisfying
 * {@code CookieAuthFileGroupReadable 1}'s 0640 mode — and nothing else of
 * Tor's state, notably the entry-guard files, is mounted; THREAT-MODEL
 * §4.2). The monitor is the CP's ONLY outbound dialer and dials only the
 * configured {@code (host, 9051)} — never a host-published port (FR-012).
 *
 * <p><strong>Read-only command allowlist.</strong> Tor's control protocol
 * has no per-command ACL — the cookie holder commands everything
 * ({@code SETEVENTS}/{@code SETCONF}/{@code ATTACHSTREAM}/{@code ADD_ONION};
 * redteam finding 20260727-001). The monitor therefore issues exactly three
 * hard-coded commands — {@code AUTHENTICATE <hex>},
 * {@code GETINFO status/bootstrap-phase}, {@code QUIT} — and never sends
 * any reply-derived or external string. This is the policy-mechanism
 * boundary this class owns; the compose/network boundary is M14's.
 *
 * <p><strong>Fixed vocabulary.</strong> {@code detail} is drawn from the
 * closed set in {@code contracts/control-grpc.md} §"WatchEvents":
 * {@code STARTED → container_start}, {@code HEALTHY → healthcheck_pass}.
 * Tor's reply text (bootstrap strings) never enters events or logs
 * (arch §5.2; FR-014) — logs carry state tokens and status codes only.
 *
 * <p><strong>State machine.</strong> {@code STARTED} fires on the edge into
 * an authenticated control session (the honest analog of "the container
 * started" available over this channel; a failed cycle re-arms it, so
 * a Tor restart re-emits {@code STARTED}). {@code HEALTHY} fires on each
 * edge into {@code PROGRESS=100}, the same signal Tor's own healthcheck
 * probes ({@code sidecars/tor/Dockerfile}); each entry writes exactly one
 * §4 row {@code sidecar_healthy}/{@code tor}/
 * {@code {"generation":<gen>}} with {@code <gen>} from the injected
 * generation supplier (§1.8: {@code 0} = none). Failed cycles (refused
 * connection, auth rejection, absent cookie, malformed reply) emit and
 * write nothing and never propagate — the monitor is advisory surface and
 * must never take the control plane down (Principle II; FR-014).
 */
public final class SidecarMonitor implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(SidecarMonitor.class);

    /** The only sidecar this feature observes (control-grpc.md §"WatchEvents"). */
    public static final String SIDECAR_TOR = "tor";

    /** Fixed-vocabulary detail for {@link Kind#STARTED} (control-grpc.md). */
    public static final String DETAIL_CONTAINER_START = "container_start";

    /** Fixed-vocabulary detail for {@link Kind#HEALTHY} (control-grpc.md). */
    public static final String DETAIL_HEALTHCHECK_PASS = "healthcheck_pass";

    /** data-model.md §4 action for a transition into HEALTHY. Validated
     * against the same fixed vocabulary by AuditLogService (T036). */
    public static final String ACTION_SIDECAR_HEALTHY = "sidecar_healthy";

    /** Tor ControlPort default inside the compose network (torrc invariant #3). */
    public static final int CONTROL_PORT = 9051;

    /** Compose DNS name of the Tor sidecar (FR-007 service key). */
    public static final String TOR_HOST = "tor";

    /** Where compose mounts the single-file cookie subpath into the CP. */
    public static final Path DEFAULT_COOKIE_PATH = Path.of("/run/tor/control_auth_cookie");

    /** Poll cadence — bounded per the ticket; well under Tor's 30s healthcheck interval. */
    public static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(10);

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS = 5_000;
    private static final int MAX_LINE_CHARS = 8_192;
    private static final int MAX_REPLY_LINES = 64;

    /** The v1 subset of the wire {@code stargate.v1.EventKind}; T074 adds
     * UNHEALTHY/STOPPED/CRASHED/RESTARTED (control-grpc.md §"WatchEvents"). */
    public enum Kind { STARTED, HEALTHY }

    /**
     * Neutral event shape mirroring {@code stargate.v1.SidecarEvent} minus
     * transport — the runtime adapter (T041) maps it onto the proto and
     * stamps nothing: {@code ts} is the emission instant observed here.
     */
    public record Event(Instant ts, String sidecar, Kind kind, String detail) {
    }

    /** Port the monitor emits into. Production adapter: ControlGrpcService. */
    public interface EventSink {
        void publish(Event event);
    }

    /** Port for the §4 audit row. Production adapter: AuditLogService.write. */
    public interface AuditSink {
        void write(String action, String target, String detailJson);
    }

    private final String host;
    private final int port;
    private final Path cookiePath;
    private final Duration pollInterval;
    private final LongSupplier generation;
    private final EventSink events;
    private final AuditSink audit;

    /** Created inert in the constructor; {@link #start()} owns its lifecycle. */
    private final Thread loop;
    private volatile boolean running;
    private volatile boolean connected;
    private volatile boolean healthy;

    /**
     * @param host       ControlPort host (compose DNS name {@code tor})
     * @param port       ControlPort (9051; FR-012 — never a published port)
     * @param cookiePath the single-file cookie subpath mount
     * @param pollInterval bounded cycle cadence
     * @param generation current token generation supplier (§1.8; 0 = none)
     * @param events     event sink (T041 wires ControlGrpcService)
     * @param audit      §4 audit sink (T036 wires AuditLogService)
     */
    public SidecarMonitor(String host, int port, Path cookiePath, Duration pollInterval,
            LongSupplier generation, EventSink events, AuditSink audit) {
        this.host = host;
        this.port = port;
        this.cookiePath = cookiePath;
        this.pollInterval = pollInterval;
        this.generation = generation;
        this.events = events;
        this.audit = audit;
        this.loop = new Thread(this::loop, "sidecar-monitor-tor");
        this.loop.setDaemon(true);
    }

    /** Starts the bounded-interval poll loop. Single-lifecycle: start once. */
    public synchronized void start() {
        if (running) {
            throw new IllegalStateException("sidecar monitor already started");
        }
        running = true;
        loop.start();
    }

    private void loop() {
        while (running) {
            try {
                runOnce();
            } catch (RuntimeException e) {
                // Safety net for must-hold 7: an injected port that escapes
                // its own containment must degrade to a failed cycle, never
                // kill the poll thread (Principle II — advisory surface).
                markDown();
                LOG.warnf("sidecar tor: poll cycle aborted (%s)", e.getClass().getSimpleName());
            }
            try {
                Thread.sleep(pollInterval.toMillis());
            } catch (InterruptedException e) {
                break; // close() requested
            }
        }
    }

    @Override
    public synchronized void close() {
        running = false;
        loop.interrupt();
        try {
            loop.join(5_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * One poll cycle: read the cookie, dial the ControlPort, authenticate,
     * query bootstrap phase, fire edges. Every failure mode inside this
     * method is contained — a failed cycle changes state to "down" and
     * returns quietly so the next cycle can proceed (must-hold 7).
     */
    void runOnce() {
        final byte[] cookie;
        try {
            cookie = Files.readAllBytes(cookiePath);
        } catch (NoSuchFileException e) {
            // Boot ordering tolerates a not-yet-mounted cookie: skip quietly.
            markDown();
            return;
        } catch (IOException e) {
            LOG.warnf("sidecar tor: control cookie unreadable (%s); cycle skipped", e.getClass().getSimpleName());
            markDown();
            return;
        }
        if (cookie.length == 0) {
            LOG.warn("sidecar tor: control cookie is empty; cycle skipped");
            markDown();
            return;
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            final Writer out = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.ISO_8859_1);
            final Reader in = new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1);

            send(out, "AUTHENTICATE " + toHex(cookie));
            String reply = readLine(in);
            if (!isSuccess(reply)) {
                markDown();
                LOG.warnf("sidecar tor: ControlPort rejected the cookie exchange (status %s)",
                        statusCode(reply));
                return;
            }
            // STARTED is edge-triggered per session: a failed cycle marked
            // the session down, so the next authenticated cycle re-arms it.
            // It fires only after the cycle's state read has completed — a
            // session that authenticates but cannot report bootstrap state
            // has not observably "started" (aborted cycles emit nothing).
            boolean wasConnected = connected;
            connected = true;

            send(out, "GETINFO status/bootstrap-phase");
            String phase = readReply(in);

            if (!wasConnected) {
                emit(Kind.STARTED, DETAIL_CONTAINER_START);
            }
            boolean bootstrapped = false;
            for (String token : phase.split("\\s+")) {
                if (token.equals("PROGRESS=100")) {
                    bootstrapped = true;
                    break;
                }
            }
            if (bootstrapped && !healthy) {
                healthy = true;
                emit(Kind.HEALTHY, DETAIL_HEALTHCHECK_PASS);
                writeAuditRow();
            } else if (!bootstrapped) {
                healthy = false;
            }

            try {
                send(out, "QUIT");
            } catch (IOException ignored) {
                // the cycle is already complete; the socket close below ends the session
            }
        } catch (IOException e) {
            markDown();
            LOG.warnf("sidecar tor: ControlPort cycle failed (%s)", e.getClass().getSimpleName());
        }
    }

    private void markDown() {
        connected = false;
        healthy = false;
    }

    private void emit(Kind kind, String detail) {
        try {
            events.publish(new Event(Instant.now(), SIDECAR_TOR, kind, detail));
        } catch (RuntimeException e) {
            // Advisory fan-out must never take the poll loop down (Principle II).
            LOG.warnf("sidecar tor: event sink rejected %s (%s)", detail, e.getClass().getSimpleName());
        }
    }

    private void writeAuditRow() {
        // The generation supplier is an injected port like the sinks: its
        // failure is contained here, and the HEALTHY edge is re-armed so
        // the §4 row is retried on the next healthy cycle (must-hold 5:
        // exactly one row per ENTRY — a lost row is retried, never
        // duplicated) rather than lost for the session.
        final String detailJson;
        try {
            detailJson = "{\"generation\":" + generation.getAsLong() + "}";
        } catch (RuntimeException e) {
            healthy = false;
            LOG.warnf("sidecar tor: generation unavailable, sidecar_healthy row deferred (%s)",
                    e.getClass().getSimpleName());
            return;
        }
        try {
            audit.write(ACTION_SIDECAR_HEALTHY, SIDECAR_TOR, detailJson);
        } catch (RuntimeException e) {
            LOG.warnf("sidecar tor: sidecar_healthy audit row lost (%s)", e.getClass().getSimpleName());
        }
    }

    private static void send(Writer out, String command) throws IOException {
        out.write(command);
        out.write("\r\n");
        out.flush();
    }

    /** Control-port success replies are 2xx; only single-line "250"-style is used here. */
    private static boolean isSuccess(String replyLine) {
        return replyLine.length() >= 3 && replyLine.charAt(0) == '2';
    }

    /** Extracts the 3-digit status code for the journal; non-numeric leading
     * bytes are logged as "malformed" — reply text never reaches the log. */
    private static String statusCode(String replyLine) {
        if (replyLine.length() >= 3
                && Character.isDigit(replyLine.charAt(0))
                && Character.isDigit(replyLine.charAt(1))
                && Character.isDigit(replyLine.charAt(2))) {
            return replyLine.substring(0, 3);
        }
        return "malformed";
    }

    /**
     * Reads a bounded multi-line control reply (250- continuations, final
     * 250-space line) and returns the concatenated payload. The reply is
     * external input: line length and line count are bounded, and a
     * non-250 status aborts the cycle.
     */
    private static String readReply(Reader in) throws IOException {
        StringBuilder payload = new StringBuilder();
        for (int i = 0; i < MAX_REPLY_LINES; i++) {
            String line = readLine(in);
            if (line.length() < 4 || (line.charAt(3) != '-' && line.charAt(3) != ' ')) {
                throw new IOException("malformed control reply status " + statusCode(line));
            }
            if (!isSuccess(line)) {
                throw new IOException("control reply status " + statusCode(line));
            }
            payload.append(line, 4, line.length()).append(' ');
            if (line.charAt(3) == ' ') {
                return payload.toString();
            }
        }
        throw new IOException("control reply exceeded " + MAX_REPLY_LINES + " lines");
    }

    /** Bounded readline — replies are external input (validate at the edge). */
    private static String readLine(Reader in) throws IOException {
        StringBuilder sb = new StringBuilder(128);
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                int len = sb.length();
                if (len > 0 && sb.charAt(len - 1) == '\r') {
                    sb.setLength(len - 1);
                }
                return sb.toString();
            }
            sb.append((char) c);
            if (sb.length() > MAX_LINE_CHARS) {
                throw new IOException("control reply line exceeded bound");
            }
        }
        throw new IOException("control port closed mid-reply");
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** Liveness introspection for the runtime wiring (T041); never gates anything. */
    boolean sessionConnected() {
        return connected;
    }
}
