// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.sidecar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** T138's finite health-to-event mapping, with no inferred Tor lifecycle. */
class SidecarMonitorTest {

    @TempDir
    Path tempDir;

    private static final class Recorder {
        final AtomicReference<SidecarMonitor.Health> health =
                new AtomicReference<>(SidecarMonitor.Health.UNAVAILABLE);
        final List<String> events = new ArrayList<>();
        final List<String> audits = new ArrayList<>();
        final SidecarMonitor monitor = new SidecarMonitor(() ->
                java.util.Objects.requireNonNull(health.get()), Duration.ofSeconds(10),
                () -> 7L,
                e -> events.add(e.kind() + "/" + e.detail()),
                (action, target, detail) -> audits.add(action + "/" + target + "/" + detail));

        void sample(SidecarMonitor.Health h) {
            health.set(h);
            monitor.runOnce();
        }
    }

    @Test
    void bootstrapFailureAndRecoveryNeverFabricateExitOrRestart() {
        Recorder r = new Recorder();
        r.sample(SidecarMonitor.Health.UNAVAILABLE); // observer down at boot
        r.sample(SidecarMonitor.Health.NOT_READY);   // authenticated bootstrap incomplete
        r.sample(SidecarMonitor.Health.UNAVAILABLE); // malformed Tor reply or timeout
        r.sample(SidecarMonitor.Health.NOT_READY);   // recovery, still bootstrapping
        r.sample(SidecarMonitor.Health.READY);
        r.sample(SidecarMonitor.Health.READY);
        r.sample(SidecarMonitor.Health.UNAVAILABLE); // observer down after READY
        r.sample(SidecarMonitor.Health.UNAVAILABLE);
        r.sample(SidecarMonitor.Health.READY);       // observer recovers
        r.sample(SidecarMonitor.Health.NOT_READY);
        r.sample(SidecarMonitor.Health.UNAVAILABLE);
        assertEquals(List.of(
                "STARTED/container_start",
                "HEALTHY/healthcheck_pass",
                "UNHEALTHY/healthcheck_fail",
                "HEALTHY/healthcheck_pass",
                "UNHEALTHY/healthcheck_fail"), r.events);
        assertEquals(List.of(
                "sidecar_healthy/tor/{\"generation\":7}",
                "sidecar_unhealthy/tor/{\"kind\":\"UNHEALTHY\"}",
                "sidecar_healthy/tor/{\"generation\":7}",
                "sidecar_unhealthy/tor/{\"kind\":\"UNHEALTHY\"}"), r.audits);
    }

    @Test
    void firstReadySampleEmitsStartedAndHealthyOnlyOnce() {
        Recorder r = new Recorder();
        r.sample(SidecarMonitor.Health.READY);
        r.sample(SidecarMonitor.Health.READY);
        assertEquals(List.of("STARTED/container_start", "HEALTHY/healthcheck_pass"), r.events);
    }

    @Test
    void transportFailureIsAdvisory() {
        List<String> events = new ArrayList<>();
        SidecarMonitor monitor = new SidecarMonitor(() -> {
            throw new IllegalStateException("fake observer down");
        }, Duration.ofSeconds(10), () -> 0L,
                e -> events.add(e.kind().name()), (action, target, detail) -> {});
        monitor.runOnce();
        assertEquals(List.of(), events);
    }

    @Test
    void javaClientAuthenticatesToGoObserverAndGetsOnlyReadyToken() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair cp = generator.generateKeyPair();
        KeyPair observer = generator.generateKeyPair();
        writePem(tempDir.resolve("cp.priv"), "PRIVATE KEY", cp.getPrivate().getEncoded());
        writePem(tempDir.resolve("cp.pub"), "PUBLIC KEY", cp.getPublic().getEncoded());
        writePem(tempDir.resolve("observer.priv"), "PRIVATE KEY", observer.getPrivate().getEncoded());
        writePem(tempDir.resolve("observer.pub"), "PUBLIC KEY", observer.getPublic().getEncoded());

        Path goDir = Path.of("../../data-plane").toAbsolutePath().normalize();
        ProcessBuilder builder = new ProcessBuilder("go", "test", "./cmd/tor-observer",
                "-run", "^TestJavaClientInteropFixture$", "-count=1", "-timeout=30s");
        builder.directory(goDir.toFile());
        builder.environment().put("T164_INTEROP_DIR", tempDir.toString());
        builder.redirectErrorStream(true);
        builder.redirectOutput(tempDir.resolve("go.log").toFile());
        Process fixture = builder.start();
        try {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
            while (!Files.exists(tempDir.resolve("ready")) && fixture.isAlive()
                    && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(Files.exists(tempDir.resolve("ready")),
                    "Go observer fixture started: " + Files.readString(tempDir.resolve("go.log")));
            ObserverHealthClient client = new ObserverHealthClient(tempDir.resolve("health.sock"),
                    tempDir.resolve("cp.priv"), tempDir.resolve("observer.pub"));
            assertEquals(SidecarMonitor.Health.READY, client.sample(),
                    "Java CP receives only sanitized READY from the real Go observer");
            Files.write(tempDir.resolve("stop"), new byte[0]);
            assertTrue(fixture.waitFor(5, TimeUnit.SECONDS), "Go fixture exited");
            assertEquals(0, fixture.exitValue(), Files.readString(tempDir.resolve("go.log")));
        } finally {
            fixture.destroyForcibly();
        }
    }

    private static void writePem(Path path, String type, byte[] der) throws Exception {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        Files.writeString(path, "-----BEGIN " + type + "-----\n" + body + "\n-----END "
                + type + "-----\n", StandardCharsets.US_ASCII);
    }
}
