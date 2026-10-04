// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.ui;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.vertx.http.HttpServerOptionsCustomizer;
import io.quarkus.vertx.http.ManagementInterface;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.PemKeyCertOptions;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;

/** Deployment Model: effective options must be checked before Vert.x listens. */
@QuarkusTest
class HttpListenerBoundaryTest {
    @Inject
    Instance<HttpServerOptionsCustomizer> customizers;

    @Inject
    Event<ManagementInterface> management;

    private void http(String host) {
        HttpServerOptions options = new HttpServerOptions().setHost(host);
        customizers.forEach(customizer -> customizer.customizeHttpServer(options));
    }

    @Test
    void onlyExplicitIpv4LoopbackIsSupported() {
        assertDoesNotThrow(() -> http("127.0.0.1"));
        for (String host : new String[] {"0.0.0.0", "::", "::1", "127.0.0.2",
                "192.0.2.1", "localhost", "::ffff:127.0.0.1"}) {
            assertThrows(IllegalStateException.class, () -> http(host), host);
        }
    }

    @Test
    void httpsAndHttpDomainSocketsAreUnsupported() {
        assertDoesNotThrow(() -> customizers.forEach(customizer ->
                customizer.customizeHttpsServer(new HttpServerOptions())));
        assertThrows(IllegalStateException.class, () -> customizers.forEach(customizer ->
                customizer.customizeHttpsServer(new HttpServerOptions().setHost("127.0.0.1")
                        .setKeyCertOptions(new PemKeyCertOptions()))));
        assertThrows(IllegalStateException.class, () -> customizers.forEach(customizer ->
                customizer.customizeDomainSocketServer(new HttpServerOptions())));
    }

    @Test
    void managementRouterCannotBeActivated() {
        assertThrows(IllegalStateException.class, () -> management.fire(() -> null));
    }
}
