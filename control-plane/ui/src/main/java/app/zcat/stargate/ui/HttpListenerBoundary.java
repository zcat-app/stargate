// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.ui;

import io.quarkus.vertx.http.HttpServerOptionsCustomizer;
import io.quarkus.vertx.http.ManagementInterface;
import io.vertx.core.http.HttpServerOptions;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

/**
 * Deployment Model / foundation-boundaries: configuration precedence cannot
 * turn the Local health stub into a wildcard listener. Quarkus 3.33.1 calls
 * these customizers before deploying its HTTP server, and fires the separate
 * management Router event before publishing that router to server startup.
 */
@ApplicationScoped
public class HttpListenerBoundary implements HttpServerOptionsCustomizer {
    @Override
    public void customizeHttpServer(HttpServerOptions options) {
        // Compare the effective literal; never resolve an operator-supplied name.
        if (!"127.0.0.1".equals(options.getHost())) {
            throw refused();
        }
    }

    @Override
    public void customizeHttpsServer(HttpServerOptions options) {
        // Quarkus 3.33.1 discards the HTTPS placeholder when no key/cert is set.
        if (options.getKeyCertOptions() != null) {
            throw refused();
        }
    }

    @Override
    public void customizeDomainSocketServer(HttpServerOptions options) {
        throw refused();
    }

    void rejectManagement(@Observes ManagementInterface management) {
        // Management bypasses HttpServerOptionsCustomizer, including when main HTTP is off.
        throw refused();
    }

    private static IllegalStateException refused() {
        return new IllegalStateException("CP_HTTP_BOUNDARY");
    }
}
