// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.ui;

import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

/**
 * The control plane's bodyless GET /healthz stub (T040/T204), restricted to
 * IPv4 loopback by {@link HttpListenerBoundary}. No admin UI lands in this
 * feature (spec.md §Assumptions "No Quarkus dashboard UI yet").
 *
 * <p>Compose healthchecks are disabled under Constitution III; neither
 * Compose nor the installer polls this endpoint. It reports only process
 * liveness, not Tor readiness, authenticated IPC or forwarding success.
 * The handler reads no payload, headers or mutable state.</p>
 *
 * <p>Quarkus 3.40 has no declarative route annotation for plain
 * vertx-http; the documented registration mechanism is observing the
 * {@link Router} before the server accepts traffic. The route is bound to
 * GET only, so any other method or any other path 404s by default.</p>
 */
@ApplicationScoped
public class HealthEndpoint {

    void init(@Observes Router router) {
        router.route(HttpMethod.GET, "/healthz").handler(HealthEndpoint::health);
    }

    private static void health(RoutingContext context) {
        context.response().setStatusCode(200).end();
    }
}
