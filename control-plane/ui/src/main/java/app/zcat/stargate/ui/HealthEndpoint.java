// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.ui;

import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

/**
 * The control plane's single HTTP surface: the Compose healthcheck
 * (T040). spec.md §Assumptions "No Quarkus dashboard UI yet" — no admin
 * UI lands in this feature, and research.md §"Decision" (headless control
 * plane) pins the stub to "GET /healthz → 200 and serves nothing else".
 *
 * <p>The response is a fixed 200 with no body: the consumer is the Compose
 * healthcheck (control-plane/Dockerfile; the compose {@code healthcheck:}
 * block and the bounded wait in {@code scripts/stargate init} poll this
 * path), which needs a status code, not content. Constitution Principle II
 * keeps request bytes off this plane — the route reads nothing (no
 * headers, no payload) and holds no state, so it discloses nothing beyond
 * liveness on the compose-internal network.</p>
 *
 * <p>Quarkus 3.33 has no declarative route annotation for plain
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
