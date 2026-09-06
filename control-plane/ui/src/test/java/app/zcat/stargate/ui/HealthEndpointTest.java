// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;

import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;

/**
 * Contract tests for the control plane's only HTTP surface (T040): the
 * compose healthcheck. spec.md §Assumptions "No Quarkus dashboard UI yet"
 * — the CP exposes "no HTTP admin UI for this feature beyond a health
 * endpoint used by {@code docker compose} healthchecks", and research.md
 * §"Decision" pins the stub shape: GET /healthz → 200, serves nothing
 * else. Each test pins one clause of that contract; anything extra the
 * module starts serving is a regression toward an undeclared admin
 * surface.
 */
@QuarkusTest
class HealthEndpointTest {

    @TestHTTPResource("/healthz")
    URI healthz;

    @TestHTTPResource("/")
    URI root;

    @Test
    void getHealthzReturns200WithNoBody() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(healthz).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(),
                "the compose healthcheck contract is GET /healthz → 200");
        assertTrue(response.body().isEmpty(),
                "healthcheck response must carry no body, got: "
                        + response.body());
    }

    @Test
    void healthzAnswersGetOnly() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(healthz)
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertNotEquals(200, response.statusCode(),
                "POST /healthz must not succeed — the surface is GET-only");
    }

    @Test
    void rootIsNotServed() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(root).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(404, response.statusCode(),
                "GET / must 404 — the stub serves nothing beyond /healthz");
    }
}
