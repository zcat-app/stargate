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
 * Finite HTTP contract (T040/T204): bodyless GET /healthz, no admin routes.
 * Compose does not poll the stub; Docker health history remains disabled.
 * Effective listener configuration is covered separately by HttpListenerBoundaryTest.
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
                "the finite health contract is GET /healthz → 200");
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
