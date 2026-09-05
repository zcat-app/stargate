// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import java.time.Instant;

import app.zcat.stargate.auth.TokenLoaderContract;
import app.zcat.stargate.persistence.entity.AuditLog;
import jakarta.inject.Singleton;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;

/**
 * Append-only audit sink (data-model.md §4; arch spec §6.5) — the production
 * adapter for {@link TokenLoaderContract.AuditSink} (T035a seam): one
 * {@code write(action, target, detailJson)} method, the exact shape tasks.md
 * T036 pins. Callers wired by this feature: T035 (the three token actions),
 * T039 ({@code sidecar_healthy}), T074 ({@code sidecar_unhealthy}).
 *
 * <p>Enforced here:
 * <ul>
 *   <li><strong>Fixed five-action vocabulary</strong> (data-model.md §4;
 *       arch spec §5.2 "detail is a fixed-vocabulary token") — an action
 *       outside {@link #ACTION_ENROLLED}, {@link #ACTION_REVOKED},
 *       {@link #ACTION_CONFIG_ERROR}, {@link #ACTION_SIDECAR_HEALTHY} or
 *       {@link #ACTION_SIDECAR_UNHEALTHY} throws before any row is written.
 *       Later vocabulary (e.g. {@code bridge_toggle}) lands via lock-step
 *       amendments, per the V001 §6.5 column comment.</li>
 *   <li><strong>Actor constants, no user identity</strong> (data-model.md
 *       §4: "No user identity is captured because there is no admin UI in
 *       this feature") — the three token actions run as {@code tokens.yaml},
 *       the two sidecar transitions as {@code system}.</li>
 *   <li><strong>Verbatim detail</strong> (data-model.md §1.6; Principle III)
 *       — {@code detailJson} is stored exactly as supplied, never parsed,
 *       re-serialized or enriched; the per-action JSON shapes are the
 *       callers' contracts (§4 table).</li>
 * </ul>
 *
 * <p>{@code write} is {@code @Transactional}(REQUIRED): standalone callers
 * (the sidecar monitors) get one transaction per row; the token loader's
 * store-wrapped load joins its surrounding transaction, matching the T035a
 * contract ("audit rows emitted between the same begin/commit pair").
 */
@Singleton
public class AuditLogService implements TokenLoaderContract.AuditSink {

    /** data-model.md §4 action: new token label encountered during file load. */
    public static final String ACTION_ENROLLED = "enrolled";

    /** data-model.md §4 action: token label removed from the file. */
    public static final String ACTION_REVOKED = "revoked";

    /** data-model.md §4 action: tokens.yaml load failure (kind parse|validation|io). */
    public static final String ACTION_CONFIG_ERROR = "config_error";

    /** data-model.md §4 action: Tor sidecar transition to HEALTHY. */
    public static final String ACTION_SIDECAR_HEALTHY = "sidecar_healthy";

    /** data-model.md §4 action: Tor sidecar transition to UNHEALTHY/STOPPED/CRASHED. */
    public static final String ACTION_SIDECAR_UNHEALTHY = "sidecar_unhealthy";

    private static final String ACTOR_TOKEN_ACTIONS = "tokens.yaml";
    private static final String ACTOR_SIDECAR_TRANSITIONS = "system";

    private final EntityManager em;

    AuditLogService(EntityManager em) {
        this.em = em;
    }

    @Override
    @Transactional
    public void write(String action, String target, String detailJson) {
        AuditLog row = new AuditLog();
        row.ts = Instant.now().getEpochSecond();
        row.actor = actorFor(action);
        row.action = action;
        row.target = target;
        row.detailJson = detailJson;
        em.persist(row);
    }

    private static String actorFor(String action) {
        return switch (action) {
            case ACTION_ENROLLED, ACTION_REVOKED, ACTION_CONFIG_ERROR -> ACTOR_TOKEN_ACTIONS;
            case ACTION_SIDECAR_HEALTHY, ACTION_SIDECAR_UNHEALTHY -> ACTOR_SIDECAR_TRANSITIONS;
            default -> throw new IllegalArgumentException(
                "audit action outside the data-model.md §4 fixed vocabulary: " + action);
        };
    }
}
