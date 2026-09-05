// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence.entity;

import java.time.Instant;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One admin-action audit row (data-model.md §4; arch spec §6.5 — the
 * {@code audit_log} table of {@code V001__init.sql}).
 *
 * <p><strong>Append-only by mechanism</strong> (Constitution Principle III —
 * privacy-preserving by construction): nothing in this module ever UPDATEs or
 * DELETEs a row; the V001 triggers {@code audit_log_no_update},
 * {@code audit_log_no_delete} and {@code audit_log_no_replace} reject every
 * mutation path at the database, including the {@code merge()} /
 * {@code update()} / {@code delete()} mutators inherited from
 * {@link PanacheEntityBase} (pinned by
 * {@code AuditLogServiceTest#panacheMergeAndDeleteAreRejectedByTheAppendOnlyTriggers}).
 * The entity therefore intentionally carries no mutator code of its own —
 * {@code ts} is stamped once by {@code AuditLogService.write}.
 *
 * <p>Privacy shape (Principle III; data-model.md §1.6): {@code actor} is a
 * constant derived from the action — no user identity exists in this feature —
 * and {@code detail_json} / {@code target} carry fixed-vocabulary tokens and
 * labels only, never request data or token bytes. Columns map to V001 exactly;
 * {@code id} uses {@code GenerationType.IDENTITY} (SQLite rowid alias) rather
 * than {@link PanacheEntity}'s inherited strategy-less
 * {@code @GeneratedValue}, whose sequence/table fallback does not fit SQLite.
 */
@Entity
@Table(name = "audit_log")
@SuppressWarnings("NullAway.Init") // columns are framework-initialized by Hibernate, never by this class (parent pom documents the suppression pattern)
public class AuditLog extends PanacheEntityBase {

    /** DB-generated PK (V001: {@code id INTEGER PRIMARY KEY}). */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    /** Write-time unix seconds — admin-action time, not user request time. */
    @Column(name = "ts", nullable = false)
    public long ts;

    /** {@code "tokens.yaml"} or {@code "system"} per data-model.md §4. */
    @Column(name = "actor", nullable = false)
    public String actor;

    /** One of the five fixed-vocabulary actions (data-model.md §4). */
    @Column(name = "action", nullable = false)
    public String action;

    /** Affected entity: the token label, {@code tor}, or {@code tokens.yaml}. */
    @Column(name = "target")
    public String target;

    /** Fixed-vocabulary JSON token, stored verbatim (arch spec §5.2). */
    @Column(name = "detail_json")
    public String detailJson;

    @Override
    public String toString() {
        return "AuditLog{id=" + id + ", ts=" + Instant.ofEpochSecond(ts) + ", actor=" + actor
            + ", action=" + action + ", target=" + target + "}";
    }
}
