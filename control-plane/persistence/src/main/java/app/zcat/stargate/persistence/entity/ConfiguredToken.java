// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.jspecify.annotations.Nullable;

/**
 * One manual {@code tokens.yaml} token record (data-model.md §1.9; arch §6.6
 * — the {@code configured_tokens} table of {@code V001__init.sql}).
 *
 * <p>Manual tokens carry {@code (label, verifier)} only — no device public
 * key — so they live here, NOT in {@code enrolled_devices} (whose
 * {@code pubkey}/{@code token_hash} are both NOT NULL and which is reserved
 * for the future dashboard-enrollment feature; T092 / sol-review M1, with the
 * nullable-{@code pubkey} alternative explicitly rejected in data-model.md
 * §1.9).
 *
 * <p>{@code label} is the PRIMARY KEY (V001; NOT NULL closes SQLite's TEXT-PK
 * NULL quirk). {@code created_at} is stamped once at first sight, and
 * {@code revoked_at} when the label disappears from the file — both by
 * {@code SqliteTokenState} (T041), the only writer. The {@code verifier} is a
 * 32-byte HMAC-SHA-256 tag under the install-time pepper (§1.5): the pepper
 * itself is never persisted anywhere (§1.6). {@code last_seen_hour} is the
 * ≥1h-bucketed auth-pass column (Principle III); nullable and untouched until
 * a later feature writes it.
 */
@Entity
@Table(name = "configured_tokens")
@SuppressWarnings("NullAway.Init") // columns are framework-initialized by Hibernate, never by this class (parent pom documents the suppression pattern)
public class ConfiguredToken {

    /** The {@code tokens.yaml} label — unique, the audit-log key (§1.1/§4). */
    @Id
    public String label;

    /** 32-byte HMAC-SHA-256 verifier under the pepper (§1.5); verifiers only —
     * never the plaintext, never the pepper (§1.6). */
    @Column(name = "verifier", nullable = false)
    public byte[] verifier;

    /** Unix seconds, stamped when the label is first seen (audit {@code enrolled}). */
    @Column(name = "created_at", nullable = false)
    public long createdAt;

    /** Hour-bucket of last auth pass (Principle III ≥1h); nullable until first use. */
    @Column(name = "last_seen_hour")
    public @Nullable Long lastSeenHour;

    /** Unix seconds, stamped when the label disappears from {@code tokens.yaml}
     * (audit {@code revoked}); nullable — set means soft-deleted. */
    @Column(name = "revoked_at")
    public @Nullable Long revokedAt;

    @Override
    public String toString() {
        // label only — the verifier is secret-derived material (§1.6) and never
        // belongs in a journal line.
        return "ConfiguredToken{label=" + label + ", revoked=" + (revokedAt != null) + "}";
    }
}
