// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import java.time.Instant;
import java.util.Collection;

import org.jboss.logging.Logger;

import app.zcat.stargate.auth.TokenLoaderContract;
import app.zcat.stargate.persistence.entity.ConfiguredToken;
import jakarta.inject.Singleton;
import jakarta.persistence.EntityManager;
import jakarta.transaction.UserTransaction;

/**
 * The production persistence adapters for the {@code tokens.yaml} loader
 * (T041): both the §1.9 {@code configured_tokens} store (arch §6.6) and the
 * §1.8 {@code token_generation} singleton (arch §6.7) behind the T035a ports
 * the loader (T035) binds. Wired by T041's runtime boot; schema owned by
 * Flyway ({@code V001__init.sql}) — this class writes DML only.
 *
 * <p><strong>Transactional shape (§1.7).</strong> The loader drives one
 * {@code begin()} / {@code commit()} window per successful load; every
 * {@code upsert}/{@code delete} and every §4 audit diff row the loader emits
 * inside that window JOIN the same JTA transaction — the {@code
 * AuditLogService.write} is {@code @Transactional}(REQUIRED), so a
 * {@code rollback()} discards the diff rows together with the store writes
 * (§4 atomicity; pinned by {@code SqliteTokenStateTest}). Reads
 * ({@code storedTokens}, {@code lastGeneration}) run outside the loader's
 * window — on the boot thread BEFORE {@code begin()}, and on the sidecar
 * monitor's poll thread via the generation supplier — so they open their own
 * short transaction when none is active.
 *
 * <p><strong>Row semantics (§1.9).</strong> {@code created_at} stamps once at
 * first sight and survives re-upserts (the pepper-rotation rewrite refreshes
 * only the verifier); {@code delete} is a soft delete — {@code revoked_at}
 * stamped, label removed from {@code storedTokens} (the loader's diff view);
 * a re-appearing label is un-revoked with its original {@code created_at}
 * (the PRIMARY KEY row is updated in place, matching the schema's one-row-
 * per-label contract).
 *
 * <p>{@code token_generation} is the singleton counter row (§1.8): absent row
 * reads as {@code 0} (the DB-wipe state — the loader then proposes 1 and the
 * DP-side reconciliation absorbs the CP-DB-restore case), and {@code record}
 * is an UPDATE-then-INSERT upsert so the singleton stays exactly one row. The
 * two native statements are the entire SQL surface for that table — a dead
 * entity class for a one-column singleton would outgrow its purpose.
 */
@Singleton
public class SqliteTokenState
        implements TokenLoaderContract.ConfiguredTokenStore, TokenLoaderContract.GenerationStore {

    private static final Logger LOG = Logger.getLogger(SqliteTokenState.class);

    private final EntityManager em;
    private final UserTransaction utx;

    SqliteTokenState(EntityManager em, UserTransaction utx) {
        this.em = em;
        this.utx = utx;
    }

    // --- ConfiguredTokenStore (§1.9) ------------------------------------------

    @Override
    public Collection<TokenLoaderContract.StoredToken> storedTokens() {
        return inTransaction(() -> em
                .createQuery("SELECT c FROM ConfiguredToken c WHERE c.revokedAt IS NULL",
                        ConfiguredToken.class)
                .getResultList()
                .stream()
                .map(row -> new TokenLoaderContract.StoredToken(row.label, row.verifier))
                .toList());
    }

    @Override
    public void begin() {
        try {
            utx.begin();
        } catch (Exception e) {
            throw new IllegalStateException("token store: cannot open the load transaction", e);
        }
    }

    @Override
    public void upsert(String label, byte[] verifier) {
        ConfiguredToken row = em.find(ConfiguredToken.class, label);
        if (row == null) {
            row = new ConfiguredToken();
            row.label = label;
            row.createdAt = Instant.now().getEpochSecond();
        }
        row.verifier = verifier;
        row.revokedAt = null; // a re-appearing label is un-revoked (§1.9; the diff logs `enrolled`)
        em.merge(row);
    }

    @Override
    public void delete(String label) {
        ConfiguredToken row = em.find(ConfiguredToken.class, label);
        if (row != null) {
            row.revokedAt = Instant.now().getEpochSecond();
            em.merge(row);
        }
    }

    @Override
    public void commit() {
        try {
            utx.commit();
        } catch (Exception e) {
            throw new IllegalStateException("token store: cannot commit the load transaction", e);
        }
    }

    @Override
    public void rollback() {
        // Best-effort abort of the open transaction (T035a port contract): the
        // loader calls this on its own failure path, where the original failure
        // is the one to propagate. A not-active transaction surfaces as an
        // IllegalStateException from the JTA implementation — that is the
        // "nothing to abort" case, swallowed by design.
        try {
            utx.rollback();
        } catch (Exception e) {
            LOG.warnf("token store: rollback of the load transaction not applied (%s)",
                    e.getClass().getSimpleName());
        }
    }

    // --- GenerationStore (§1.8) --------------------------------------------------

    @Override
    public long lastGeneration() {
        return inTransaction(() -> {
            Object row = em.createNativeQuery("SELECT generation FROM token_generation")
                    .getResultStream()
                    .findFirst()
                    .orElse(null);
            return row == null ? 0L : ((Number) row).longValue();
        });
    }

    @Override
    public void record(long generation) {
        inTransaction(() -> {
            int updated = em
                    .createNativeQuery("UPDATE token_generation SET generation = ?1")
                    .setParameter(1, generation)
                    .executeUpdate();
            if (updated == 0) {
                em.createNativeQuery("INSERT INTO token_generation (generation) VALUES (?1)")
                        .setParameter(1, generation)
                        .executeUpdate();
            }
            return null;
        });
    }

    // --- transaction plumbing -----------------------------------------------------

    /**
     * Runs a read in its own short transaction. Production reads always land
     * outside the loader's window — on the boot thread BEFORE {@code begin()},
     * and on the sidecar monitor's poll thread via the generation supplier —
     * so there is nothing to join: begin, read, commit. (A future in-window
     * read would fail loud in {@link #begin()}, which is the honest shape.)
     */
    private <T> T inTransaction(java.util.function.Supplier<T> work) {
        begin();
        try {
            T result = work.get();
            utx.commit();
            return result;
        } catch (Exception e) {
            rollback();
            throw new IllegalStateException("token store: read transaction failed", e);
        }
    }
}
