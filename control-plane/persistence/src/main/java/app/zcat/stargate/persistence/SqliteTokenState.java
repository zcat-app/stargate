// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.persistence;

import java.util.Collection;


import app.zcat.stargate.auth.TokenLoaderContract;
import app.zcat.stargate.persistence.entity.ConfiguredToken;
import jakarta.inject.Singleton;
import jakarta.persistence.EntityManager;
import jakarta.transaction.UserTransaction;

/**
 * Current credential/generation storage (data-model §1.7–1.9). Operational counts
 * join the transaction only after commit; rollback leaves no count or credential.
 * Revoked rows are deleted instead of retaining per-device lifecycle history (III).
 */
@Singleton
public class SqliteTokenState
        implements TokenLoaderContract.ConfiguredTokenStore, TokenLoaderContract.GenerationStore {

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
                .createQuery("SELECT c FROM ConfiguredToken c",
                        ConfiguredToken.class)
                .getResultList()
                .stream()
                .map(row -> new TokenLoaderContract.StoredToken(row.label, row.verifier))
                .toList());
    }

    @Override
    public void begin() {
        openTransaction();
        try {
            // SQLite's deferred read-to-write upgrade can fail with SQLITE_BUSY
            // while the §4 aggregate worker commits. Reserve the single writer
            // before Hibernate reads a credential, preserving §1.7's atomic set.
            em.createNativeQuery("UPDATE token_generation SET generation = generation")
                    .executeUpdate();
        } catch (Exception e) {
            rollback();
            throw new IllegalStateException("token store: cannot reserve the load transaction", e);
        }
    }

    private void openTransaction() {
        try {
            utx.begin();
        } catch (Exception e) {
            throw new IllegalStateException("token store: cannot open the transaction", e);
        }
    }

    @Override
    public void upsert(String label, byte[] verifier) {
        ConfiguredToken row = em.find(ConfiguredToken.class, label);
        if (row == null) {
            row = new ConfiguredToken();
            row.label = label;
        }
        row.verifier = verifier;
        em.merge(row);
    }

    @Override
    public void delete(String label) {
        ConfiguredToken row = em.find(ConfiguredToken.class, label);
        if (row != null) {
            em.remove(row);
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
            // No persistent diagnostic history; the original failure remains authoritative.
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

    @Override
    public TokenLoaderContract.GenerationStore.DeliveryMarker deliveryMarker() {
        return inTransaction(this::readDeliveryMarker);
    }

    @Override
    public boolean prearmDelivery(long generation) {
        requirePositiveGeneration(generation);
        return inTransaction(() -> {
            requireFullSynchronous();
            TokenLoaderContract.GenerationStore.DeliveryMarker current = lockAndReadDeliveryMarker();
            if (current.state() == TokenLoaderContract.GenerationStore.DeliveryState.STALE
                    || (current.state() == TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED
                            && current.generation() != generation)) {
                return false;
            }
            int updated = em.createNativeQuery("UPDATE auth_delivery SET state = 'UNRESOLVED', generation = ?1 "
                    + "WHERE id = 1 AND (state = 'CLEAR' OR (state = 'UNRESOLVED' AND generation = ?1))")
                    .setParameter(1, generation)
                    .executeUpdate();
            return updated == 1;
        });
    }

    @Override
    public boolean acknowledgeDelivery(long generation) {
        requirePositiveGeneration(generation);
        return inTransaction(() -> {
            requireFullSynchronous();
            int updated = em.createNativeQuery("UPDATE auth_delivery SET state = 'CLEAR', generation = 0 "
                    + "WHERE id = 1 AND state = 'UNRESOLVED' AND generation = ?1")
                    .setParameter(1, generation)
                    .executeUpdate();
            return updated == 1;
        });
    }

    @Override
    public boolean recordStaleDelivery(long generation) {
        requirePositiveGeneration(generation);
        return inTransaction(() -> {
            requireFullSynchronous();
            TokenLoaderContract.GenerationStore.DeliveryMarker current = lockAndReadDeliveryMarker();
            if (current.state() == TokenLoaderContract.GenerationStore.DeliveryState.STALE) {
                return current.generation() == generation;
            }
            if (current.state() != TokenLoaderContract.GenerationStore.DeliveryState.UNRESOLVED
                    || current.generation() != generation) {
                return false;
            }
            int updated = em.createNativeQuery("UPDATE auth_delivery SET state = 'STALE' "
                    + "WHERE id = 1 AND state = 'UNRESOLVED' AND generation = ?1")
                    .setParameter(1, generation)
                    .executeUpdate();
            return updated == 1;
        });
    }

    private TokenLoaderContract.GenerationStore.DeliveryMarker lockAndReadDeliveryMarker() {
        int locked = em.createNativeQuery("UPDATE auth_delivery SET id = id WHERE id = 1").executeUpdate();
        if (locked != 1) {
            throw new IllegalStateException("token store: delivery marker singleton is missing");
        }
        return readDeliveryMarker();
    }

    private TokenLoaderContract.GenerationStore.DeliveryMarker readDeliveryMarker() {
        @SuppressWarnings("unchecked")
        java.util.List<Object[]> rows = em.createNativeQuery(
                "SELECT state, generation FROM auth_delivery WHERE id = 1").getResultList();
        if (rows.size() != 1) {
            throw new IllegalStateException("token store: delivery marker singleton is invalid");
        }
        try {
            return new TokenLoaderContract.GenerationStore.DeliveryMarker(
                    TokenLoaderContract.GenerationStore.DeliveryState.valueOf((String) rows.get(0)[0]),
                    ((Number) rows.get(0)[1]).longValue());
        } catch (RuntimeException invalid) {
            throw new IllegalStateException("token store: delivery marker state is invalid", invalid);
        }
    }

    private void requireFullSynchronous() {
        Object value = em.createNativeQuery("PRAGMA synchronous").getSingleResult();
        if (!(value instanceof Number number) || number.intValue() < 2) {
            throw new IllegalStateException("token store: SQLite synchronous mode is weaker than FULL");
        }
    }

    private static void requirePositiveGeneration(long generation) {
        if (generation <= 0) {
            throw new IllegalArgumentException("token delivery generation must be positive");
        }
    }

    // --- transaction plumbing -----------------------------------------------------

    /**
     * Runs a read in its own short transaction. Production reads always land
     * outside the loader's window — on the boot thread BEFORE {@code begin()},
     * and on the sidecar monitor's poll thread via the generation supplier —
     * so there is nothing to join: begin, read, commit. (A future in-window
     * read would fail loud in {@link #openTransaction()}, which is the honest shape.)
     */
    private <T> T inTransaction(java.util.function.Supplier<T> work) {
        openTransaction();
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
