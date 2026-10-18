// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.auth;

import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

/**
 * Seam contract for the {@code tokens.yaml} loader (T035's
 * {@code TokenLoader}), authored test-first by T035a so the loader's
 * in-memory fakes are compilable before the implementation lands
 * (Constitution Principle VII — authentication is a mandatory test-first
 * category; see T035a §Analysis for why a seam-only main artifact is the
 * compilable form of that requirement under the {@code mvnw} gate).
 *
 * <p>This file declares PORTS ONLY — zero behavior. Every member cites the
 * governing section of {@code specs/001-tor-route/data-model.md} (T092
 * amendment authoritative). T035 implements the loader against these ports;
 * T036's {@code AuditLogService}, the Panache {@code configured_tokens}
 * repository, and T038's gRPC client are the production adapters.
 *
 * <p>The pinned loader surface (T035a §Analysis): one constructor whose
 * parameter type list is exactly {@code Path, byte[], ConfiguredTokenStore,
 * GenerationStore, AuditSink, ReloadChannel, VerifierMinter} (order
 * irrelevant; package-private allowed — production wiring reads the FR-017
 * fixed path {@code /etc/stargate/tokens.yaml} and the §1.7 pepper file and
 * injects both, keeping the loader path/pepper-agnostic), plus one no-arg
 * method named {@code load}.
 */
public final class TokenLoaderContract {

    private TokenLoaderContract() {
    }

    /**
     * Persistence port for the manual-YAML token records (data-model.md
     * §1.9 — {@code configured_tokens}; NOT {@code enrolled_devices},
     * which is reserved for future dashboard enrollment).
     *
     * <p>Transactions: every successful load writes the FULL current
     * record set (§1.7 "writes the new verifiers" — same-label rewrites
     * keep stored verifiers fresh, which is what a pepper rotation §1.7
     * relies on) inside {@link #begin()} / {@link #commit()}, so a
     * concurrent reader never sees interleaved partial state. The label
     * diff's {@code enrolled}/{@code revoked} counts are NOT part of this
     * transaction: T187 emits them through {@link AuditSink} only after the
     * data plane acknowledges the candidate's exact generation.
     *
     * <p>Timestamps are store-side: {@code created_at} is stamped when a
     * label is first seen, {@code revoked_at} when {@link #delete} is
     * called (§1.9 column table) — the loader carries no clock.
     */
    public interface ConfiguredTokenStore {

        /** Current rows, for the label diff against the new file (§1.9). */
        Collection<StoredToken> storedTokens();

        /** View over {@link #storedTokens()} used by the label diff. */
        default Collection<String> storedLabels() {
            return storedTokens().stream().map(StoredToken::label).toList();
        }

        /** Opens the atomic write for one load (§1.6 partial-state rule). */
        void begin();

        /** Inserts-or-updates one record; the row shape is §1.9. */
        void upsert(String label, byte[] verifier);

        /**
         * Records the label's removal (audit action {@code revoked};
         * §1.9 {@code revoked_at} — soft or hard delete is the store's
         * concern).
         */
        void delete(String label);

        /** Commits the load's write (§1.7 write order: store, then
         *  generation, then ReloadTokens). */
        void commit();

        /** Best-effort abort of an open transaction; unused on the
         *  success paths. */
        default void rollback() {
        }
    }

    /**
     * Persisted monotonic generation counter port (data-model.md §1.8 —
     * the {@code token_generation} singleton). {@link #lastGeneration()}
     * returns {@code 0} when no record exists yet (§1.8 DB-wipe row); the
     * proposal for a load is always {@code lastGeneration() + 1}.
     */
    public interface GenerationStore {

        /** The only durable token-delivery states; this is current state, not a history. */
        enum DeliveryState {
            CLEAR,
            UNRESOLVED,
            STALE
        }

        /** Current persisted gate and its candidate generation (zero only for CLEAR). */
        record DeliveryMarker(DeliveryState state, long generation) {
            public DeliveryMarker {
                if (state == null || generation < 0
                        || (state == DeliveryState.CLEAR && generation != 0)
                        || (state != DeliveryState.CLEAR && generation == 0)) {
                    throw new IllegalArgumentException("invalid token delivery marker");
                }
            }
        }

        /** Last-assigned generation; {@code 0} = none (§1.8). */
        long lastGeneration();

        /** Persists the generation assigned to the load just written. */
        void record(long generation);

        /** Reads the one durable delivery marker; storage/shape failures propagate. */
        DeliveryMarker deliveryMarker();

        /**
         * Durably arms this complete candidate before an RPC. Returns false
         * when an absorbing STALE or a different unresolved generation blocks it.
         */
        boolean prearmDelivery(long generation);

        /** Clears only an UNRESOLVED marker for this exact acknowledged generation. */
        boolean acknowledgeDelivery(long generation);

        /** Records STALE only from the matching UNRESOLVED marker; STALE is absorbing. */
        boolean recordStaleDelivery(long generation);
    }

    /**
     * Operational-count port (data-model §4). The legacy argument shape is kept
     * for source compatibility: production ignores target/detail immediately and
     * retains only fixed-category counts after transaction commit and hour closure.
     * Neither these arguments nor exceptions authorize per-event logging (III).
     */
    public interface AuditSink {
        void write(String action, String target, String detailJson);
    }

    /**
     * One persisted manual-token row (data-model.md §1.9): the current
     * configuration label plus its 32-byte verifier under the install-time pepper (§1.5).
     */
    public record StoredToken(String label, byte[] verifier) {
    }

    /**
     * Result of one {@code ReloadTokens} push (contracts/control-grpc.md
     * §ReloadTokens, T092 reconciliation fields). {@code stale=true}
     * means the data plane rejected the proposal as
     * {@code APPLY_STATUS_STALE_GENERATION} and
     * {@code currentGeneration} carries the DP's current generation (the
     * CP's retry with {@code current + 1} is T035 note (c) — wired above
     * this port, out of T035a's scope).
     */
    public record PushResult(boolean stale, long currentGeneration) {
    }

    /**
     * Inter-plane push port for a new token generation
     * (contracts/control-grpc.md §ReloadTokens). The production adapter
     * is T038's gRPC client; the loader calls it once per successful
     * load, AFTER the store commit and the generation record (§1.7
     * write order). Verifiers only — never plaintext, never the pepper,
     * never labels (§1.6; labels are not in the message by design).
     */
    public interface ReloadChannel {

        /** Pushes {@code generation} with its complete verifier set. */
        PushResult push(long generation, List<byte[]> verifiers);

        /**
         * T187 (Constitution II failure table): runs {@code onAcknowledged} at
         * most once, when exactly {@code generation} is later acknowledged by
         * the data plane after {@link #push} returned pending. A stale reply
         * or a closed channel drops it. The default never runs it: an adapter
         * without asynchronous redelivery can only undercount, never report an
         * unacknowledged revocation as applied.
         */
        default void whenAcknowledged(long generation, Runnable onAcknowledged) {
        }
    }

    /**
     * Verifier-minting port (data-model.md §1.5): the 32-byte
     * {@code HMAC-SHA-256(pepper, tokenUtf8)} tag. Pure — implementations
     * MUST NOT clear or retain the input buffer: the mint-then-clear step
     * of data-model.md §1.1 ("the byte[] cleared to zero before the next
     * file entry is processed") is the CALLER's (the loader's) role, which
     * is what makes the buffer-zeroing assertion in TokenLoaderTest
     * non-tautological (T093 narrowed the erasure claim to this mutable
     * buffer; SnakeYAML String values are NOT claimed erased).
     */
    public interface VerifierMinter {

        /** Mints the verifier for one plaintext token (UTF-8 bytes). */
        byte[] mint(byte[] tokenUtf8);
    }
}
