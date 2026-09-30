// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.auth;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.jspecify.annotations.Nullable;
import org.yaml.snakeyaml.Yaml;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Unit tests for the {@code tokens.yaml} loader (T035's {@code TokenLoader})
 * — diff logic, validation, and failure semantics (T035a; Constitution
 * Principle VII — {@code tokens.yaml} is the operator-facing config surface
 * and the diff-derived audit log is operator-visible).
 *
 * <p>Authoritative contract: {@code data-model.md} §1.1/§1.5/§1.6/§1.8/§1.9/§4
 * and {@code spec.md} FR-017/FR-018 as amended by T092 (the pre-amendment
 * ticket body's Argon2id/enrolled_devices/empty-push-on-missing wording is
 * retired — see T035a §Analysis for the five resolved contradictions).
 *
 * <p>Three layers, per the T068a tests-first precedent (round-1 APPROVE):
 * <ol>
 *   <li><b>Oracle layer</b> — pins the §4 audit-row vocabulary and the
 *       enrolled/revoked diff algebra as executable reference expectations.
 *       Green TODAY; extends (never duplicates) T093, which pinned the mint,
 *       the narrowed erasure claim, and the failure decision table.</li>
 *   <li><b>Loader-driving layer</b> — every behavioral case below drives the
 *       REAL {@code TokenLoader} through in-memory fakes. Until T035 lands
 *       the class, these cases SELF-SKIP with a loud marker (a compiling test
 *       referencing an absent class is a hard {@code mvnw} FAIL on this host,
 *       so T012a's compile-red pattern is unavailable here; a JUnit
 *       assumption = skip keeps verify green). When T035 lands the class the
 *       skips lift automatically and every assertion bites inside T035's own
 *       verify run. A class that exists but does NOT expose the pinned
 *       surface is a hard FAIL — that conformance gate is the binding.</li>
 *   <li><b>Fakes</b> — in-memory, no SQLite, no DI runtime: a
 *       {@link TokenLoaderContract.ConfiguredTokenStore} fake recording the
 *       ordered call journal, a capturing {@link TokenLoaderContract.AuditSink},
 *       a capturing {@link TokenLoaderContract.ReloadChannel}, a
 *       {@link TokenLoaderContract.VerifierMinter} double that records the
 *       {@code byte[]} references it receives (real HMAC mint, NO internal
 *       clear — the mint-then-clear step of §1.1 is the LOADER's role, which
 *       is what makes the zeroing assertion non-tautological), and a
 *       {@link TokenLoaderContract.GenerationStore} fake. The shared journal
 *       makes the cross-fake ordering assertions of case (e) possible.</li>
 * </ol>
 *
 * <p>Pinned surface (the ONLY assumption about T035's design — everything
 * else is observable through the fakes): one constructor whose parameter type
 * list is exactly {@code Path, byte[], ConfiguredTokenStore, GenerationStore,
 * AuditSink, ReloadChannel, VerifierMinter} (order irrelevant), plus one
 * no-arg method named {@code load}. Per T035a §Out-of-scope, T035 must not
 * edit this file — a surface that genuinely cannot host T035's design is a
 * refine escalation, not a test edit.
 *
 * <p>Test plaintexts reuse the repo's documented example tokens (T093's
 * gitleaks practice — the values are fixtures, not credentials).
 */
class TokenLoaderTest {

    // --- fixtures -----------------------------------------------------------

    private static final String LABEL_A = "alice-laptop";
    private static final String LABEL_B = "alice-desktop";
    private static final String LABEL_C = "carol-phone";
    private static final String LABEL_D = "bob-tablet";
    private static final String LABEL_BAD_SHORT = "bad-short";
    private static final String LABEL_BAD_NONHEX = "bad-nonhex";

    private static final String TOKEN_A = "9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f";
    private static final String TOKEN_B = "1a2b3c4d5e6f70819a8b7c6d5e4f3a2b";
    // TOKEN_C reuses T034's already-allowlisted fixture value (.gitleaks.toml);
    // the malformed fixtures are deliberately non-hex / truncated, so they are
    // not deployable secrets in any sense (T093's gitleaks practice).
    private static final String TOKEN_C = "0123456789abcdef0123456789abcdef";
    private static final String TOKEN_SHORT = "9f2c3a14";
    private static final String TOKEN_NONHEX = "wxyzwxyzwxyzwxyzwxyzwxyzwxyzwxyz";

    private static final List<String> ALL_PLAINTEXTS = List.of(
        TOKEN_A, TOKEN_B, TOKEN_C, TOKEN_SHORT, TOKEN_NONHEX);

    /** §1.7: 32 random bytes; injected, never read from the keys volume here. */
    private static final byte[] PEPPER = repeat((byte) 0x37, 32);

    /** Pre-amendment store rows carry these to prove a load rewrites them. */
    private static final byte[] STALE_VERIFIER = repeat((byte) 0x11, 32);

    private static final String LOADER_FQN = "app.zcat.stargate.auth.TokenLoader";

    private static final String SKIP_UNTIL_T035 =
        "T035 not landed: " + LOADER_FQN + " is absent — loader-driving cases "
        + "self-skip (Constitution Principle VII tests-first; T068a precedent). "
        + "The skips lift the moment T035 lands the pinned surface.";

    // --- oracle layer (green today; no skip) --------------------------------

    /**
     * §4 pins the audit-row vocabulary as a FIXED enum — the loader's
     * {@code detail_json} must parse to exactly these shapes. detailOf
     * equality is parsed-map equality, so the oracle pins the
     * fixed-vocabulary VALUES and their key sets; byte-level drift (key
     * order, whitespace) is deliberately not load-bearing.
     */
    @Test
    void auditRowVocabularyIsPinned() {
        assertEquals(mapOf("source", "tokens.yaml", "generation", 3),
            detailOf("{\"source\":\"tokens.yaml\",\"generation\":3}"),
            "§4 enrolled/revoked detail_json shape");
        assertEquals(mapOf("kind", "parse", "line", 4),
            detailOf("{\"kind\":\"parse\",\"line\":4}"),
            "§4 config_error kind=parse carries the parser-reported line");
        assertEquals(mapOf("kind", "validation", "line", 3),
            detailOf("{\"kind\":\"validation\",\"line\":3}"),
            "§4: validation rows carry the parser-reported line; the offending LABEL "
                + "is a warning-log surface (§1.1), never an audit detail key");
        Map<String, Object> io = detailOf("{\"kind\":\"io\",\"line\":null}");
        assertEquals("io", io.get("kind"), "§4 config_error kind=io");
        assertTrue(io.containsKey("line") && io.get("line") == null,
            "§4: io rows carry line=null (no parser context)");
        // The §4 action literals themselves (enrolled/revoked/config_error) are
        // exercised non-tautologically by the loader-driving cases, which filter
        // rows(h, action) against REAL captured loader output.
    }

    /**
     * The diff algebra the loader's audit rows must implement (§4: enrolled
     * = labels new this load, revoked = labels present in the previous
     * store set but absent now). These helpers are the expectation model the
     * loader-driving cases assert against.
     */
    @Test
    void diffOracleComputesEnrolledAndRevokedSets() {
        var previous = Set.of(LABEL_A, LABEL_B);
        var current = Set.of(LABEL_B, LABEL_C);
        assertEquals(Set.of(LABEL_C), enrolledLabels(previous, current), "mixed: the added label");
        assertEquals(Set.of(LABEL_A), revokedLabels(previous, current), "mixed: the removed label");

        assertEquals(current, enrolledLabels(Set.of(), current), "first load: everything enrolled");
        assertEquals(Set.of(), revokedLabels(Set.of(), current), "first load: nothing revoked");

        assertEquals(previous, revokedLabels(previous, Set.of()), "tokens: []: revoke-all algebra");
        assertEquals(Set.of(), enrolledLabels(previous, Set.of()));

        assertEquals(Set.of(), enrolledLabels(previous, previous), "unchanged: no diff either way");
        assertEquals(Set.of(), revokedLabels(previous, previous));
    }

    // --- loader-driving layer (self-skips until T035 lands) -----------------

    /**
     * Body case (a) + amendment (a)/(d): a first load with an empty store
     * and N valid tokens emits N {@code enrolled} rows (one per label,
     * §4 detail shape, generation 1), writes the full record set into the
     * store transactionally (§1.7), proposes generation 1 (§1.8), and
     * issues exactly ONE push whose verifiers equal
     * {@code HMAC-SHA-256(pepper, tokenUtf8)} (§1.5).
     */
    @Test
    void firstLoadEnrollsEveryLabelAndPushesGeneration1(@TempDir Path dir) throws Throwable {
        Harness h = runLoad(writeTokens(dir, tokensFile(LABEL_A, TOKEN_A, LABEL_B, TOKEN_B)),
            Map.of(), 0L);

        assertEquals(List.of(), rows(h, "revoked"), "first load revokes nothing");
        assertEquals(List.of(), rows(h, "config_error"), "first load has no failures");
        assertEquals(Set.of(LABEL_A, LABEL_B), labelsOf(rows(h, "enrolled")),
            "one enrolled row per new label");
        for (CapturedAudit r : rows(h, "enrolled")) {
            assertEquals(mapOf("source", "tokens.yaml", "generation", 1),
                detailOf(r.detailJson()), "enrolled row detail for " + r.target());
        }

        assertEquals(Set.of(LABEL_A, LABEL_B), Set.copyOf(h.store.upsertedLabels),
            "§1.7: the full current record set is written");
        assertVerifiersUpserted(h, Map.of(LABEL_A, TOKEN_A, LABEL_B, TOKEN_B));
        assertEquals(List.of(), h.store.deletedLabels, "nothing deleted on first load");
        assertEquals(1L, h.gens.recordedValue, "§1.8: fresh store proposes 0 + 1");

        assertEquals(1, h.reload.pushes.size(), "exactly one ReloadTokens push");
        CapturedPush push = h.reload.pushes.get(0);
        assertEquals(1L, push.generation(), "push carries the proposed generation");
        assertEquals(Set.of(hex(expectedVerifier(TOKEN_A)), hex(expectedVerifier(TOKEN_B))),
            hexSet(push.verifiers()),
            "§1.5: pushed verifiers are the HMAC tags under the injected pepper");

        assertTransactionalWrite(h);
        assertPushIsLast(h);
        assertNoPlaintextEscapes(h);
    }

    /**
     * Body case (h), narrowed per §1.1/T092: every {@code byte[]} the loader
     * hands to the minter is all-zero after the load (the loader's
     * mint-then-clear step). The fake minter does NOT clear — a loader that
     * omits the clear fails here. Each handed buffer holds the UTF-8 bytes
     * of the hex plaintext at mint time (§1.5 message). NO assertion about
     * SnakeYAML-materialized Strings (the deliberately narrow claim).
     */
    @Test
    void firstLoadLeavesEveryMinterBufferZeroed(@TempDir Path dir) throws Throwable {
        Harness h = runLoad(writeTokens(dir, tokensFile(LABEL_A, TOKEN_A, LABEL_B, TOKEN_B)),
            Map.of(), 0L);

        assertEquals(2, h.minter.minted.size(), "one mint per token record");
        assertEquals(Set.of(TOKEN_A, TOKEN_B), h.minter.minted.stream()
                .map(m -> new String(m.plaintextCopy(), UTF_8)).collect(Collectors.toSet()),
            "§1.5: the mint message is the 32-char lowercase-hex plaintext");
        for (Minted m : h.minter.minted) {
            assertArrayEquals(new byte[m.bufferRef().length], m.bufferRef(),
                "§1.1: the mutable byte[] HMAC input buffer must be zeroed by the "
                    + "loader's mint-then-clear step before the next entry");
        }
        assertNoPlaintextEscapes(h);
    }

    /**
     * Body case (b), amended semantics: an unchanged label set emits ZERO
     * diff rows, but the store is still rewritten with fresh verifiers
     * (§1.7 "writes the new verifiers" — same-label rewrites are what a
     * pepper rotation §1.7 relies on), the generation still bumps, and the
     * push still happens (§1.8: every successful parse).
     */
    @Test
    void unchangedReloadEmitsNoDiffRowsButBumpsGenerationAndPushes(@TempDir Path dir)
            throws Throwable {
        Harness h = runLoad(writeTokens(dir, tokensFile(LABEL_A, TOKEN_A, LABEL_B, TOKEN_B)),
            Map.of(LABEL_A, STALE_VERIFIER, LABEL_B, STALE_VERIFIER), 7L);

        assertEquals(List.of(), rows(h, "enrolled"), "unchanged labels: no enrolled rows");
        assertEquals(List.of(), rows(h, "revoked"), "unchanged labels: no revoked rows");
        assertEquals(List.of(), rows(h, "config_error"), "no failures");

        assertEquals(Set.of(LABEL_A, LABEL_B), Set.copyOf(h.store.upsertedLabels),
            "§1.7: verifiers are rewritten even for unchanged labels");
        assertVerifiersUpserted(h, Map.of(LABEL_A, TOKEN_A, LABEL_B, TOKEN_B));
        assertEquals(List.of(), h.store.deletedLabels);
        assertEquals(8L, h.gens.recordedValue, "§1.8: proposes persisted 7 + 1");

        assertEquals(1, h.reload.pushes.size());
        assertEquals(8L, h.reload.pushes.get(0).generation());

        assertTransactionalWrite(h);
        assertPushIsLast(h);
        assertNoPlaintextEscapes(h);
    }

    /**
     * Body case (c): one label removed → exactly one {@code revoked} row for
     * that label; the store deletes exactly that label.
     */
    @Test
    void removedLabelRevokesExactlyThatLabel(@TempDir Path dir) throws Throwable {
        Harness h = runLoad(writeTokens(dir, tokensFile(LABEL_A, TOKEN_A)),
            Map.of(LABEL_A, STALE_VERIFIER, LABEL_B, STALE_VERIFIER), 7L);

        assertEquals(Set.of(LABEL_B), labelsOf(rows(h, "revoked")),
            "exactly one revoked row, for the removed label");
        for (CapturedAudit r : rows(h, "revoked")) {
            assertEquals(mapOf("source", "tokens.yaml", "generation", 8),
                detailOf(r.detailJson()), "revoked row detail for " + r.target());
        }
        assertEquals(List.of(), rows(h, "enrolled"));
        assertEquals(List.of(), rows(h, "config_error"));

        assertEquals(List.of(LABEL_B), h.store.deletedLabels);
        assertEquals(Set.of(LABEL_A), Set.copyOf(h.store.upsertedLabels));
        assertEquals(8L, h.gens.recordedValue);
        assertEquals(1, h.reload.pushes.size());
        assertEquals(Set.of(hex(expectedVerifier(TOKEN_A))), hexSet(h.reload.pushes.get(0).verifiers()),
            "the pushed set no longer contains the removed label's verifier");

        assertTransactionalWrite(h);
        assertPushIsLast(h);
        assertNoPlaintextEscapes(h);
    }

    /**
     * Body case (d): one new label → exactly one {@code enrolled} row; the
     * full current set (old label rewritten + new label) lands in the store.
     */
    @Test
    void addedLabelEnrollsExactlyThatLabel(@TempDir Path dir) throws Throwable {
        Harness h = runLoad(writeTokens(dir, tokensFile(LABEL_A, TOKEN_A, LABEL_C, TOKEN_C)),
            Map.of(LABEL_A, STALE_VERIFIER), 7L);

        assertEquals(Set.of(LABEL_C), labelsOf(rows(h, "enrolled")),
            "exactly one enrolled row, for the added label");
        assertEquals(List.of(), rows(h, "revoked"));
        assertEquals(List.of(), rows(h, "config_error"));

        assertEquals(Set.of(LABEL_A, LABEL_C), Set.copyOf(h.store.upsertedLabels),
            "§1.7 full-set write: the retained label is rewritten too");
        assertEquals(List.of(), h.store.deletedLabels);
        assertEquals(8L, h.gens.recordedValue);
        assertEquals(1, h.reload.pushes.size());
        assertEquals(Set.of(hex(expectedVerifier(TOKEN_A)), hex(expectedVerifier(TOKEN_C))),
            hexSet(h.reload.pushes.get(0).verifiers()));

        assertTransactionalWrite(h);
        assertPushIsLast(h);
        assertNoPlaintextEscapes(h);
    }

    /**
     * Body case (e): mixed add+remove → every store mutation inside ONE
     * begin/commit pair (no interleaved partial state visible to a
     * concurrent reader), the push after the store (§1.7 write order:
     * store → generation → ReloadTokens), and both diff rows only after
     * the acknowledged push (T187). The method name is kept for T035a
     * traceability; the rows are no longer inside the transaction.
     */
    @Test
    void mixedAddRemoveEmitsBothRowsInsideOneStoreTransaction(@TempDir Path dir) throws Throwable {
        Harness h = runLoad(writeTokens(dir, tokensFile(LABEL_B, TOKEN_B, LABEL_C, TOKEN_C)),
            Map.of(LABEL_A, STALE_VERIFIER, LABEL_B, STALE_VERIFIER, LABEL_D, STALE_VERIFIER), 7L);

        assertEquals(Set.of(LABEL_C), labelsOf(rows(h, "enrolled")));
        assertEquals(Set.of(LABEL_A, LABEL_D), labelsOf(rows(h, "revoked")));
        assertEquals(List.of(), rows(h, "config_error"));

        assertEquals(Set.of(LABEL_B, LABEL_C), Set.copyOf(h.store.upsertedLabels));
        assertEquals(Set.of(LABEL_A, LABEL_D), Set.copyOf(h.store.deletedLabels));
        assertEquals(8L, h.gens.recordedValue);
        assertEquals(1, h.reload.pushes.size());
        assertEquals(Set.of(hex(expectedVerifier(TOKEN_B)), hex(expectedVerifier(TOKEN_C))),
            hexSet(h.reload.pushes.get(0).verifiers()));

        assertTransactionalWrite(h);
        assertPushIsLast(h);
        assertNoPlaintextEscapes(h);
    }

    /**
     * Body case (f), §1.1 partial-failure tolerance: malformed token entries
     * (wrong length, non-hex) each yield one {@code config_error} row in the
     * §4 shape — {@code target="tokens.yaml"}, {@code kind="validation"},
     * detail keys ⊆ {kind, line} (the offending LABEL is a §1.1 warning-log
     * surface, T041's layer — never an audit detail key); the offending
     * records are skipped and the valid record still enrolls, persists, and
     * pushes.
     */
    @Test
    void malformedEntryIsRejectedWithValidationRowAndValidRecordsContinue(@TempDir Path dir)
            throws Throwable {
        String yaml = "tokens:\n"
            + "  - label: " + LABEL_A + "\n"
            + "    token: " + TOKEN_A + "\n"
            + "  - label: " + LABEL_BAD_SHORT + "\n"
            + "    token: " + TOKEN_SHORT + "\n"
            + "  - label: " + LABEL_BAD_NONHEX + "\n"
            + "    token: " + TOKEN_NONHEX + "\n";
        Harness h = runLoad(writeTokens(dir, yaml), Map.of(), 7L);

        List<CapturedAudit> failures = rows(h, "config_error");
        assertEquals(2, failures.size(), "one validation row per malformed record");
        for (CapturedAudit r : failures) {
            assertEquals("tokens.yaml", r.target(),
                "§4: the config_error target is the file constant, not the label");
            Map<String, Object> detail = detailOf(r.detailJson());
            assertEquals("validation", detail.get("kind"), "§4 kind for " + r.target());
            assertTrue(detail.keySet().stream()
                    .allMatch(k -> k.equals("kind") || k.equals("line")),
                "§4 fixed vocabulary — detail keys ⊆ {kind, line}, got: " + detail);
        }
        assertEquals(Set.of(LABEL_A), labelsOf(rows(h, "enrolled")),
            "the valid record still enrolls (partial-failure tolerance)");
        assertEquals(List.of(), rows(h, "revoked"));

        assertEquals(Set.of(LABEL_A), Set.copyOf(h.store.upsertedLabels));
        assertEquals(8L, h.gens.recordedValue);
        assertEquals(1, h.reload.pushes.size());
        assertEquals(Set.of(hex(expectedVerifier(TOKEN_A))), hexSet(h.reload.pushes.get(0).verifiers()),
            "only the valid record's verifier is pushed");

        assertTransactionalWrite(h);
        assertPushIsLast(h);
        assertNoPlaintextEscapes(h);
    }

    /**
     * Body case (g) + §1.6: unparseable YAML → exactly one {@code config_error}
     * row with {@code kind="parse"} and a parser-reported line number ≥ 1;
     * NO store write, NO generation record, NO push (the DP keeps its
     * last-known list, Principle II); the loader MUST NOT throw.
     */
    @Test
    void unparseableYamlEmitsParseErrorRowAndDoesNotPush(@TempDir Path dir) throws Throwable {
        Harness h = runLoad(writeTokens(dir, "tokens: [unclosed\n"), Map.of(), 7L);

        List<CapturedAudit> failures = rows(h, "config_error");
        assertEquals(1, failures.size(), "exactly one parse-failure row");
        assertEquals("tokens.yaml", failures.get(0).target(),
            "§4: the config_error target is the file constant");
        Map<String, Object> detail = detailOf(failures.get(0).detailJson());
        assertEquals("parse", detail.get("kind"), "§4 kind=parse for YAML syntax errors");
        Object line = detail.get("line");
        assertTrue(line instanceof Integer i && i >= 1,
            "§4: parse rows carry the parser-reported line number, got: " + line);

        assertEquals(List.of(), rows(h, "enrolled"));
        assertEquals(List.of(), rows(h, "revoked"));
        assertUntouchedExceptAudit(h);
        assertFalse(h.gens.recordedSet, "no successful parse → no generation record (§1.7)");
    }

    /**
     * Body case (i), amended per §1.6/§4/FR-018: a missing file is the
     * legitimate first-boot state — NO audit row at all, NO
     * {@code ReloadTokens} call (the DP keeps its last-known list), no store
     * or generation writes, and the loader MUST NOT throw (the CP comes up
     * healthy; Principle II keeps the DP serving).
     */
    @Test
    void missingFileIsFirstBootNoAuditNoPushNoThrow(@TempDir Path dir) throws Throwable {
        Harness h = runLoad(dir.resolve("tokens.yaml"), Map.of(), 7L);

        assertEquals(List.of(), h.audit.rows, "§4 first-boot exemption: no audit row at all");
        assertUntouchedExceptAudit(h);
        assertFalse(h.gens.recordedSet);
    }

    /**
     * Body case (j), §1.6/§4: an unreadable file (e.g. wrong group/mode on
     * the operator mount) → exactly one {@code config_error} row with
     * {@code kind="io"} and {@code line} null-or-absent — the distinct
     * operator signal for a permissions misconfiguration — and the same
     * no-push/no-write/no-throw shape as the missing-file case.
     */
    @Test
    void unreadableFileEmitsIoRowWithoutLineAndDoesNotPush(@TempDir Path dir) throws Throwable {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
            "POSIX permission bits unavailable — environmental skip, not contractual");
        Path file = writeTokens(dir, tokensFile(LABEL_A, TOKEN_A));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("---------"));
        assumeTrue(!Files.isReadable(file),
            "running privileged (root reads anyway) — environmental skip, not contractual");

        Harness h = runLoad(file, Map.of(), 7L);

        List<CapturedAudit> failures = rows(h, "config_error");
        assertEquals(1, failures.size(), "exactly one io row");
        assertEquals("tokens.yaml", failures.get(0).target(),
            "§4: the config_error target is the file constant");
        Map<String, Object> detail = detailOf(failures.get(0).detailJson());
        assertEquals("io", detail.get("kind"), "§4: io distinguishes misconfiguration from missing");
        assertTrue(!detail.containsKey("line") || detail.get("line") == null,
            "§4: io rows carry line=null (no parser context)");
        assertEquals(List.of(), rows(h, "enrolled"));
        assertEquals(List.of(), rows(h, "revoked"));
        assertUntouchedExceptAudit(h);
        assertFalse(h.gens.recordedSet);
    }

    /**
     * Amendment note (c), §1.6: a successfully-parsed explicit
     * {@code tokens: []} is the SOLE revoke-all path — one {@code revoked}
     * row per previously-stored label, all rows deleted, generation bumped,
     * and ONE push carrying an EMPTY verifier set (after which the DP
     * returns AUTH_REQUIRED on all requests). Every failure mode above is
     * deliberately distinct from this.
     */
    @Test
    void explicitEmptyListIsRevokeAll(@TempDir Path dir) throws Throwable {
        Harness h = runLoad(writeTokens(dir, "tokens: []\n"),
            Map.of(LABEL_A, STALE_VERIFIER, LABEL_B, STALE_VERIFIER), 7L);

        assertEquals(Set.of(LABEL_A, LABEL_B), labelsOf(rows(h, "revoked")),
            "revoke-all: one revoked row per previously-stored label");
        for (CapturedAudit r : rows(h, "revoked")) {
            assertEquals(mapOf("source", "tokens.yaml", "generation", 8),
                detailOf(r.detailJson()), "revoked row detail for " + r.target());
        }
        assertEquals(List.of(), rows(h, "enrolled"));
        assertEquals(List.of(), rows(h, "config_error"),
            "an explicit empty list is a SUCCESSFUL parse, not a failure (§1.6)");

        assertEquals(Set.of(LABEL_A, LABEL_B), Set.copyOf(h.store.deletedLabels));
        assertEquals(List.of(), h.store.upsertedLabels);
        assertEquals(8L, h.gens.recordedValue);
        assertEquals(1, h.reload.pushes.size(), "revoke-all DOES push (the only failure-shaped input that does)");
        assertEquals(8L, h.reload.pushes.get(0).generation());
        assertEquals(List.of(), h.reload.pushes.get(0).verifiers(),
            "the revoke-all push carries an EMPTY verifier set");

        assertTransactionalWrite(h);
        assertPushIsLast(h);
        assertNoPlaintextEscapes(h);
    }

    /** T159: an unchanged durable candidate replays the SAME generation. */
    @Test
    void restartReplaysUnchangedCandidateWithoutRenumbering(@TempDir Path dir) throws Throwable {
        Path file = writeTokens(dir, tokensFile(LABEL_A, TOKEN_A));

        Harness first = runLoad(file, Map.of(LABEL_A, STALE_VERIFIER), 7L);
        assertEquals(8L, first.gens.recordedValue, "first boot proposes persisted 7 + 1");
        assertEquals(1, first.reload.pushes.size());
        assertEquals(8L, first.reload.pushes.get(0).generation());

        // Simulated CP restart: a NEW loader over the SAME persisted state.
        Harness restarted = runLoad(file, first.store.currentRows(), first.gens.last);
        assertFalse(restarted.gens.recordedSet,
            "unchanged content must not assign another generation");
        assertEquals(List.of(), restarted.store.upsertedLabels,
            "same-generation replay does not rewrite the durable candidate");
        assertEquals(1, restarted.reload.pushes.size());
        assertEquals(8L, restarted.reload.pushes.get(0).generation(),
            "restart replays the pending/current candidate verbatim");

        assertNoPlaintextEscapes(first);
        assertNoPlaintextEscapes(restarted);
    }

    @Test
    void staleResponseNeverRelabelsRejectedContent(@TempDir Path dir) throws Throwable {
        Path file = writeTokens(dir, tokensFile(LABEL_A, TOKEN_A));
        Harness h = runLoad(file, Map.of(), 0L,
            new TokenLoaderContract.PushResult(true, 5L));

        assertEquals(List.of(1L), h.reload.pushes.stream().map(CapturedPush::generation).toList(),
            "a stale reply is a conflict, never permission to retry at current+1");
        assertEquals(1L, h.gens.recordedValue,
            "the durable candidate keeps its originally assigned generation");
    }

    @Test
    void pendingCandidateReplaysSameGenerationAfterRestart(@TempDir Path dir) throws Throwable {
        Path file = writeTokens(dir, tokensFile(LABEL_A, TOKEN_A));
        var pending = new TokenLoaderContract.PushResult(false, 0L);
        Harness first = runLoad(file, Map.of(LABEL_A, STALE_VERIFIER), 7L, pending);
        Harness restarted = runLoad(file, first.store.currentRows(), first.gens.last, pending);

        assertEquals(8L, first.reload.pushes.get(0).generation());
        assertEquals(8L, restarted.reload.pushes.get(0).generation(),
            "transport loss/missing ack remains pending at the exact candidate generation");
        assertFalse(restarted.gens.recordedSet,
            "pending replay must not consume another generation number");
    }

    /**
     * T187 / Constitution II failure table: a revocation whose delivery is
     * still pending (DP unreachable, missing or inexact acknowledgement) is
     * not counted. The loader registers the diff counts for the exact
     * candidate generation; they are written once when that generation is
     * acknowledged and never again for a later re-acknowledgement.
     */
    @Test
    void pendingDeliveryDefersDiffCountsUntilExactAcknowledgement(@TempDir Path dir)
            throws Throwable {
        Path file = writeTokens(dir, tokensFile(LABEL_A, TOKEN_A, LABEL_C, TOKEN_C));
        Harness h = runLoad(file, Map.of(LABEL_A, STALE_VERIFIER, LABEL_B, STALE_VERIFIER), 7L,
            new TokenLoaderContract.PushResult(false, 0L));

        assertEquals(List.of(), rows(h, "revoked"), "pending revocation must not be counted");
        assertEquals(List.of(), rows(h, "enrolled"), "pending enrollment must not be counted");
        assertEquals(List.of(8L), h.reload.ackWaits,
            "the diff counts wait for the exact candidate generation");

        h.reload.acknowledge(7L);
        assertEquals(List.of(), rows(h, "revoked"), "another generation's ack is not this candidate's");

        h.reload.acknowledge(8L);
        assertEquals(Set.of(LABEL_B), labelsOf(rows(h, "revoked")),
            "the revocation counts once the exact generation is acknowledged");
        assertEquals(Set.of(LABEL_C), labelsOf(rows(h, "enrolled")));

        h.reload.acknowledge(8L);
        assertEquals(1, rows(h, "revoked").size(), "a reconnect re-acknowledgement never counts twice");
        assertEquals(1, rows(h, "enrolled").size());
        assertTransactionalWrite(h);
        assertPushIsLast(h);
        assertNoPlaintextEscapes(h);
    }

    /** T187: a stale reply is a conflict; the revocation is never counted. */
    @Test
    void staleDeliveryNeverCountsDiff(@TempDir Path dir) throws Throwable {
        Path file = writeTokens(dir, tokensFile(LABEL_A, TOKEN_A));
        Harness h = runLoad(file, Map.of(LABEL_A, STALE_VERIFIER, LABEL_B, STALE_VERIFIER), 7L,
            new TokenLoaderContract.PushResult(true, 0L));

        assertEquals(List.of(), rows(h, "revoked"), "a stale-refused revocation must not be counted");
        assertEquals(List.of(), h.reload.ackWaits, "a stale candidate waits for no acknowledgement");
        h.reload.acknowledge(8L);
        assertEquals(List.of(), rows(h, "revoked"));
    }

    /** T187: an exact synchronous acknowledgement counts the diff after the push. */
    @Test
    void acknowledgedDeliveryCountsDiffAfterPush(@TempDir Path dir) throws Throwable {
        Path file = writeTokens(dir, tokensFile(LABEL_A, TOKEN_A));
        Harness h = runLoad(file, Map.of(LABEL_A, STALE_VERIFIER, LABEL_B, STALE_VERIFIER), 7L);

        assertEquals(Set.of(LABEL_B), labelsOf(rows(h, "revoked")));
        assertTrue(h.journal.firstIndexOf("audit.write(revoked") > h.journal.firstIndexOf("reload.push("),
            "the revoked count follows the acknowledged push");
        assertEquals(List.of(), h.reload.ackWaits, "an immediate exact ack needs no deferred wait");
    }

    @Test
    void incompleteGenerationZeroAuthorityFailsClosed(@TempDir Path dir) throws Throwable {
        Path file = writeTokens(dir, tokensFile(LABEL_A, TOKEN_A));
        Harness h = runLoad(file, Map.of(LABEL_A, STALE_VERIFIER), 0L);

        assertTrue(h.reload.pushes.isEmpty(),
            "stored credentials without a generation must never be relabelled as generation 1");
        assertFalse(h.gens.recordedSet, "incomplete authority cannot assign a generation");
        assertEquals(List.of(), h.store.upsertedLabels);
    }

    @Test
    void generationReservationPrecedesCandidateWriteAndRecoversCrash(@TempDir Path dir)
            throws Throwable {
        Path file = writeTokens(dir, tokensFile(LABEL_B, TOKEN_B));
        Harness changed = runLoad(file, Map.of(LABEL_A, expectedVerifier(TOKEN_A)), 7L);
        assertTrue(changed.journal.firstIndexOf("gen.record(8)")
                < changed.journal.firstIndexOf("store.begin"),
            "generation reservation must precede candidate mutation so no new content can retain generation 7");

        // Crash after reservation but before store commit leaves old rows with
        // generation 8. Restart safely consumes 9 for the still-changed YAML.
        Harness restarted = runLoad(file, Map.of(LABEL_A, expectedVerifier(TOKEN_A)), 8L);
        assertEquals(9L, restarted.gens.recordedValue);
        assertEquals(9L, restarted.reload.pushes.get(0).generation());
        assertEquals(Set.of(hex(expectedVerifier(TOKEN_B))),
            hexSet(restarted.reload.pushes.get(0).verifiers()));
    }

    // --- reflective probe (the self-skip + conformance gate) ----------------

    private static final Class<?>[] PINNED_PARAM_TYPES = {
        Path.class, byte[].class,
        TokenLoaderContract.ConfiguredTokenStore.class,
        TokenLoaderContract.GenerationStore.class,
        TokenLoaderContract.AuditSink.class,
        TokenLoaderContract.ReloadChannel.class,
        TokenLoaderContract.VerifierMinter.class,
    };

    private static Optional<Class<?>> loaderClass() {
        try {
            return Optional.of(Class.forName(LOADER_FQN));
        }
        catch (ClassNotFoundException notLanded) {
            return Optional.empty();
        }
    }

    /**
     * Order-insensitive match on the pinned parameter-type multiset. Empty
     * when no declared constructor matches — the caller turns that into a
     * hard FAIL (the T035 conformance gate), never a silent skip.
     */
    private static Optional<Constructor<?>> pinnedConstructor(Class<?> cls) {
        for (Constructor<?> c : cls.getDeclaredConstructors()) {
            if (c.getParameterCount() != PINNED_PARAM_TYPES.length) {
                continue;
            }
            List<Class<?>> remaining = new ArrayList<>(List.of(PINNED_PARAM_TYPES));
            boolean matches = true;
            for (Class<?> p : c.getParameterTypes()) {
                if (!remaining.remove(p)) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return Optional.of(c);
            }
        }
        return Optional.empty();
    }

    private static Optional<Method> noArgMethodNamed(Class<?> cls, String name) {
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getName().equals(name) && m.getParameterCount() == 0) {
                return Optional.of(m);
            }
        }
        return Optional.empty();
    }

    /**
     * Constructs the REAL loader against the pinned surface with fresh fakes
     * and runs {@code load()} once. Skips (JUnit assumption) while T035 is
     * unlanded; hard-FAILS with an expected-vs-actual diagnostic when the
     * class exists but does not expose the pinned surface.
     */
    private Harness runLoad(Path tokensYaml, Map<String, byte[]> initialStore, long lastGeneration)
            throws Throwable {
        return runLoad(tokensYaml, initialStore, lastGeneration, null);
    }

    private Harness runLoad(Path tokensYaml, Map<String, byte[]> initialStore, long lastGeneration,
            TokenLoaderContract.@Nullable PushResult forcedResult) throws Throwable {
        Class<?> cls = loaderClass().orElse(null);
        assumeTrue(cls != null, SKIP_UNTIL_T035);

        Constructor<?> ctor = pinnedConstructor(cls).orElseThrow(() -> new AssertionError(
            "T035 landed " + LOADER_FQN + " but it does not expose the pinned surface "
                + "of TokenLoaderContract (T035a §Analysis). Expected one constructor with the "
                + "exact parameter-type set " + Arrays.toString(PINNED_PARAM_TYPES)
                + " and one no-arg method named 'load'. Declared constructors: "
                + List.of(cls.getDeclaredConstructors())
                + ". A genuinely different surface is a refine escalation against T035a, "
                + "not a test edit (T035a §Out-of-scope)."));

        Harness h = new Harness(initialStore, lastGeneration, forcedResult);
        Object[] args = new Object[ctor.getParameterCount()];
        for (int i = 0; i < args.length; i++) {
            Class<?> p = ctor.getParameterTypes()[i];
            if (p == Path.class) {
                args[i] = tokensYaml;
            }
            else if (p == byte[].class) {
                args[i] = PEPPER.clone();
            }
            else if (p == TokenLoaderContract.ConfiguredTokenStore.class) {
                args[i] = h.store;
            }
            else if (p == TokenLoaderContract.GenerationStore.class) {
                args[i] = h.gens;
            }
            else if (p == TokenLoaderContract.AuditSink.class) {
                args[i] = h.audit;
            }
            else if (p == TokenLoaderContract.ReloadChannel.class) {
                args[i] = h.reload;
            }
            else if (p == TokenLoaderContract.VerifierMinter.class) {
                args[i] = h.minter;
            }
            else {
                throw new AssertionError("unexpected pinned-surface parameter type: " + p);
            }
        }

        ctor.setAccessible(true);
        Object loader = ctor.newInstance(args);

        Method load = noArgMethodNamed(cls, "load").orElseThrow(() -> new AssertionError(
            "T035 landed " + LOADER_FQN + " without a no-arg method named 'load' "
                + "(pinned surface, T035a §Analysis)."));
        load.setAccessible(true);
        try {
            load.invoke(loader);
        }
        catch (InvocationTargetException e) {
            throw new AssertionError("load() threw — the CP would crash-loop on this input "
                + "(§1.6/FR-018: missing/unreadable/invalid/unparseable must never throw)", e.getCause());
        }
        return h;
    }

    // --- fakes (shared journal makes cross-fake ordering observable) --------

    private static final class Harness {

        final Journal journal = new Journal();
        final FakeStore store;
        final FakeGens gens;
        final FakeAudit audit;
        final FakeReload reload;
        final FakeMinter minter;

        Harness(Map<String, byte[]> initialStore, long lastGeneration,
                TokenLoaderContract.@Nullable PushResult forcedResult) {
            store = new FakeStore(journal, initialStore);
            gens = new FakeGens(journal, lastGeneration);
            audit = new FakeAudit(journal);
            reload = new FakeReload(journal, forcedResult);
            minter = new FakeMinter(journal);
        }
    }

    private static final class Journal {
        final List<String> lines = new ArrayList<>();

        void add(String line) {
            lines.add(line);
        }

        int firstIndexOf(String prefix) {
            for (int i = 0; i < lines.size(); i++) {
                if (lines.get(i).startsWith(prefix)) {
                    return i;
                }
            }
            return -1;
        }
    }

    private static final class FakeStore implements TokenLoaderContract.ConfiguredTokenStore {
        final Journal journal;
        final TreeMap<String, byte[]> rows = new TreeMap<>();
        final List<String> upsertedLabels = new ArrayList<>();
        final List<byte[]> upsertedVerifiers = new ArrayList<>();
        final List<String> deletedLabels = new ArrayList<>();

        FakeStore(Journal journal, Map<String, byte[]> initial) {
            this.journal = journal;
            rows.putAll(initial);
        }

        Map<String, byte[]> currentRows() {
            return Map.copyOf(rows);
        }

        @Override
        public List<TokenLoaderContract.StoredToken> storedTokens() {
            return rows.entrySet().stream()
                .map(e -> new TokenLoaderContract.StoredToken(e.getKey(), e.getValue()))
                .toList();
        }

        @Override
        public void begin() {
            journal.add("store.begin");
        }

        @Override
        public void upsert(String label, byte[] verifier) {
            upsertedLabels.add(label);
            upsertedVerifiers.add(verifier);
            rows.put(label, verifier);
            journal.add("store.upsert(" + label + ")");
        }

        @Override
        public void delete(String label) {
            deletedLabels.add(label);
            rows.remove(label);
            journal.add("store.delete(" + label + ")");
        }

        @Override
        public void commit() {
            journal.add("store.commit");
        }
    }

    private static final class FakeGens implements TokenLoaderContract.GenerationStore {
        final Journal journal;
        long last;
        long recordedValue;
        boolean recordedSet;

        FakeGens(Journal journal, long last) {
            this.journal = journal;
            this.last = last;
        }

        @Override
        public long lastGeneration() {
            return last;
        }

        @Override
        public void record(long generation) {
            recordedValue = generation;
            recordedSet = true;
            last = generation;
            journal.add("gen.record(" + generation + ")");
        }
    }

    private record CapturedAudit(String action, String target, String detailJson) {
    }

    private static final class FakeAudit implements TokenLoaderContract.AuditSink {
        final Journal journal;
        final List<CapturedAudit> rows = new ArrayList<>();

        FakeAudit(Journal journal) {
            this.journal = journal;
        }

        @Override
        public void write(String action, String target, String detailJson) {
            rows.add(new CapturedAudit(action, target, detailJson));
            journal.add("audit.write(" + action + "," + target + ")");
        }
    }

    private record CapturedPush(long generation, List<byte[]> verifiers) {
    }

    private static final class FakeReload implements TokenLoaderContract.ReloadChannel {
        final Journal journal;
        final List<CapturedPush> pushes = new ArrayList<>();
        final TokenLoaderContract.@Nullable PushResult forcedResult;
        /** T187: deferred acknowledgement actions, keyed by exact generation. */
        final List<Long> ackWaits = new ArrayList<>();
        final List<Runnable> ackActions = new ArrayList<>();

        FakeReload(Journal journal, TokenLoaderContract.@Nullable PushResult forcedResult) {
            this.journal = journal;
            this.forcedResult = forcedResult;
        }

        @Override
        public TokenLoaderContract.PushResult push(long generation, List<byte[]> verifiers) {
            pushes.add(new CapturedPush(generation,
                verifiers.stream().map(byte[]::clone).toList()));
            journal.add("reload.push(" + generation + "," + verifiers.size() + ")");
            return forcedResult == null
                ? new TokenLoaderContract.PushResult(false, generation)
                : forcedResult;
        }

        @Override
        public void whenAcknowledged(long generation, Runnable onAcknowledged) {
            ackWaits.add(generation);
            ackActions.add(onAcknowledged);
        }

        /** Simulates a later exact acknowledgement delivered by the channel. */
        void acknowledge(long generation) {
            for (int i = 0; i < ackWaits.size(); i++) {
                if (ackWaits.get(i) == generation) {
                    ackActions.get(i).run();
                }
            }
        }
    }

    private record Minted(byte[] bufferRef, byte[] plaintextCopy, byte[] tag) {
    }

    /**
     * Real HMAC-SHA-256 under the injected pepper (§1.5) — a pure mint: NO
     * internal clear. The recorded {@code bufferRef} is the caller's own
     * array, so a loader that skips its §1.1 clear fails the post-load
     * all-zero assertion (non-tautological by construction).
     */
    private static final class FakeMinter implements TokenLoaderContract.VerifierMinter {
        final Journal journal;
        final List<Minted> minted = new ArrayList<>();

        FakeMinter(Journal journal) {
            this.journal = journal;
        }

        @Override
        public byte[] mint(byte[] tokenUtf8) {
            byte[] tag = hmacSha256(PEPPER, tokenUtf8);
            minted.add(new Minted(tokenUtf8, tokenUtf8.clone(), tag));
            journal.add("minter.mint(" + tokenUtf8.length + ")");
            return tag;
        }
    }

    // --- assertion helpers ---------------------------------------------------

    private static Path writeTokens(Path dir, String yaml) {
        try {
            Path file = dir.resolve("tokens.yaml");
            Files.writeString(file, yaml);
            return file;
        }
        catch (java.io.IOException e) {
            throw new IllegalStateException("fixture write failed", e);
        }
    }

    private static String tokensFile(String... labelTokenPairs) {
        StringBuilder sb = new StringBuilder("tokens:\n");
        for (int i = 0; i < labelTokenPairs.length; i += 2) {
            sb.append("  - label: ").append(labelTokenPairs[i]).append('\n')
                .append("    token: ").append(labelTokenPairs[i + 1]).append('\n');
        }
        return sb.toString();
    }

    private static List<CapturedAudit> rows(Harness h, String action) {
        return h.audit.rows.stream().filter(r -> r.action().equals(action)).toList();
    }

    private static Set<String> labelsOf(List<CapturedAudit> rows) {
        return rows.stream().map(CapturedAudit::target).collect(Collectors.toSet());
    }

    /** The labels the oracle expects to enroll / revoke for a diff. */
    private static Set<String> enrolledLabels(Set<String> previous, Set<String> current) {
        var out = new TreeSet<>(current);
        out.removeAll(previous);
        return out;
    }

    private static Set<String> revokedLabels(Set<String> previous, Set<String> current) {
        var out = new TreeSet<>(previous);
        out.removeAll(current);
        return out;
    }

    private static Map<String, Object> detailOf(String detailJson) {
        Object parsed = new Yaml().load(detailJson);
        if (!(parsed instanceof Map<?, ?> map)) {
            throw new AssertionError("detail_json is not a JSON/YAML mapping: " + detailJson);
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> out = (Map<String, Object>) map;
        return out;
    }

    /** Null-tolerant map literal (Map.of rejects nulls; §4 io rows need them). */
    private static Map<String, Object> mapOf(Object... keyValues) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            m.put((String) keyValues[i], keyValues[i + 1]);
        }
        return m;
    }

    private static void assertVerifiersUpserted(Harness h, Map<String, String> labelTokens) {
        for (int i = 0; i < h.store.upsertedLabels.size(); i++) {
            String label = h.store.upsertedLabels.get(i);
            String token = Objects.requireNonNull(labelTokens.get(label),
                () -> "fixture has no token for upserted label " + label);
            byte[] expected = expectedVerifier(token);
            assertArrayEquals(expected, h.store.upsertedVerifiers.get(i),
                "stored verifier for " + label + " must be the fresh §1.5 HMAC tag "
                    + "(a §1.7 pepper rotation relies on same-label rewrites)");
        }
    }

    /**
     * §1.6 atomicity: store.begin precedes every store mutation; store.commit
     * follows them. T187: enrolled/revoked counts are NOT part of the
     * candidate transaction. They describe acknowledged application, so they
     * may appear only after the ReloadTokens push (Constitution II failure
     * table: report pending delivery, not success). config_error rows are
     * deliberately exempt — validation failures are discovered during
     * parsing, before the transaction opens.
     */
    private static void assertTransactionalWrite(Harness h) {
        int begin = h.journal.firstIndexOf("store.begin");
        int commit = h.journal.firstIndexOf("store.commit");
        int push = h.journal.firstIndexOf("reload.push(");
        assertTrue(begin >= 0, "successful loads open a store transaction");
        assertTrue(commit > begin, "store.commit must follow store.begin");
        for (int i = 0; i < h.journal.lines.size(); i++) {
            String line = h.journal.lines.get(i);
            boolean inside = i > begin && i < commit;
            boolean mutation = line.startsWith("store.upsert(") || line.startsWith("store.delete(");
            boolean diffRow = line.startsWith("audit.write(enrolled") || line.startsWith("audit.write(revoked");
            if (mutation) {
                assertTrue(inside, "partial state leak in journal: " + line);
            }
            if (diffRow) {
                assertTrue(push >= 0 && i > push,
                    "T187: an enrolled/revoked count before DP acknowledgement claims success early: " + line);
            }
        }
    }

    /**
     * §1.7 write order: the ReloadTokens push is the last store/generation/
     * delivery call of a load. T187: only acknowledged enrolled/revoked
     * counts may follow it.
     */
    private static void assertPushIsLast(Harness h) {
        int push = h.journal.firstIndexOf("reload.push(");
        assertTrue(push >= 0, "a successful load pushes once");
        for (int i = push + 1; i < h.journal.lines.size(); i++) {
            String line = h.journal.lines.get(i);
            assertTrue(line.startsWith("audit.write(enrolled") || line.startsWith("audit.write(revoked"),
                "only acknowledged diff counts may follow the push (§1.7: store, then generation, "
                    + "then ReloadTokens): " + line);
        }
        assertTrue(h.journal.firstIndexOf("gen.record(") < push,
            "§1.7: the generation is recorded before the push");
    }

    /** Failure cases: no store transaction, no generation record, no push. */
    private static void assertUntouchedExceptAudit(Harness h) {
        assertEquals(-1, h.journal.firstIndexOf("store.begin"), "no store transaction on failure");
        assertEquals(-1, h.journal.firstIndexOf("store.commit"), "no store transaction on failure");
        assertEquals(-1, h.journal.firstIndexOf("store.upsert("), "no store writes on failure");
        assertEquals(-1, h.journal.firstIndexOf("store.delete("), "no store writes on failure");
        assertEquals(-1, h.journal.firstIndexOf("gen.record("), "no generation record on failure");
        assertEquals(-1, h.journal.firstIndexOf("reload.push("),
            "§1.6: NO ReloadTokens call on failure — the DP keeps its last-known list (Principle II)");
    }

    /**
     * §1.6: no plaintext token and no pepper bytes anywhere the test can
     * observe — every audit row field, the whole call journal, and every
     * pushed payload (verifiers only; labels are not in the message by
     * design). Hex-encoded scan: tokens are lowercase hex, the pepper is
     * scanned in both raw-hex and UTF-8-ish renderings.
     */
    private static void assertNoPlaintextEscapes(Harness h) {
        List<String> surfaces = new ArrayList<>(h.journal.lines);
        for (CapturedAudit r : h.audit.rows) {
            surfaces.add(r.action());
            surfaces.add(r.target());
            surfaces.add(r.detailJson());
        }
        List<byte[]> pushedBytes = new ArrayList<>();
        for (CapturedPush p : h.reload.pushes) {
            for (byte[] v : p.verifiers()) {
                pushedBytes.add(v);
                surfaces.add(hex(v));
            }
        }
        for (String token : ALL_PLAINTEXTS) {
            for (String surface : surfaces) {
                assertFalse(surface.contains(token),
                    "§1.6 leak: plaintext token material surfaced in a captured payload");
            }
        }
        String pepperHex = hex(PEPPER);
        for (String surface : surfaces) {
            assertFalse(surface.contains(pepperHex),
                "§1.6 leak: pepper bytes surfaced in a captured payload");
        }
        for (byte[] payload : pushedBytes) {
            assertFalse(Arrays.equals(payload, PEPPER),
                "§1.6 leak: the pepper was pushed instead of a verifier");
            assertEquals(32, payload.length,
                "§1.2/§\"ReloadTokens\": every pushed verifier is exactly 32 bytes");
        }
    }

    // --- crypto + misc helpers ----------------------------------------------

    private static byte[] expectedVerifier(String tokenHex) {
        return hmacSha256(PEPPER, tokenHex.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] hmacSha256(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        }
        catch (Exception e) {
            throw new AssertionError("HMAC-SHA-256 unavailable: " + e.getMessage(), e);
        }
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private static Set<String> hexSet(List<byte[]> verifiers) {
        return verifiers.stream().map(TokenLoaderTest::hex).collect(Collectors.toSet());
    }

    private static byte[] repeat(byte b, int n) {
        byte[] out = new byte[n];
        Arrays.fill(out, b);
        return out;
    }
}
