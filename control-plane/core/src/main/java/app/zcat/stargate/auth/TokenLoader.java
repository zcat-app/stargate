// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package app.zcat.stargate.auth;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.MarkedYAMLException;
import org.yaml.snakeyaml.error.YAMLException;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.SequenceNode;

/**
 * The {@code tokens.yaml} loader (FR-017/FR-018; data-model.md §1.1) — the
 * production consumer of the {@link TokenLoaderContract} seams pinned by
 * T035a. One {@link #load()} per CP start (FR-018 startup-only reload;
 * T041's {@code @QuarkusMain} wiring is the caller): parse, validate, diff
 * against the persisted record set, persist, bump the generation, push
 * verifiers to the data plane, and increment §4 operational counts through
 * the injected {@link TokenLoaderContract.AuditSink}. The production sink
 * discards legacy label/detail arguments (T152 / Constitution III).
 *
 * <p><strong>Failure semantics (§1.6, T092 / sol-review M1).</strong> A
 * missing, unreadable, unparseable, structurally invalid, or all-invalid
 * {@code tokens.yaml} increments {@code config_error} at most once per
 * offending record (or file-level structure violation), and
 * returns WITHOUT touching the store, the generation record, or the data
 * plane — the DP keeps its last-known verifier list and keeps serving port
 * 8881 (Principle II). {@code load()} never throws on file input; only the
 * injected collaborators' own failures propagate (a broken store is
 * infrastructure, not configuration). A missing file is the legitimate
 * first-boot state: no operational count or diagnostic record.
 * The SOLE revoke-all path is a successfully-parsed explicit {@code tokens: []}
 * — which alone pushes an empty verifier set.
 *
 * <p><strong>Memory-erasure claim is the narrowed §1.1 form.</strong> The
 * loader fills a mutable {@code byte[]} with one record's UTF-8 plaintext,
 * mints through the injected {@link TokenLoaderContract.VerifierMinter}, and
 * zeroes that buffer before the next record (§1.1). SnakeYAML-materialized
 * {@code String}s are NOT claimed erased (immutable; THREAT-MODEL §2.8 scopes
 * process-memory attackers out). The loader performs NO crypto itself — the
 * verifier is whatever the minter returns ({@code HMAC-SHA-256(pepper, token)},
 * §1.5, in production).
 *
 * <p><strong>Write order (§1.7).</strong> Reserve a changed candidate's next
 * generation → store its full record set → {@code ReloadTokens}. Reserving
 * first may consume a number if the store write fails, but prevents a crash
 * from pairing new credential content with an old generation. An exact
 * unchanged durable candidate replays at the same generation. Rejection,
 * missing acknowledgment or transport loss never relabels content at a
 * DP-reported generation; the persisted candidate remains pending for exact
 * replay.
 */
public final class TokenLoader {
    // data-model.md §4 audit vocabulary — fixed enum, never free text. The
    // literals mirror AuditLogService's constants (core cannot depend on
    // persistence; the sink validates the vocabulary independently).
    private static final String ACTION_ENROLLED = "enrolled";
    private static final String ACTION_REVOKED = "revoked";
    private static final String ACTION_CONFIG_ERROR = "config_error";

    /** §4: config_error rows target the file constant; diff rows target the label. */
    private static final String TARGET_FILE = "tokens.yaml";

    /** §4 diff-row detail {@code source} value. */
    private static final String DETAIL_SOURCE = "tokens.yaml";

    /** FR-017: the plaintext token is exactly 32 lowercase hex chars (128 bits). */
    private static final Pattern TOKEN_HEX = Pattern.compile("^[0-9a-f]{32}$");

    /** §1.1 label row: at most 64 UTF-8 chars. */
    private static final int LABEL_MAX_CODE_POINTS = 64;

    private final Path tokensYaml;

    /**
     * The §1.7 pepper, injected per the pinned T035a surface. Held, never
     * used here: minting is the injected {@link TokenLoaderContract.VerifierMinter}'s
     * role (production wiring builds it around this same pepper), and the
     * pepper's lifecycle — clearing above all — belongs to the key file and
     * the minter, NOT to a per-load object. Never logged, never zeroed, never
     * pushed (§1.6).
     */
    private final byte[] pepper;

    private final TokenLoaderContract.ConfiguredTokenStore store;
    private final TokenLoaderContract.GenerationStore generations;
    private final TokenLoaderContract.AuditSink audit;
    private final TokenLoaderContract.ReloadChannel reload;
    private final TokenLoaderContract.VerifierMinter minter;

    /**
     * Pinned surface (T035a §Analysis): the test's reflective probe matches
     * this parameter-type list order-insensitively; declared here in the
     * documented order. Public because T041's wiring wires from outside the
     * package (package-private also satisfies the probe).
     */
    public TokenLoader(Path tokensYaml, byte[] pepper,
            TokenLoaderContract.ConfiguredTokenStore store,
            TokenLoaderContract.GenerationStore generations,
            TokenLoaderContract.AuditSink audit,
            TokenLoaderContract.ReloadChannel reload,
            TokenLoaderContract.VerifierMinter minter) {
        this.tokensYaml = tokensYaml;
        this.pepper = pepper;
        this.store = store;
        this.generations = generations;
        this.audit = audit;
        this.reload = reload;
        this.minter = minter;
    }

    /** One validated record of the parsed file (§1.1: label + plaintext). */
    private record TokenRecord(String label, String token) {
    }

    /**
     * Reads {@code tokens.yaml} and applies the load. Never throws on file
     * input (FR-018 — the CP must come up healthy so the DP keeps serving,
     * Principle II).
     */
    public void load() {
        Node root;
        try (Reader reader = Files.newBufferedReader(tokensYaml, StandardCharsets.UTF_8)) {
            root = new Yaml().compose(reader);
        }
        catch (NoSuchFileException | FileNotFoundException firstBoot) {
            // §1.1/§4: the legitimate first-boot state — no count or diagnostic,
            // and no ReloadTokens call
            // (the DP keeps its last-known list, §1.6/Principle II).

            return;
        }
        catch (IOException unreadable) {
            // §1.1/§4 kind=io: the distinct operator signal for a permissions
            // misconfiguration; line=null (no parser context). No push.
            configErrorUnlocated("io");

            return;
        }
        catch (YAMLException unparseable) {
            if (unparseable instanceof MarkedYAMLException marked) {
                int line = marked.getProblemMark().getLine() + 1;
                configErrorAt("parse", line);

            }
            else {
                // No parser mark (e.g. input-decoding failure) — §4 allows line=null.
                configErrorUnlocated("parse");

            }
            return;
        }

        // File-level structure (§1.1 File rows): a mapping document with a
        // sequence under `tokens`. Any other shape means no record set can be
        // derived — a validation failure, and deliberately NOT a revoke-all
        // (§1.6 reserves that for a successfully-parsed explicit empty list).
        if (!(root instanceof MappingNode doc)) {
            configErrorUnlocated("validation");

            return;
        }
        Node tokensNode = null;
        for (NodeTuple kv : doc.getValue()) {
            if (kv.getKeyNode() instanceof ScalarNode key && "tokens".equals(key.getValue())) {
                tokensNode = kv.getValueNode();
                break;
            }
        }
        if (tokensNode == null) {
            configErrorUnlocated("validation");

            return;
        }
        if (!(tokensNode instanceof SequenceNode seq)) {
            configErrorAt("validation", markLine(tokensNode));

            return;
        }

        // Per-record parse + validation (§1.1 table). config_error rows are
        // written as discovered — before the store transaction opens (the
        // T035a journal contract deliberately exempts them from begin/commit).
        List<TokenRecord> valid = new ArrayList<>();
        Set<String> acceptedLabels = new LinkedHashSet<>();
        for (Node entry : seq.getValue()) {
            if (!(entry instanceof MappingNode record)) {
                configErrorAt("validation", markLine(entry));

                continue;
            }
            int line = markLine(record);
            ScalarNode labelNode = null;
            ScalarNode tokenNode = null;
            for (NodeTuple kv : record.getValue()) {
                if (!(kv.getKeyNode() instanceof ScalarNode key)) {
                    continue;
                }
                if ("label".equals(key.getValue()) && kv.getValueNode() instanceof ScalarNode v) {
                    labelNode = v;
                }
                else if ("token".equals(key.getValue()) && kv.getValueNode() instanceof ScalarNode v) {
                    tokenNode = v;
                }
            }
            if (labelNode == null) {
                configErrorAt("validation", line);

                continue;
            }
            String label = labelNode.getValue();
            if (label.isEmpty()) {
                configErrorAt("validation", line);

                continue;
            }
            if (label.indexOf('\0') >= 0) {
                configErrorAt("validation", line);

                continue;
            }
            if (label.codePointCount(0, label.length()) > LABEL_MAX_CODE_POINTS) {
                configErrorAt("validation", line);

                continue;
            }
            if (tokenNode == null) {
                configErrorAt("validation", line);

                continue;
            }
            String token = tokenNode.getValue();
            if (!TOKEN_HEX.matcher(token).matches()) {
                // §1.1: warn WITHOUT the offending token bytes — label only.
                configErrorAt("validation", line);

                continue;
            }
            if (!acceptedLabels.add(label)) {
                configErrorAt("validation", line);

                continue;
            }
            valid.add(new TokenRecord(label, token));
        }

        // A file whose records ALL fail validation derives no record set —
        // the per-record validation rows above are the config_error signal,
        // and the DP keeps its last-known list (§1.1 File row / §1.6). Only
        // the explicit `tokens: []` sequence (or a non-empty valid set)
        // proceeds past this point.
        if (!seq.getValue().isEmpty() && valid.isEmpty()) {

            return;
        }

        long storedGeneration = generations.lastGeneration();
        Collection<TokenLoaderContract.StoredToken> storedTokens = store.storedTokens();
        // A nonempty candidate without its generation is incomplete authority,
        // not first boot. Fail closed instead of inventing generation 1.
        if (storedGeneration == 0 && !storedTokens.isEmpty()) {
            return;
        }

        // §4 label diff: enrolled = new this load, revoked = stored but absent.
        Set<String> newLabels = new LinkedHashSet<>();
        for (TokenRecord record : valid) {
            newLabels.add(record.label());
        }
        Set<String> storedLabels = new LinkedHashSet<>();
        for (TokenLoaderContract.StoredToken stored : storedTokens) {
            storedLabels.add(stored.label());
        }

        List<byte[]> verifiers = new ArrayList<>(valid.size());
        for (TokenRecord record : valid) {
            byte[] plaintext = record.token().getBytes(StandardCharsets.UTF_8);
            byte[] verifier = minter.mint(plaintext);
            Arrays.fill(plaintext, (byte) 0);
            verifiers.add(verifier);
        }

        boolean sameContent = storedGeneration > 0 && sameVerifierMultiset(storedTokens, verifiers);
        if (storedGeneration > 0 && sameStoredRecords(storedTokens, valid, verifiers)) {
            reload.push(storedGeneration, verifiers);
            return;
        }
        long generation = sameContent ? storedGeneration : storedGeneration + 1;

        // Reserve before mutating candidate rows. A crash after reservation
        // may consume a generation; a crash after candidate commit can never
        // leave new content paired with the prior generation (T159).
        if (generation != storedGeneration) {
            generations.record(generation);
        }

        store.begin();
        try {
            for (int i = 0; i < valid.size(); i++) {
                store.upsert(valid.get(i).label(), verifiers.get(i));
            }
            for (String label : newLabels) {
                if (!storedLabels.contains(label)) {
                    audit.write(ACTION_ENROLLED, label, diffDetail(generation));
                }
            }
            for (String label : storedLabels) {
                if (!newLabels.contains(label)) {
                    audit.write(ACTION_REVOKED, label, diffDetail(generation));
                    store.delete(label);
                }
            }
            store.commit();
        }
        catch (RuntimeException failure) {
            store.rollback(); // best-effort abort of the open transaction (T035a port)
            throw failure;
        }

        // §1.7 write order: generation reservation, store, then ReloadTokens
        // — the push is the last action of a successful load.
        reload.push(generation, verifiers);
    }

    private static boolean sameVerifierMultiset(
            Collection<TokenLoaderContract.StoredToken> storedTokens, List<byte[]> desired) {
        List<byte[]> stored = storedTokens.stream().map(TokenLoaderContract.StoredToken::verifier)
                .map(bytes -> bytes.clone()).sorted(Arrays::compareUnsigned).toList();
        List<byte[]> proposed = desired.stream().map(bytes -> bytes.clone())
                .sorted(Arrays::compareUnsigned).toList();
        if (stored.size() != proposed.size()) {
            return false;
        }
        for (int i = 0; i < stored.size(); i++) {
            if (!Arrays.equals(stored.get(i), proposed.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean sameStoredRecords(Collection<TokenLoaderContract.StoredToken> storedTokens,
            List<TokenRecord> desired, List<byte[]> verifiers) {
        if (storedTokens.size() != desired.size()) {
            return false;
        }
        var storedByLabel = new HashMap<String, byte[]>();
        for (TokenLoaderContract.StoredToken stored : storedTokens) {
            storedByLabel.put(stored.label(), stored.verifier());
        }
        for (int i = 0; i < desired.size(); i++) {
            if (!Arrays.equals(storedByLabel.get(desired.get(i).label()), verifiers.get(i))) {
                return false;
            }
        }
        return true;
    }

    /** One §4 config_error row with a parser-reported line. */
    private void configErrorAt(String kind, int line) {
        audit.write(ACTION_CONFIG_ERROR, TARGET_FILE,
            "{\"kind\":\"" + kind + "\",\"line\":" + line + "}");
    }

    /** One §4 config_error row with {@code line:null} — no parser context. */
    private void configErrorUnlocated(String kind) {
        audit.write(ACTION_CONFIG_ERROR, TARGET_FILE,
            "{\"kind\":\"" + kind + "\",\"line\":null}");
    }

    /** §4 detail_json for enrolled/revoked diff rows. */
    private static String diffDetail(long generation) {
        return "{\"source\":\"" + DETAIL_SOURCE + "\",\"generation\":" + generation + "}";
    }

    /** 1-based parser line of a composed node's start mark (§4 {@code line}). */
    private static int markLine(Node node) {
        return node.getStartMark().getLine() + 1;
    }
}
