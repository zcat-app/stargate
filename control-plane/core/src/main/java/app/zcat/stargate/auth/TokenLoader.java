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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;
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
 * verifiers to the data plane, and write the §4 audit rows through the
 * injected {@link TokenLoaderContract.AuditSink} (T036's
 * {@code AuditLogService}, which derives {@code actor=tokens.yaml}).
 *
 * <p><strong>Failure semantics (§1.6, T092 / sol-review M1).</strong> A
 * missing, unreadable, unparseable, structurally invalid, or all-invalid
 * {@code tokens.yaml} emits at most one {@code config_error} audit row per
 * offending record (or file-level structure violation), logs a warning, and
 * returns WITHOUT touching the store, the generation record, or the data
 * plane — the DP keeps its last-known verifier list and keeps serving port
 * 8881 (Principle II). {@code load()} never throws on file input; only the
 * injected collaborators' own failures propagate (a broken store is
 * infrastructure, not configuration). A missing file is the legitimate
 * first-boot state: a single path-only warning, NO audit row (§4 exemption).
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
 * <p><strong>Write order (§1.7).</strong> Store (full current record set,
 * unchanged labels rewritten with fresh verifiers — the pepper-rotation
 * property) → generation record → {@code ReloadTokens}. On a stale reply
 * (T035 note (c), §1.3/§1.8 reconciliation) the loader adopts the DP's
 * reported {@code currentGeneration + 1}, records it, and retries — bounded,
 * because the handshake is deterministic under the single-CP topology and the
 * cap only stops a misbehaving DP reply from spinning the CP.
 */
public final class TokenLoader {

    private static final Logger LOG = Logger.getLogger(TokenLoader.class);

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

    /**
     * §1.3/§1.8 reconciliation bound: the deterministic retry (adopt the DP's
     * reported {@code current + 1}) converges in one round under the
     * single-CP topology; the cap stops a misbehaving DP reply from spinning
     * the CP. Exhaustion leaves the DP on its previous generation — the next
     * boot reconciles again (§1.8 durability: losing sync never revokes).
     */
    private static final int MAX_PUSH_ATTEMPTS = 3;

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
            // §1.1/§4: the legitimate first-boot state — one path-only warning
            // (no token context exists), NO audit row, NO ReloadTokens call
            // (the DP keeps its last-known list, §1.6/Principle II).
            LOG.warnf("tokens.yaml not found at %s — first boot with no configured tokens; "
                + "the data plane keeps its last-known list (FR-018/§1.6)", tokensYaml);
            return;
        }
        catch (IOException unreadable) {
            // §1.1/§4 kind=io: the distinct operator signal for a permissions
            // misconfiguration; line=null (no parser context). No push.
            configErrorUnlocated("io");
            LOG.warnf("tokens.yaml at %s is unreadable (%s) — check the mount's ownership/mode; "
                + "the data plane keeps its last-known list (§1.6)",
                tokensYaml, unreadable.getClass().getSimpleName());
            return;
        }
        catch (YAMLException unparseable) {
            if (unparseable instanceof MarkedYAMLException marked) {
                int line = marked.getProblemMark().getLine() + 1;
                configErrorAt("parse", line);
                LOG.warnf("tokens.yaml is not parseable YAML (line %d) — the data plane "
                    + "keeps its last-known list (§1.6)", line);
            }
            else {
                // No parser mark (e.g. input-decoding failure) — §4 allows line=null.
                configErrorUnlocated("parse");
                LOG.warnf("tokens.yaml is not parseable — the data plane keeps its "
                    + "last-known list (§1.6)");
            }
            return;
        }

        // File-level structure (§1.1 File rows): a mapping document with a
        // sequence under `tokens`. Any other shape means no record set can be
        // derived — a validation failure, and deliberately NOT a revoke-all
        // (§1.6 reserves that for a successfully-parsed explicit empty list).
        if (!(root instanceof MappingNode doc)) {
            configErrorUnlocated("validation");
            LOG.warnf("tokens.yaml must be a mapping with a 'tokens' key — the data plane "
                + "keeps its last-known list (§1.1/§1.6)");
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
            LOG.warnf("tokens.yaml is missing its 'tokens' key — the data plane keeps its "
                + "last-known list (§1.1/§1.6)");
            return;
        }
        if (!(tokensNode instanceof SequenceNode seq)) {
            configErrorAt("validation", markLine(tokensNode));
            LOG.warnf("tokens.yaml field 'tokens' must be a sequence — the data plane keeps "
                + "its last-known list (§1.1/§1.6)");
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
                LOG.warnf("tokens.yaml line %d: rejected record — a token record must be a "
                    + "mapping of label/token (§1.1)", markLine(entry));
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
                LOG.warnf("tokens.yaml line %d: rejected record — missing label (§1.1)", line);
                continue;
            }
            String label = labelNode.getValue();
            if (label.isEmpty()) {
                configErrorAt("validation", line);
                LOG.warnf("tokens.yaml line %d: rejected record — label must be non-empty (§1.1)", line);
                continue;
            }
            if (label.indexOf('\0') >= 0) {
                // No label text in the log: NUL bytes do not belong in log lines.
                configErrorAt("validation", line);
                LOG.warnf("tokens.yaml line %d: rejected record — label must not contain NUL bytes (§1.1)", line);
                continue;
            }
            if (label.codePointCount(0, label.length()) > LABEL_MAX_CODE_POINTS) {
                configErrorAt("validation", line);
                LOG.warnf("tokens.yaml line %d: rejected record — label exceeds %d characters (§1.1)",
                    line, LABEL_MAX_CODE_POINTS);
                continue;
            }
            if (tokenNode == null) {
                configErrorAt("validation", line);
                LOG.warnf("tokens.yaml line %d: rejected record for label '%s' — missing token (§1.1)",
                    line, label);
                continue;
            }
            String token = tokenNode.getValue();
            if (!TOKEN_HEX.matcher(token).matches()) {
                // §1.1: warn WITHOUT the offending token bytes — label only.
                configErrorAt("validation", line);
                LOG.warnf("tokens.yaml line %d: rejected record for label '%s' — token must be "
                    + "32-char lowercase hex (§1.1/FR-017)", line, label);
                continue;
            }
            if (!acceptedLabels.add(label)) {
                configErrorAt("validation", line);
                LOG.warnf("tokens.yaml line %d: rejected record — duplicate label '%s' (§1.1)", line, label);
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
            LOG.warnf("tokens.yaml contains no valid token records — the data plane keeps its "
                + "last-known list (§1.6)");
            return;
        }

        // §1.8: propose the persisted last + 1 — a restarted CP never restarts
        // at 1 (that would be stale the moment the DP accepted ≥ 1 and would
        // silently revoke every client via the reconciliation handshake).
        long generation = generations.lastGeneration() + 1;

        // §4 label diff: enrolled = new this load, revoked = stored but absent.
        Set<String> newLabels = new LinkedHashSet<>();
        for (TokenRecord record : valid) {
            newLabels.add(record.label());
        }
        Set<String> storedLabels = new LinkedHashSet<>(store.storedLabels());

        List<byte[]> verifiers = new ArrayList<>(valid.size());
        store.begin();
        try {
            for (TokenRecord record : valid) {
                byte[] plaintext = record.token().getBytes(StandardCharsets.UTF_8);
                byte[] verifier = minter.mint(plaintext);
                // §1.1: the mutable HMAC input buffer is cleared before the
                // next record is processed — the narrowed erasure claim.
                Arrays.fill(plaintext, (byte) 0);
                store.upsert(record.label(), verifier);
                verifiers.add(verifier);
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

        // §1.7 write order: store, then generation, then ReloadTokens — the
        // push is the last action of a successful load.
        generations.record(generation);
        push(generation, verifiers);
    }

    /**
     * Issues {@code ReloadTokens} and reconciles a stale rejection
     * (T035 note (c), §1.3/§1.8): adopt the DP's reported
     * {@code currentGeneration + 1}, record it as the last-assigned value,
     * and retry. Bounded by {@link #MAX_PUSH_ATTEMPTS}; exhaustion leaves the
     * DP on its previous generation (availability first, Principle II) and
     * the next boot's §1.8 read re-syncs.
     */
    private void push(long generation, List<byte[]> verifiers) {
        TokenLoaderContract.PushResult result = reload.push(generation, verifiers);
        for (int attempt = 1; result.stale() && attempt < MAX_PUSH_ATTEMPTS; attempt++) {
            long adopted = result.currentGeneration() + 1;
            LOG.warnf("ReloadTokens generation %d rejected as stale — reconciling with the "
                + "data plane's current generation %d (§1.8)", generation, result.currentGeneration());
            generations.record(adopted);
            generation = adopted;
            result = reload.push(generation, verifiers);
        }
        if (result.stale()) {
            LOG.warnf("ReloadTokens still stale after %d attempts — the data plane keeps its "
                + "previous generation; the next boot re-reads token_generation and "
                + "reconciles (§1.8)", MAX_PUSH_ATTEMPTS);
        }
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
