// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// snapshot.go — the dp-snapshot.json persistence layer (T046): the atomic
// cold-start cache behind server.go's SnapshotFunc seam. Contract:
// specs/001-tor-route/data-model.md §1.4 (schemaVersion 2, verifiers-only —
// NEVER the pepper or plaintext; stale v1 ignored, not misparsed),
// §1.3 (generation / atomic swap), contracts/control-grpc.md §"ReloadTokens"
// row 4 (persist before the OK response; a failed persist is journaled and
// the response stays OK — in-memory truth wins), and arch §5.5 (control
// plane down at startup → continue from the last-known snapshot).
//
// The snapshot holds derived material only (base64 HMAC-SHA-256 tags): the
// pepper and plaintexts never reach this file, so the writer's signature
// takes an *auth.Generation — there is no API shape that could persist more.
package controlclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/auth"
)

// snapshotFileName is the fixed file name inside the state dir
// (§1.4: /var/lib/stargate/dp-snapshot.json in production; the dir is
// resolved by the boot sequence, T050 — STARGATE_STATE_DIR per the
// contract-harness env contract).
const snapshotFileName = "dp-snapshot.json"

// snapshotSchemaVersion is the v2 shape T092 introduced: verifiers[] of
// 32-byte HMAC tags, no per-token salt. A file claiming any other version
// is ignored at restore (never misparsed — parsing v1 {hash,salt} pairs as
// verifiers would authenticate nothing and silently break routing, §1.4).
const snapshotSchemaVersion = 2

// snapshotFile is the on-disk §1.4 shape. LoadedAt is an RFC 3339 string
// (not time.Time) so a malformed timestamp is a restore-rejecting
// validation failure instead of a silent zero time.
type snapshotFile struct {
	SchemaVersion int              `json:"schemaVersion"`
	Generation    uint64           `json:"generation"`
	LoadedAt      string           `json:"loadedAt"`
	Verifiers     []snapshotV2Item `json:"verifiers"`
}

type snapshotV2Item struct {
	Verifier string `json:"verifier"`
}

// SnapshotWriter returns the persist seam server.go's ReloadTokens calls
// after the in-memory swap: write to dir, journal the outcome under the
// loginvariants snapshot_write line class. T050 constructs it with the
// resolved state dir; the closure binds the dir so the seam signature
// stays SnapshotFunc.
func SnapshotWriter(dir string, log *slog.Logger) SnapshotFunc {
	return func(g *auth.Generation) error {
		if err := WriteSnapshot(dir, g); err != nil {
			return err
		}
		// Success line: msg only — generation/count ride the adjacent
		// "tokens applied" line (reload_tokens_apply class), and this
		// class's AllowedFields reserves err/reason/generation for the
		// restore half.
		log.Info("snapshot written")
		return nil
	}
}

// WriteSnapshot atomically persists g to dir/dp-snapshot.json (§1.4):
// write a temp file in the SAME directory (rename(2) is
// same-filesystem-or-EINVAL), fsync it, then os.Rename over the previous
// content. A failure at any point leaves the previous snapshot intact and
// returns an error carrying the operation and path only — never material
// bytes (§1.6; Principle III).
//
// The fsync before rename is what makes the cache survive a power cut as
// a coherent file instead of a renamed-but-empty inode; the directory
// entry itself is not fsynced — the snapshot is a cache whose loss only
// costs tokens until the CP re-pushes (row 4), not a source of truth.
func WriteSnapshot(dir string, g *auth.Generation) error {
	sf := snapshotFile{
		SchemaVersion: snapshotSchemaVersion,
		Generation:    g.Generation,
		LoadedAt:      g.LoadedAt.Format(time.RFC3339),
		// Non-nil even for a revoke-all generation: §1.4's verifiers is
		// an array, and json.Marshal renders a nil slice as null.
		Verifiers: make([]snapshotV2Item, 0, len(g.Verifiers)),
	}
	for _, v := range g.Verifiers {
		sf.Verifiers = append(sf.Verifiers, snapshotV2Item{Verifier: base64.StdEncoding.EncodeToString(v)})
	}
	blob, err := json.Marshal(sf)
	if err != nil {
		return fmt.Errorf("marshalling %s: %w", snapshotFileName, err)
	}

	final := filepath.Join(dir, snapshotFileName)
	tmp, err := os.CreateTemp(dir, "."+snapshotFileName+"-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp beside %s: %w", final, err)
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("writing temp beside %s: %w", final, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("syncing temp beside %s: %w", final, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("closing temp beside %s: %w", final, err)
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("renaming snapshot into place %s: %w", final, err)
	}
	return nil
}

// RestoreSnapshot installs the cold-start generation from
// dir/dp-snapshot.json into tokens (§1.4: restored when the control plane
// is unreachable at startup — the reachability policy is the boot
// sequence's, T050). The three outcomes:
//
//   - file absent (first boot) → store stays at the empty generation
//     (revoke-all); deliberately silent — a missing cache is normal, not
//     a warning condition;
//   - file present but unusable — stale schemaVersion, corrupt JSON,
//     unparsable loadedAt, or any verifier not exactly 32 base64 bytes —
//     → warning ("snapshot restore ignored", §1.4 requires the warning),
//     store untouched. No partial trust: one bad verifier rejects the
//     whole file, because a half-restored set silently authenticates a
//     subset of the operator's tokens;
//   - file valid → the generation is swapped in atomically and the
//     restart journal carries "snapshot restored" with the generation
//     (the §1.3 restart-log use of loadedAt; the timestamp itself is NOT
//     journaled — it is finer-grained than the ≥1h aggregate the journal
//     scan permits).
//
// Restore never fails the boot: a broken cache must not take routing down
// with it (arch §5.5; Principle II).
func RestoreSnapshot(dir string, tokens *auth.TokenStore, log *slog.Logger) {
	raw, err := os.ReadFile(filepath.Join(dir, snapshotFileName))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("snapshot restore ignored", "reason", err.Error())
		}
		return
	}

	var sf snapshotFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		log.Warn("snapshot restore ignored", "reason", "unparsable json")
		return
	}
	if sf.SchemaVersion != snapshotSchemaVersion {
		log.Warn("snapshot restore ignored", "reason", fmt.Sprintf("schemaVersion %d", sf.SchemaVersion))
		return
	}
	loadedAt, err := time.Parse(time.RFC3339, sf.LoadedAt)
	if err != nil {
		log.Warn("snapshot restore ignored", "reason", "loadedAt unparsable")
		return
	}
	verifiers := make([][]byte, 0, len(sf.Verifiers))
	for i, item := range sf.Verifiers {
		v, err := base64.StdEncoding.DecodeString(item.Verifier)
		if err != nil || len(v) != verifierLen {
			// Index and byte count only — never the bytes (§1.6).
			log.Warn("snapshot restore ignored", "reason", fmt.Sprintf("verifier %d: %d bytes", i, len(v)))
			return
		}
		verifiers = append(verifiers, v)
	}

	tokens.Swap(&auth.Generation{
		Generation: sf.Generation,
		Verifiers:  verifiers,
		LoadedAt:   loadedAt,
	})
	log.Info("snapshot restored", "generation", sf.Generation)
}
