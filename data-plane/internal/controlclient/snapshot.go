// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// snapshot.go — the dp-snapshot.json persistence layer (T046): the atomic
// cold-start cache behind server.go's SnapshotFunc seam. Contract:
// specs/001-tor-route/data-model.md §1.4 (schemaVersion 3, verifiers-only —
// NEVER the pepper or plaintext; legacy schemas ignored, not misparsed),
// §1.3 (generation / atomic swap), contracts/control-grpc.md §"ReloadTokens"
// row 4 (durable persist before in-memory swap and acknowledgment), and arch §5.5 (control
// plane down at startup → continue from the last-known snapshot).
//
// The snapshot holds derived material only (base64 HMAC-SHA-256 tags): the
// pepper and plaintexts never reach this file, so the writer's signature
// takes an *auth.Generation — there is no API shape that could persist more.
package controlclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/auth"
)

// snapshotFileName is the fixed file name inside the state dir
// (§1.4: /var/lib/stargate/dp-snapshot.json in production; the dir is
// resolved by the boot sequence, T050 — STARGATE_STATE_DIR per the
// contract-harness env contract).
const snapshotFileName = "dp-snapshot.json"

const (
	// Schema 3 adds the versioned exact-content commitment required before a
	// T159 durable acknowledgment. Legacy schemas cannot prove that property.
	snapshotSchemaVersion = 3
	authSetVersion        = 1
	sha256CommitmentLen   = sha256.Size
)

// snapshotFile is the on-disk §1.4 shape. LoadedAt is an RFC 3339 string
// (not time.Time) so a malformed timestamp is a restore-rejecting
// validation failure instead of a silent zero time.
type snapshotFile struct {
	SchemaVersion  int              `json:"schemaVersion"`
	AuthSetVersion int              `json:"authSetVersion"`
	Generation     uint64           `json:"generation"`
	Commitment     string           `json:"commitment"`
	LoadedAt       string           `json:"loadedAt"`
	Verifiers      []snapshotV2Item `json:"verifiers"`
}

type snapshotV2Item struct {
	Verifier string `json:"verifier"`
}

// SnapshotWriter binds the persisted auth-cache directory. The compatibility
// logger argument is unused: maintenance cannot emit an event journal (III).
func SnapshotWriter(dir string, _ *slog.Logger) SnapshotFunc {
	return func(g *auth.Generation) error { return WriteSnapshot(dir, g) }
}

// WriteSnapshot atomically persists g to dir/dp-snapshot.json (§1.4):
// write a temp file in the SAME directory (rename(2) is
// same-filesystem-or-EINVAL), fsync it, then os.Rename over the previous
// content. A failure at any point leaves the previous snapshot intact and
// returns an error carrying the operation and path only — never material
// bytes (§1.6; Principle III).
//
// The file fsync makes the renamed inode coherent; the directory fsync makes
// that rename durable before the caller may publish or acknowledge the new
// generation. A directory-sync failure leaves the candidate pending: the
// file may already be visible, but its durability has not been acknowledged.
func WriteSnapshot(dir string, g *auth.Generation) error {
	commitment := authSetCommitment(g.Verifiers)
	sf := snapshotFile{
		SchemaVersion:  snapshotSchemaVersion,
		AuthSetVersion: authSetVersion,
		Generation:     g.Generation,
		Commitment:     base64.StdEncoding.EncodeToString(commitment),
		LoadedAt:       g.LoadedAt.Format(time.RFC3339),
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
		_ = tmp.Close()           // cleanup after failed write; preserve the original error
		_ = os.Remove(tmp.Name()) // cleanup is best effort
		return fmt.Errorf("writing temp beside %s: %w", final, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()           // cleanup after failed sync; preserve the original error
		_ = os.Remove(tmp.Name()) // cleanup is best effort
		return fmt.Errorf("syncing temp beside %s: %w", final, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name()) // cleanup after failed close is best effort
		return fmt.Errorf("closing temp beside %s: %w", final, err)
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		_ = os.Remove(tmp.Name()) // cleanup after failed rename is best effort
		return fmt.Errorf("renaming snapshot into place %s: %w", final, err)
	}
	dirFile, err := os.Open(dir) // #nosec G304 -- snapshot directory is configured locally, never from a request
	if err != nil {
		return fmt.Errorf("opening snapshot directory %s: %w", dir, err)
	}
	if err := dirFile.Sync(); err != nil {
		_ = dirFile.Close() // preserve the sync error; close is best effort here
		return fmt.Errorf("syncing snapshot directory %s: %w", dir, err)
	}
	if err := dirFile.Close(); err != nil {
		return fmt.Errorf("closing snapshot directory %s: %w", dir, err)
	}
	return nil
}

// authSetCommitment implements control-grpc.md's order-independent,
// duplicate-preserving auth-set-v1 commitment.
func authSetCommitment(verifiers [][]byte) []byte {
	members := make([][]byte, len(verifiers))
	for i, verifier := range verifiers {
		members[i] = append([]byte(nil), verifier...)
	}
	sort.Slice(members, func(i, j int) bool { return bytes.Compare(members[i], members[j]) < 0 })
	h := sha256.New()
	h.Write(append([]byte("stargate-auth-set-v1"), 0))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(members)))
	h.Write(count[:])
	for _, member := range members {
		h.Write(member)
	}
	return h.Sum(nil)
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
//     → store untouched, with no diagnostic record (Constitution III). No partial trust: one bad verifier rejects the
//     whole file, because a half-restored set silently authenticates a
//     subset of the operator's tokens;
//   - file valid → the generation is swapped in atomically without a journal.
//
// Restore never fails the boot: a broken cache must not take routing down
// with it (arch §5.5; Principle II).
func RestoreSnapshot(dir string, tokens *auth.TokenStore, _ *slog.Logger) {
	raw, err := os.ReadFile(filepath.Join(dir, snapshotFileName)) // #nosec G304 -- fixed filename in configured snapshot directory
	if err != nil {
		return
	}

	var sf snapshotFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		return
	}
	if sf.SchemaVersion != snapshotSchemaVersion || sf.AuthSetVersion != authSetVersion || sf.Generation == 0 {
		return
	}
	loadedAt, err := time.Parse(time.RFC3339, sf.LoadedAt)
	if err != nil {
		return
	}
	verifiers := make([][]byte, 0, len(sf.Verifiers))
	for _, item := range sf.Verifiers {
		v, err := base64.StdEncoding.DecodeString(item.Verifier)
		if err != nil || len(v) != verifierLen {
			return
		}
		verifiers = append(verifiers, v)
	}
	commitment, err := base64.StdEncoding.DecodeString(sf.Commitment)
	if err != nil || len(commitment) != sha256CommitmentLen ||
		!bytes.Equal(commitment, authSetCommitment(verifiers)) {
		return
	}

	tokens.Swap(&auth.Generation{
		Generation: sf.Generation,
		Verifiers:  verifiers,
		LoadedAt:   loadedAt,
	})
}
